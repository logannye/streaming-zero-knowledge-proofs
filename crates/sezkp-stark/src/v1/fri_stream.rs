//! Streaming helpers for FRI layers (layer-0 builder and fold glue).
//!
//! This module provides:
//! - `StreamingLayerBuilder`: a Merkle root builder that ingests leaves in
//!   order and keeps only a tiny per-level stack; no full layer storage.
//! - `fold_stream`: a convenience function that consumes an iterator of pairs
//!   `(y[i], y[i+half])`, applies `y'[i] = y[i] + beta * y[i+half]`, and feeds
//!   the results to a `StreamingLayerBuilder`.
//! - `merkle_path_from_le_chunker`: compute a Merkle path **streaming** from an
//!   out-of-core layer-0 leaf producer; no arrays are materialized.
//!
//! Notes
//! -----
//! * The Merkle combination rule matches our non-streaming `MerkleTree`
//!   implementation: when a level has an odd count of nodes, the last node is
//!   carried up unchanged (odd promotion).
//! * The layer-0 leaves here are **unlabeled** 8-byte field encodings; this
//!   matches the back-compat `hash_field_leaves` used for FRI layers.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_mut)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;

use crate::v1::field::F1;

/// Hash a single 8-byte little-endian value into a 32-byte leaf.
#[inline]
fn hash_leaf(le: &[u8; 8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(le);
    *h.finalize().as_bytes()
}

/// Hash two 32-byte nodes into their parent (left then right).
#[inline]
fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Streaming Merkle builder for a single layer.
/// Keeps at most one unpaired node per level (stack discipline).
#[derive(Debug)]
pub struct StreamingLayerBuilder {
    expected_len: usize,
    seen: usize,
    /// One optional node per level; `stack[lvl]` is a node waiting for its right sibling.
    stack: Vec<Option<[u8; 32]>>,
}

impl StreamingLayerBuilder {
    /// Create a builder for a layer with `layer_len` leaves.
    #[must_use]
    pub fn new(layer_len: usize) -> Self {
        Self {
            expected_len: layer_len,
            seen: 0,
            stack: Vec::new(),
        }
    }

    /// Absorb a batch of **layer leaves** (8-byte little-endian encodings).
    /// This can be called many times; total absorbed count must equal `layer_len`.
    pub fn absorb_leaves(&mut self, chunk: &[[u8; 8]]) {
        for le in chunk {
            self.seen += 1;
            let mut cur = hash_leaf(le);
            let mut lvl = 0usize;
            loop {
                if self.stack.len() <= lvl {
                    self.stack.push(None);
                }
                if let Some(left) = self.stack[lvl].take() {
                    // Pair available ⇒ combine and propagate upward.
                    cur = hash_nodes(&left, &cur);
                    lvl += 1;
                } else {
                    // First in its pair at this level; wait for the sibling.
                    self.stack[lvl] = Some(cur);
                    break;
                }
            }
        }
    }

    /// Finalize and return the Merkle root. Panics if absorb count mismatches.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        assert_eq!(
            self.seen, self.expected_len,
            "StreamingLayerBuilder absorbed {} leaves, expected {}",
            self.seen, self.expected_len
        );

        // Odd promotions: carry lone nodes up unchanged.
        // The root is the left-to-right reduction of remaining nodes over levels.
        let mut cur: Option<[u8; 32]> = None;
        for opt in self.stack.into_iter() {
            if let Some(node) = opt {
                cur = Some(match cur {
                    None => node,
                    Some(acc) => hash_nodes(&acc, &node),
                });
            }
        }

        cur.unwrap_or([0u8; 32])
    }
}

/// Consume `(y[i], y[i+half])` pairs, apply the FRI fold with `beta`, and
/// feed the folded stream to `out` as layer-(ℓ+1) leaves.
///
/// This helper does **not** create or store any arrays; callers control how
/// pairs are produced (e.g., via an out-of-core pairing adaptor).
pub fn fold_stream(
    beta: F1,
    mut in_pairs: impl Iterator<Item = ([u8; 8], [u8; 8])>,
    out: &mut StreamingLayerBuilder,
) {
    // Small staging buffer to amortize per-call overhead of `absorb_leaves`.
    // This buffer holds encoded 8-byte outputs; tune 1<<12 (~4K) by default.
    const BUF_CAP: usize = 1 << 12;
    let mut buf: Vec<[u8; 8]> = Vec::with_capacity(BUF_CAP);

    while let Some((a_le, b_le)) = in_pairs.next() {
        let a = F1::from_u64(u64::from_le_bytes(a_le));
        let b = F1::from_u64(u64::from_le_bytes(b_le));
        let folded = (a + beta * b).to_le_bytes();
        buf.push(folded);

        if buf.len() == BUF_CAP {
            out.absorb_leaves(&buf);
            buf.clear();
        }
    }

    if !buf.is_empty() {
        out.absorb_leaves(&buf);
    }
}

/* -------------------------------------------------------------------------- */
/*                     Streaming Merkle path (layer-0)                        */
/* -------------------------------------------------------------------------- */

/// Stream nodes at a given tree level by **driving a layer-0 chunker** and
/// emitting the nodes formed at `target_level`. No arrays are stored.
///
/// - `layer_len`: number of layer-0 leaves.
/// - `target_level`: 0 for leaves, 1 for parents, ...
/// - `chunker`: a function that accepts a `sink` and repeatedly calls it with
///              slices of 8-byte leaves (layer-0).
/// - `on_node(pos, hash, leaf_opt)`: callback invoked for each node at
///              `target_level`, in order. For `target_level == 0`, `leaf_opt`
///              is `Some([u8;8])`; otherwise `None`.
fn emit_level_nodes_from_le_chunker(
    layer_len: usize,
    target_level: usize,
    mut chunker: impl FnMut(&mut dyn FnMut(&[[u8; 8]])),
    mut on_node: impl FnMut(usize, [u8; 32], Option<[u8; 8]>),
) {
    if layer_len == 0 {
        return;
    }
    if target_level == 0 {
        // Directly stream leaves as nodes at level 0.
        let mut pos = 0usize;
        chunker(&mut |chunk| {
            for le in chunk {
                let h = hash_leaf(le);
                on_node(pos, h, Some(*le));
                pos += 1;
            }
        });
        return;
    }

    // For levels >= 1, maintain a per-level stack of pending nodes.
    let mut stack: Vec<Option<[u8; 32]>> = Vec::new();
    let mut pos_at_target = 0usize;

    // Ingest all leaves, bubbling combinations upward; whenever we *form*
    // a node at `target_level`, emit it.
    chunker(&mut |chunk| {
        for le in chunk {
            let mut cur = hash_leaf(le);
            let mut lvl = 0usize;
            loop {
                if stack.len() <= lvl {
                    stack.push(None);
                }
                if let Some(left) = stack[lvl].take() {
                    // Combine and bubble upward.
                    cur = hash_nodes(&left, &cur);
                    lvl += 1;

                    if lvl == target_level {
                        // We just formed a node at target level.
                        on_node(pos_at_target, cur, None);
                        pos_at_target += 1;
                    }
                    // Continue bubbling until we place `cur`.
                } else {
                    stack[lvl] = Some(cur);
                    break;
                }
            }
        }
    });

    // Odd promotions: carry lone nodes up unchanged, possibly crossing
    // multiple levels. When a promotion *reaches* target_level, emit it.
    for l in 0..stack.len() {
        if let Some(mut cur) = stack[l].take() {
            // Promote from level `l` to `l+1` unchanged, resolving pending lefts along the way.
            let mut lvl = l + 1;
            loop {
                if lvl == target_level {
                    on_node(pos_at_target, cur, None);
                    pos_at_target += 1;
                    break;
                }
                if stack.len() <= lvl {
                    stack.push(Some(cur));
                    break;
                }
                if let Some(left) = stack[lvl].take() {
                    // Promotion meets a pending left -> combine and go up.
                    cur = hash_nodes(&left, &cur);
                    lvl += 1;
                } else {
                    stack[lvl] = Some(cur);
                    break;
                }
            }
        }
    }
}

/// Compute a Merkle path for a single index `idx` over the layer-0 leaves,
/// **streaming** the leaves from `chunker` without retaining any layer arrays.
/// Returns `(value_le, sibling_hashes_bottom_to_top)`.
///
/// The tree uses "odd promotion": when a level has an odd count of nodes,
/// the last node is carried up unchanged; our path matches this rule.
pub fn merkle_path_from_le_chunker(
    layer_len: usize,
    mut chunker: impl FnMut(&mut dyn FnMut(&[[u8; 8]])),
    mut idx: usize,
) -> ([u8; 8], Vec<[u8; 32]>) {
    assert!(layer_len > 0, "empty layer not supported");
    assert!(idx < layer_len, "index out of bounds for layer");

    let mut cur_len = layer_len;
    let mut level = 0usize;
    let mut path: Vec<[u8; 32]> = Vec::new();
    let mut val_le: Option<[u8; 8]> = None;

    while cur_len > 1 {
        let want = idx;
        let sib = idx ^ 1;
        let mut cur_hash: Option<[u8; 32]> = None;

        // Scan nodes at this level in order and record (hash at idx) and (hash at sibling, if any).
        emit_level_nodes_from_le_chunker(
            layer_len,
            level,
            &mut chunker,
            |pos, hash, leaf_opt| {
                if pos == want {
                    cur_hash = Some(hash);
                    if level == 0 {
                        // Capture raw value at the leaf level.
                        if let Some(le) = leaf_opt {
                            val_le = Some(le);
                        }
                    }
                }
                if sib < cur_len && pos == sib {
                    path.push(hash);
                }
            },
        );

        // Odd promotion at this level: sibling does not exist, use self as sibling.
        if sib >= cur_len {
            let h = cur_hash.expect("current node hash available");
            path.push(h);
        }

        // Move to next level up.
        idx >>= 1;
        cur_len = (cur_len + 1) / 2;
        level += 1;
    }

    (val_le.expect("leaf value present"), path)
}
