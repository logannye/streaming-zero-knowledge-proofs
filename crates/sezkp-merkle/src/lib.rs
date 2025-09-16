//! Streaming Merkle commitments over `BlockSummary` leaves.
//!
//! ## Overview
//! This crate provides a compact Merkle commitment for a sequence of
//! [`sezkp_core::BlockSummary`] records. It includes:
//!
//! - A **canonical leaf hash** (exported) used consistently across the
//!   workspace. Other components (e.g., folding leaf gadget) must bind to the
//!   same byte layout to remain compatible.
//! - A small [`CommitManifest`] containing `{root, n_leaves, version}`.
//! - Helpers to commit blocks from disk (JSON/CBOR/JSONL), validate a blocks
//!   file against a manifest, and read/write manifests in **JSON** or **CBOR**.
//!
//! ## Canonical leaf schema (v1)
//! The leaf hash is `BLAKE3` over raw little-endian fields in this order:
//! 1. `version: u16`
//! 2. `block_id: u32`
//! 3. `step_lo: u64`
//! 4. `step_hi: u64`
//! 5. `ctrl_in: u16`
//! 6. `ctrl_out: u16`
//! 7. `in_head_in: i64`
//! 8. `in_head_out: i64`
//! 9. `windows.len(): u64`, then for each window: `left: i64`, `right: i64`
//! 10. `head_in_offsets` values only (no length; each `u32`)
//! 11. `head_out_offsets` values only (no length; each `u32`)
//! 12. `movement_log.steps.len(): u64` (the **length only** in v1)
//!
//! Notes:
//! - There is no domain tag and no CBOR/Serde framing inside the leaf hash.
//! - The movement log’s **contents** are *not* included in v1; the schema that
//!   carries the blocks includes them. If you change what the leaf hash binds,
//!   you must bump the manifest schema version.
//!
//! ## Merkle tree shape
//! - Odd leaves are **promoted** at each level (left-balanced tree). We do not
//!   duplicate the last leaf. This choice is deterministic and tested here.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_core::{io as core_io, BlockSummary};
use sezkp_core::io_jsonl::stream_block_summaries_jsonl;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

/// Format version for the current `CommitManifest` wire schema.
pub const MANIFEST_VERSION: u32 = 1;

/// Compact commitment over a set of `BlockSummary` leaves.
///
/// This is the object typically written to disk and consumed by other
/// subsystems (e.g., the folding line) to bind to a specific blocks file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitManifest {
    /// Schema/encoding version of this manifest (see [`MANIFEST_VERSION`]).
    pub version: u32,
    /// Merkle root over canonical leaf hashes (see [`leaf_hash`]).
    pub root: [u8; 32],
    /// Number of leaves (blocks) bound by `root`.
    pub n_leaves: u32,
}

/* -------------------------- Leaf/node hashing -------------------------- */

/// Compute the **canonical** leaf hash for a `BlockSummary`.
///
/// The byte layout is intentionally duplicated in the folding leaf gadget and
/// must remain byte-for-byte identical across the workspace.
///
/// See the module-level docs for the exact encoding.
#[must_use]
pub fn leaf_hash(b: &BlockSummary) -> [u8; 32] {
    let mut h = Hasher::new();

    // Core scalars (raw little-endian)
    h.update(&b.version.to_le_bytes());
    h.update(&b.block_id.to_le_bytes());
    h.update(&b.step_lo.to_le_bytes());
    h.update(&b.step_hi.to_le_bytes());
    h.update(&b.ctrl_in.to_le_bytes());
    h.update(&b.ctrl_out.to_le_bytes());
    h.update(&b.in_head_in.to_le_bytes());
    h.update(&b.in_head_out.to_le_bytes());

    // Windows: length + (left, right) pairs
    h.update(&(b.windows.len() as u64).to_le_bytes());
    for w in &b.windows {
        h.update(&w.left.to_le_bytes());
        h.update(&w.right.to_le_bytes());
    }

    // Head offsets: values only (no lengths)
    for &x in &b.head_in_offsets {
        h.update(&x.to_le_bytes());
    }
    for &x in &b.head_out_offsets {
        h.update(&x.to_le_bytes());
    }

    // Movement log: bind **length only** in v1
    h.update(&(b.movement_log.steps.len() as u64).to_le_bytes());

    *h.finalize().as_bytes()
}

/// Public node combiner used everywhere that needs to hash two children.
///
/// This **must** match the manifest/Merkle combiner and the fold crate.
#[inline]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[inline]
fn merkle_parent(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    node_hash(&a, &b)
}

/// Compute a left-balanced Merkle root from a vector of leaf hashes.
///
/// - Empty input → all-zero root.
/// - Odd leaf at a level → **promote** (carry up unchanged).
#[must_use]
pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for i in (0..leaves.len()).step_by(2) {
            if i + 1 < leaves.len() {
                next.push(merkle_parent(leaves[i], leaves[i + 1]));
            } else {
                // Promote odd leaf (left-balanced construction).
                next.push(leaves[i]);
            }
        }
        leaves = next;
    }
    leaves[0]
}

/* --------------------------- Streaming frontier --------------------------- */

/// O(log n) frontier that maintains a left-balanced Merkle root incrementally.
///
/// Push leaves one-by-one with [`Frontier::push_leaf`], then call
/// [`Frontier::finalize_root`] to obtain the root. Memory is bounded by the
/// number of levels (~`floor(log2(n)) + 1`).
#[derive(Default)]
struct Frontier {
    // One slot per level; slot[i] is the pending promoted node at that level.
    slots: Vec<Option<[u8; 32]>>,
}

impl Frontier {
    #[inline]
    fn push_leaf(&mut self, mut h: [u8; 32]) {
        let mut lvl = 0usize;
        loop {
            if self.slots.len() <= lvl {
                self.slots.resize(lvl + 1, None);
            }
            match self.slots[lvl] {
                None => {
                    self.slots[lvl] = Some(h);
                    break;
                }
                Some(left) => {
                    // Pair with the waiting left node; carry to next level.
                    self.slots[lvl] = None;
                    h = merkle_parent(left, h);
                    lvl += 1;
                }
            }
        }
    }

    #[inline]
    fn finalize_root(&self) -> [u8; 32] {
        // Start from the highest non-empty level and fold downward,
        // pairing current accumulator (higher) with lower-level nodes.
        let mut acc: Option<[u8; 32]> = None;
        for node in self.slots.iter().rev().filter_map(|x| *x) {
            acc = Some(match acc {
                None => node,
                Some(higher) => merkle_parent(higher, node),
            });
        }
        acc.unwrap_or([0u8; 32])
    }
}

/* ------------------------------ In-memory API ------------------------------ */

/// Compute a manifest (root + leaf count) from an in-memory slice of blocks.
#[must_use]
pub fn commit_blocks(blocks: &[BlockSummary]) -> CommitManifest {
    let leaves: Vec<[u8; 32]> = blocks.iter().map(leaf_hash).collect();
    let root = merkle_root(leaves);
    CommitManifest {
        version: MANIFEST_VERSION,
        root,
        n_leaves: blocks.len() as u32,
    }
}

/// In-memory validator: recompute and compare root and leaf count.
///
/// Returns `Ok(())` if the manifest matches the provided blocks.
pub fn validate_blocks_against_manifest(
    blocks: &[BlockSummary],
    man: &CommitManifest,
) -> Result<()> {
    let recomputed = commit_blocks(blocks);
    if recomputed.root != man.root {
        return Err(anyhow!(
            "root mismatch: manifest={}, recomputed={}",
            hex::encode(man.root),
            hex::encode(recomputed.root)
        ));
    }
    if recomputed.n_leaves != man.n_leaves {
        return Err(anyhow!(
            "leaf count mismatch: manifest={}, recomputed={}",
            man.n_leaves,
            recomputed.n_leaves
        ));
    }
    Ok(())
}

/* -------------------------- File/streaming helpers ------------------------- */

/// Commit a blocks file to a manifest, write it to `out_manifest_path`, and return it.
///
/// - Supports `.json`, `.cbor`, or line-delimited JSON as `.jsonl`/`.ndjson`.
/// - JSONL/NDJSON is processed **streamingly** with an O(log n) frontier.
///   JSON/CBOR are loaded via `sezkp-core` helpers.
///
/// This function also prints a one-line summary (root/leaf count) for UX.
/// Library users that prefer no output can wrap/redirect stdout.
pub fn commit_block_file<P: AsRef<Path>, Q: AsRef<Path>>(
    blocks_path: P,
    out_manifest_path: Q,
) -> Result<CommitManifest> {
    let path = blocks_path.as_ref();

    let manifest = if is_jsonl_like(path) {
        // Stream leaves in one pass using a frontier.
        let mut frontier = Frontier::default();
        let mut n = 0u32;
        for blk in stream_block_summaries_jsonl(path)? {
            frontier.push_leaf(leaf_hash(&blk?));
            n = n.saturating_add(1);
        }
        let root = frontier.finalize_root();
        CommitManifest {
            version: MANIFEST_VERSION,
            root,
            n_leaves: n,
        }
    } else {
        // Use sezkp-core auto-reader for JSON/CBOR files that contain Vec<BlockSummary>.
        let blocks = core_io::read_block_summaries_auto(&blocks_path)
            .with_context(|| format!("read blocks {}", display(path)))?;
        commit_blocks(&blocks)
    };

    write_manifest_auto(&out_manifest_path, &manifest)?;
    println!(
        "Committed {} leaves, root={}, wrote manifest {}",
        manifest.n_leaves,
        hex::encode(manifest.root),
        out_manifest_path.as_ref().display()
    );

    Ok(manifest)
}

/// Verify that a blocks file matches a manifest file by recomputing the root.
///
/// - For `.jsonl`/`.ndjson` inputs, this streams the file and uses an O(log n)
///   frontier; it does **not** materialize all blocks.
/// - For `.json`/`.cbor`, it uses `sezkp-core` helpers to load all blocks.
pub fn verify_block_file_against_manifest<P: AsRef<Path>, Q: AsRef<Path>>(
    blocks_path: P,
    manifest_path: Q,
) -> Result<()> {
    let path = blocks_path.as_ref();
    let man = read_manifest_auto(&manifest_path)?;

    if is_jsonl_like(path) {
        let mut frontier = Frontier::default();
        let mut n = 0u32;
        for blk in stream_block_summaries_jsonl(path)? {
            frontier.push_leaf(leaf_hash(&blk?));
            n = n.saturating_add(1);
        }
        let root = frontier.finalize_root();
        if root != man.root {
            anyhow::bail!(
                "root mismatch: manifest={}, recomputed={}",
                hex::encode(man.root),
                hex::encode(root)
            );
        }
        if n != man.n_leaves {
            anyhow::bail!(
                "leaf count mismatch: manifest={}, recomputed={}",
                man.n_leaves,
                n
            );
        }
        Ok(())
    } else {
        let blocks = core_io::read_block_summaries_auto(&blocks_path)
            .with_context(|| format!("read blocks {}", display(path)))?;
        validate_blocks_against_manifest(&blocks, &man)
    }
}

/* ------------------------------ Manifest I/O ------------------------------- */

/// Read a manifest from **JSON**.
pub fn read_manifest_json<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let rdr = BufReader::new(f);
    let v: CommitManifest =
        serde_json::from_reader(rdr).with_context(|| "deserialize JSON manifest")?;
    Ok(v)
}

/// Write a manifest to **JSON** (pretty).
pub fn write_manifest_json<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, v).with_context(|| "serialize JSON manifest")?;
    w.flush().with_context(|| "flush JSON writer")?;
    Ok(())
}

/// Read a manifest from **CBOR**.
pub fn read_manifest_cbor<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let mut rdr = BufReader::new(f);
    let v: CommitManifest =
        ciborium::de::from_reader(&mut rdr).with_context(|| "deserialize CBOR manifest")?;
    Ok(v)
}

/// Write a manifest to **CBOR**.
pub fn write_manifest_cbor<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    ciborium::ser::into_writer(v, &mut w).with_context(|| "serialize CBOR manifest")?;
    w.flush().with_context(|| "flush CBOR writer")?;
    Ok(())
}

/// Auto-detect **read** by extension: `.json` / `.cbor` (case-insensitive).
pub fn read_manifest_auto<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => read_manifest_json(path),
        Some("cbor") => read_manifest_cbor(path),
        Some(other) => anyhow::bail!("unsupported manifest extension: {}", other),
        None => anyhow::bail!("path has no extension (expected .json or .cbor)"),
    }
}

/// Auto-detect **write** by extension: `.json` / `.cbor` (defaults to JSON).
pub fn write_manifest_auto<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => write_manifest_json(path, v),
        Some("cbor") => write_manifest_cbor(path, v),
        _ => write_manifest_json(path, v),
    }
}

/* --------------------------------- Helpers -------------------------------- */

#[inline]
fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(|s| s.to_ascii_lowercase())
}

#[inline]
fn is_jsonl_like(path: &Path) -> bool {
    matches!(ext_lower(path).as_deref(), Some("jsonl") | Some("ndjson"))
}

#[inline]
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/* ---------------------------------- Tests --------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, TapeOp, Window};

    fn mk_block(block_id: u32, len: usize) -> BlockSummary {
        let steps = vec![
            StepProjection {
                input_mv: 0,
                tapes: vec![TapeOp { write: None, mv: 0 }],
            };
            len
        ];
        BlockSummary {
            version: 1,
            block_id,
            step_lo: 1 + (block_id as u64 - 1) * len as u64,
            step_hi: (block_id as u64) * len as u64,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: len as i64,
            windows: vec![Window { left: 0, right: len as i64 - 1 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![(len - 1) as u32],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0u8; 16]; 1],
            post_tags: vec![[0u8; 16]; 1],
        }
    }

    #[test]
    fn merkle_root_empty_and_odd() {
        assert_eq!(merkle_root(vec![]), [0u8; 32]);

        // Three leaves → odd promotion path defined behavior.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let r1 = merkle_parent(a, b);
        let r2 = merkle_parent(r1, c); // (a,b) then promote c
        let root = merkle_root(vec![a, b, c]);
        assert_eq!(root, r2);
    }

    #[test]
    fn commit_and_validate_roundtrip() {
        let blocks = vec![mk_block(1, 4), mk_block(2, 4), mk_block(3, 2)];
        let man = commit_blocks(&blocks);
        validate_blocks_against_manifest(&blocks, &man).unwrap();
    }

    #[test]
    fn frontier_matches_batch_merkle() {
        // Random-ish sizes to hit many promotion patterns.
        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 31, 32, 33] {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| {
                    let mut h = Hasher::new();
                    h.update(&(i as u64).to_le_bytes());
                    *h.finalize().as_bytes()
                })
                .collect();

            // Batch root.
            let batch = merkle_root(leaves.clone());

            // Streaming frontier root.
            let mut f = Frontier::default();
            for l in leaves {
                f.push_leaf(l);
            }
            let stream = f.finalize_root();

            assert_eq!(batch, stream);
        }
    }
}
