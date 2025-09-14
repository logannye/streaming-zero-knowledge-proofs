//! Minimal Merkle utilities for v1 (BLAKE3) + chunked & streaming column commitments.
//!
//! This module now supports **two** ways to commit to a column of per-row values:
//!  - `ColumnCommit::from_hashed_leaves(...)` (existing, in-memory): builds all
//!    inner chunk trees and an outer tree, supporting immediate openings.
//!  - `StreamingColumnCommitBuilder` (new): accepts values row-by-row, emits
//!    chunk roots as soon as a chunk fills, then builds the outer tree at the end.
//!    This keeps only `O(chunk_size)` leaves in memory and **does not** retain
//!    inner trees (openings are intended to be handled by on-demand reconstruction
//!    in the streaming prover path; see A2 in the roadmap).
//!
//! Verifier code (Merkle path verification) remains unchanged.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;

use crate::v1::params;

/* ----------------------- Plain single-tree Merkle (FRI) -------------------- */

/// Very small Merkle tree over fixed 32-byte leaves.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<[u8; 32]>, // heap-ordered, nodes.last() = root
}

/// Merkle proof: siblings bottom→top plus the leaf index.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub sibs: Vec<[u8; 32]>,
    pub index: usize,
}

impl MerkleTree {
    #[must_use]
    pub fn from_leaves(leaves_raw: &[[u8; 32]]) -> Self {
        let mut leaves = leaves_raw.to_vec();
        if leaves.is_empty() {
            leaves.push([0u8; 32]);
        }
        let mut lvl = leaves.clone();
        let mut nodes = Vec::<[u8; 32]>::new();
        nodes.extend(lvl.iter().copied());
        while lvl.len() > 1 {
            let mut next = Vec::<[u8; 32]>::with_capacity((lvl.len() + 1) / 2);
            for i in (0..lvl.len()).step_by(2) {
                if i + 1 < lvl.len() {
                    let mut h = Hasher::new();
                    h.update(&lvl[i]);
                    h.update(&lvl[i + 1]);
                    next.push(*h.finalize().as_bytes());
                } else {
                    // odd promotion: carry the last node up unchanged
                    next.push(lvl[i]);
                }
            }
            nodes.extend(next.iter().copied());
            lvl = next;
        }
        Self { leaves, nodes }
    }

    #[inline]
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        *self.nodes.last().expect("non-empty tree")
    }

    #[must_use]
    pub fn open(&self, mut idx: usize) -> MerkleProof {
        let mut sibs = Vec::<[u8; 32]>::new();
        let mut lvl = self.leaves.clone();

        // Clamp once at the bottom layer to avoid out-of-bounds on partial layers.
        if !lvl.is_empty() {
            idx %= lvl.len();
        }

        while lvl.len() > 1 {
            let sib_idx = if (idx ^ 1) < lvl.len() { idx ^ 1 } else { idx };
            sibs.push(lvl[sib_idx]);

            let mut next = Vec::<[u8; 32]>::with_capacity((lvl.len() + 1) / 2);
            for i in (0..lvl.len()).step_by(2) {
                if i + 1 < lvl.len() {
                    let mut h = Hasher::new();
                    h.update(&lvl[i]);
                    h.update(&lvl[i + 1]);
                    next.push(*h.finalize().as_bytes());
                } else {
                    next.push(lvl[i]);
                }
            }
            lvl = next;
            idx >>= 1;
        }
        MerkleProof { sibs, index: idx }
    }

    #[must_use]
    pub fn verify(root: [u8; 32], leaf: [u8; 32], mut idx: usize, proof: &MerkleProof) -> bool {
        let mut cur = leaf;
        for s in &proof.sibs {
            let mut h = Hasher::new();
            if idx & 1 == 0 {
                h.update(&cur);
                h.update(s);
            } else {
                h.update(s);
                h.update(&cur);
            }
            cur = *h.finalize().as_bytes();
            idx >>= 1;
        }
        cur == root
    }
}

/// Hash a list of 8-byte little-endian field elements into 32-byte leaves,
/// with explicit domain separation and a per-column label.
#[must_use]
pub fn hash_field_leaves_labeled(le_elems: &[[u8; 8]], col_label: &str) -> Vec<[u8; 32]> {
    le_elems
        .iter()
        .map(|le| {
            let mut h = Hasher::new();
            // Domain sep: DS_COL_LEAF || len(label) || label || value
            h.update(params::DS_COL_LEAF.as_bytes());
            let llen: u32 = col_label.len() as u32;
            h.update(&llen.to_le_bytes());
            h.update(col_label.as_bytes());
            h.update(le);
            *h.finalize().as_bytes()
        })
        .collect()
}

/// Backwards-compatible helper (kept for FRI/demo uses).
#[must_use]
pub fn hash_field_leaves(le_elems: &[[u8; 8]]) -> Vec<[u8; 32]> {
    le_elems
        .iter()
        .map(|le| {
            let mut h = Hasher::new();
            h.update(le);
            *h.finalize().as_bytes()
        })
        .collect()
}

/* ------------------------ Chunked column commitments ------------------------ */

/// Chunked column commitment: Merkle-of-chunks (each chunk is a Merkle tree of
/// row-value leaves); the outer tree commits all chunk roots.
///
/// This is the **in-memory** flavor that stores inner chunk trees and thus
/// supports immediate openings via [`ColumnCommit::open`].
#[derive(Clone, Debug)]
pub struct ColumnCommit {
    pub chunk_log2: usize,
    pub chunk_size: usize,
    pub n_leaves: usize,
    inner: Vec<MerkleTree>, // per-chunk trees
    outer: MerkleTree,      // Merkle tree over chunk roots
}

impl ColumnCommit {
    /// Build from pre-hashed leaves (32-byte leaf hashes) and a chunk size log2.
    #[must_use]
    pub fn from_hashed_leaves(leaves32: &[[u8; 32]], chunk_log2: usize) -> Self {
        let chunk_size = 1usize << chunk_log2;
        let n = leaves32.len();
        let n_chunks = (n + chunk_size - 1) / chunk_size;

        // Build inner chunk trees.
        let mut inner = Vec::with_capacity(n_chunks);
        for c in 0..n_chunks {
            let start = c * chunk_size;
            let end = (start + chunk_size).min(n);
            let chunk = &leaves32[start..end];
            inner.push(MerkleTree::from_leaves(chunk));
        }

        // Collect chunk roots and build the outer tree.
        let chunk_roots: Vec<[u8; 32]> = inner.iter().map(|t| t.root()).collect();
        let outer = MerkleTree::from_leaves(&chunk_roots);

        Self {
            chunk_log2,
            chunk_size,
            n_leaves: n,
            inner,
            outer,
        }
    }

    #[inline]
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.outer.root()
    }

    /// Open a leaf at global `row_idx`: returns paths both inside the chunk and
    /// from chunk root up to the outer root.
    ///
    /// NOTE: `idx_in_chunk` is computed by subtraction (not bit-masking) so the
    /// last, partial chunk is handled correctly.
    #[must_use]
    pub fn open(
        &self,
        row_idx: usize,
    ) -> (usize, usize, [u8; 32], Vec<[u8; 32]>, Vec<[u8; 32]>) {
        assert!(row_idx < self.n_leaves, "row index out of range");
        let chunk_idx = row_idx / self.chunk_size;
        let idx_in_chunk = row_idx - (chunk_idx * self.chunk_size);

        let chunk_tree = &self.inner[chunk_idx];
        let proof_in = chunk_tree.open(idx_in_chunk);
        let chunk_root = chunk_tree.root();
        let outer_proof = self.outer.open(chunk_idx);
        (
            chunk_idx,
            idx_in_chunk,
            chunk_root,
            proof_in.sibs,
            outer_proof.sibs,
        )
    }
}

/// Verify a chunked opening against an outer column root and column label.
#[must_use]
pub fn verify_chunked_open(
    outer_root: [u8; 32],
    col_label: &str,
    value_le: [u8; 8],
    chunk_root: [u8; 32],
    idx_in_chunk: usize,
    path_in_chunk: &[[u8; 32]],
    chunk_idx: usize,
    path_to_chunk: &[[u8; 32]],
) -> bool {
    // Leaf hash with label separation.
    let leaf_hash = hash_field_leaves_labeled(&[value_le], col_label)[0];

    // Verify inner path (leaf -> chunk root).
    let ok_inner = MerkleTree::verify(
        chunk_root,
        leaf_hash,
        idx_in_chunk,
        &MerkleProof {
            sibs: path_in_chunk.to_vec(),
            index: idx_in_chunk,
        },
    );
    if !ok_inner {
        return false;
    }

    // Verify outer path (chunk root -> outer root).
    MerkleTree::verify(
        outer_root,
        chunk_root,
        chunk_idx,
        &MerkleProof {
            sibs: path_to_chunk.to_vec(),
            index: chunk_idx,
        },
    )
}

/* ------------------------- Streaming column commitments --------------------- */

/// Minimal metadata retained for a streaming column commitment.
/// This is sufficient to (later) re-synthesize openings on demand.
#[derive(Clone, Debug)]
pub struct ColumnCommitMeta {
    pub label: String,
    pub n_rows: usize,
    pub chunk_log2: usize,
    pub n_chunks: usize,
    pub outer_root: [u8; 32],
}

/// Build a chunked column commitment by **streaming** 8-byte LE field values.
/// Only keeps `O(chunk_size)` leaf hashes in RAM; inner chunk trees are
/// constructed and immediately reduced to a chunk root which is retained.
/// The final `outer_root` is produced from the vector of chunk roots.
#[derive(Clone, Debug)]
pub struct StreamingColumnCommitBuilder {
    label: String,
    chunk_log2: usize,
    chunk_size: usize,
    n_rows: usize,
    cur_chunk_leaves: Vec<[u8; 32]>,
    chunk_roots: Vec<[u8; 32]>,
}

impl StreamingColumnCommitBuilder {
    /// Create a new streaming builder for a given column label and chunk size.
    #[must_use]
    pub fn new(label: impl Into<String>, chunk_log2: usize) -> Self {
        let chunk_log2 = chunk_log2;
        let chunk_size = 1usize << chunk_log2;
        Self {
            label: label.into(),
            chunk_log2,
            chunk_size,
            n_rows: 0,
            cur_chunk_leaves: Vec::with_capacity(chunk_size),
            chunk_roots: Vec::new(),
        }
    }

    /// Push one field element (as 8-byte little-endian) for the next row.
    pub fn push_value_le(&mut self, le: [u8; 8]) {
        // Hash with domain separation + label, then stage for inner-tree build.
        let leaf_hash = hash_field_leaves_labeled(&[le], &self.label)[0];
        self.cur_chunk_leaves.push(leaf_hash);
        self.n_rows += 1;

        if self.cur_chunk_leaves.len() == self.chunk_size {
            let mt = MerkleTree::from_leaves(&self.cur_chunk_leaves);
            self.chunk_roots.push(mt.root());
            self.cur_chunk_leaves.clear();
        }
    }

    /// Finalize the builder, producing (meta, outer_root).
    /// Any partially-filled last chunk is reduced exactly once here.
    #[must_use]
    pub fn finalize(mut self) -> (ColumnCommitMeta, [u8; 32]) {
        if !self.cur_chunk_leaves.is_empty() {
            let mt = MerkleTree::from_leaves(&self.cur_chunk_leaves);
            self.chunk_roots.push(mt.root());
            self.cur_chunk_leaves.clear();
        }
        let n_chunks = self.chunk_roots.len();
        let outer = MerkleTree::from_leaves(&self.chunk_roots);
        let outer_root = outer.root();
        let meta = ColumnCommitMeta {
            label: self.label,
            n_rows: self.n_rows,
            chunk_log2: self.chunk_log2,
            n_chunks,
            outer_root,
        };
        (meta, outer_root)
    }
}
