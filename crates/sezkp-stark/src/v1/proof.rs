//! Structured proof objects for STARK v1.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use serde::{Deserialize, Serialize};

/// Per-column outer Merkle root bound into the transcript.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnRoot {
    pub label: String,
    pub root: [u8; 32],
}

/// Wrapper for FRI layer roots (layer-0..last).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriRoots {
    pub roots: Vec<[u8; 32]>,
}

/// Opening of one column value (little-endian) with a **chunked** Merkle path.
///
/// The proof is split in two parts:
///  - path inside the chunk (leaf → chunk_root)
///  - path from chunk_root to the global outer root (chunk_root → outer_root)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opening {
    pub value_le: [u8; 8],
    pub index: usize,

    // Chunked commitment proof data:
    pub chunk_index: usize,
    pub index_in_chunk: usize,
    pub chunk_root: [u8; 32],
    pub path_in_chunk: Vec<[u8; 32]>,
    pub path_to_chunk: Vec<[u8; 32]>,
}

/// Per-tape set of openings for a single queried row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerTapeOpen {
    pub mv: Opening,
    pub next_mv: Opening, // used by head-update constraint from openings
    pub write_flag: Opening,
    pub write_sym: Opening,
    pub head: Opening,
    pub next_head: Opening,
    pub win_len: Opening,
    // Offsets needed for boundary checks from openings only
    pub in_off: Opening,
    pub out_off: Opening,
}

/// Row-level set of openings (tape-wise + scalar flags).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowOpenings {
    pub row: usize,
    pub per_tape: Vec<PerTapeOpen>,
    pub is_first: Opening,
    pub is_last: Opening,
    pub input_mv: Opening,
}

/// FRI query: indices per layer + pairs of leaves for each layer (except last).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriQuery {
    pub positions: Vec<usize>, // per-layer index
    pub pairs: Vec<([u8; 8], Vec<[u8; 32]>, [u8; 8], Vec<[u8; 32]>)>, // (v_i, path_i, v_j, path_j)
}

/// Complete proof object for v1 (columnar PIOP + FRI).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofV1 {
    /// LDE domain size used by FRI (may be > number of trace rows).
    pub domain_n: usize,
    pub tau: usize,

    /// Column commitments (outer roots) in transcript order.
    pub col_roots: Vec<ColumnRoot>,

    /// Column openings at sampled rows (AIR).
    pub queries: Vec<RowOpenings>,

    /// FRI layers + queries.
    pub fri_roots: FriRoots,
    pub fri_queries: Vec<FriQuery>,
    pub fri_final_value_le: [u8; 8],

    /// Merkle root of the block-summaries manifest (bound at the top).
    pub manifest_root: [u8; 32],
}
