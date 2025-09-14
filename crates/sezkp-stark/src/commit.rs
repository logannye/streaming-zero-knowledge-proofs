// crates/sezkp-stark/src/commit.rs

//! Streaming commitment (hash-as-you-go) over the single row stream.
//!
//! For v0 we commit to the *single* row stream. We implement this with a
//! transcript: absorb all row bytes in order with domain separation, then
//! derive a 32-byte challenge as the commitment “root”.

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

use anyhow::{ensure, Context, Result};
use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};

use crate::{air, witness};

/// Result of committing to the streaming witness.
#[derive(Clone, Debug)]
pub struct CommitResult {
    /// 32-byte transcript-derived commitment to the row stream.
    pub root: [u8; 32],
    /// Total number of rows streamed.
    pub n_rows: u64,
    /// Number of work tapes (τ).
    pub tau: usize,
}

/// Compute a streaming commitment over the encoded rows with a transcript.
///
/// Validates each block’s write-in-window invariant and checks `tau` consistency
/// across all blocks before streaming.
pub fn commit_blocks(blocks: &[BlockSummary]) -> Result<CommitResult> {
    if blocks.is_empty() {
        // Deterministic empty-domain commitment.
        let mut tr = Blake3Transcript::new("sezkp-stark/v0/row-stream/empty");
        let mut root = [0u8; 32];
        root.copy_from_slice(&tr.challenge_bytes("root", 32));
        return Ok(CommitResult { root, n_rows: 0, tau: 0 });
    }

    // Sanity: block invariants (write-in-window) and constant τ.
    for (k, b) in blocks.iter().enumerate() {
        air::check_block_invariants(b).with_context(|| {
            format!("ARE validation failed for block #{k} (k={}): invariant violation", b.block_id)
        })?;
    }
    let tau = blocks[0].windows.len();
    for (k, b) in blocks.iter().enumerate().skip(1) {
        ensure!(
            b.windows.len() == tau,
            "tau mismatch at block #{k} (k={}): {} vs {}",
            b.block_id,
            b.windows.len(),
            tau
        );
    }

    // Domain-separated transcript for the row stream.
    let mut tr = Blake3Transcript::new("sezkp-stark/v0/row-stream");
    tr.absorb_u64("tau", tau as u64);

    // Stream rows in fixed-size chunks to bound memory.
    const CHUNK_ROWS: usize = 4096;
    let mut total_rows: u64 = 0;
    witness::stream_rows(blocks, CHUNK_ROWS, |chunk| {
        tr.absorb("rows", chunk);
        // Each chunk is a whole-number multiple of row_size(tau).
        total_rows += (chunk.len() / witness::row_size(tau)) as u64;
    });

    let mut root = [0u8; 32];
    root.copy_from_slice(&tr.challenge_bytes("root", 32));

    Ok(CommitResult { root, n_rows: total_rows, tau })
}
