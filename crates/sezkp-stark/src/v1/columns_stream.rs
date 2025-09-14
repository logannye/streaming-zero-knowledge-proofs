//! Row-wise, out-of-core materialization of v1 columns.
//!
//! This module yields **per-row snapshots** of all committed columns in the
//! exact order that the prover binds into the transcript (see `prover.rs`).
//! It allows column commitments to be constructed in a streaming fashion
//! without ever building the full `TraceColumns` in memory.
//!
//! The values produced **exactly match** those in `TraceColumns::build` for:
//!   - `input_mv`, `is_first`, `is_last`,
//!   - per-tape columns: `mv`, `write_flag`, `write_sym`,
//!   - `head` (post-move semantics, relative to window-left),
//!   - `win_len`, `in_off`, `out_off`.
//!
//! Bit-decomposition auxiliaries are *not* part of the column commitment.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use sezkp_core::BlockSummary;

use crate::v1::field::F1;

/// Per-row snapshot of the committed columns (as 8-byte LE field elements).
#[derive(Clone, Debug)]
pub struct RowColsSnapshot {
    pub input_mv: [u8; 8],
    pub is_first: [u8; 8],
    pub is_last: [u8; 8],

    pub mv: Vec<[u8; 8]>,
    pub write_flag: Vec<[u8; 8]>,
    pub write_sym: Vec<[u8; 8]>,
    pub head: Vec<[u8; 8]>,
    pub win_len: Vec<[u8; 8]>,

    pub in_off: Vec<[u8; 8]>,
    pub out_off: Vec<[u8; 8]>,
}

impl RowColsSnapshot {
    fn with_tau(tau: usize) -> Self {
        Self {
            input_mv: [0u8; 8],
            is_first: [0u8; 8],
            is_last: [0u8; 8],
            mv: vec![[0u8; 8]; tau],
            write_flag: vec![[0u8; 8]; tau],
            write_sym: vec![[0u8; 8]; tau],
            head: vec![[0u8; 8]; tau],
            win_len: vec![[0u8; 8]; tau],
            in_off: vec![[0u8; 8]; tau],
            out_off: vec![[0u8; 8]; tau],
        }
    }
}

#[inline]
fn f_le_u64(x: u64) -> [u8; 8] {
    F1::from_u64(x).to_le_bytes()
}

#[inline]
fn f_le_i64(x: i64) -> [u8; 8] {
    F1::from_i64(x).to_le_bytes()
}

/// Row-wise iterator over all committed columns derived from `blocks`.
///
/// Semantics are identical to `TraceColumns::build` (move-then-write; head is
/// post-move; head is relative to window-left at block entry).
pub struct ColumnRowIter<'a> {
    blocks: &'a [BlockSummary],
    tau: usize,

    blk_idx: usize,
    row_in_blk: usize,
    row_global: usize,

    // Per-block cached data
    blk_len: usize,
    wlen: Vec<u64>,
    cur_heads: Vec<i64>,
}

impl<'a> ColumnRowIter<'a> {
    /// Create a new row iterator over `blocks`.
    #[must_use]
    pub fn new(blocks: &'a [BlockSummary]) -> Self {
        let tau = blocks.first().map(|b| b.windows.len()).unwrap_or(0);
        let mut it = Self {
            blocks,
            tau,
            blk_idx: 0,
            row_in_blk: 0,
            row_global: 0,
            blk_len: 0,
            wlen: vec![0u64; tau],
            cur_heads: vec![0i64; tau],
        };
        it.enter_block();
        it
    }

    #[inline]
    fn enter_block(&mut self) {
        if let Some(b) = self.blocks.get(self.blk_idx) {
            self.blk_len = (b.step_hi - b.step_lo + 1) as usize;

            // Pre-compute window lengths per tape.
            for r in 0..self.tau {
                let left = b.windows[r].left;
                let right = b.windows[r].right;
                let wl = (right - left).abs() as u64 + 1;
                self.wlen[r] = wl;
            }

            // Reset running heads to 0 (relative to left bound at entry).
            for h in &mut self.cur_heads {
                *h = 0;
            }
        } else {
            self.blk_len = 0;
        }
    }

    /// Number of tapes (tau).
    #[must_use]
    pub fn tau(&self) -> usize {
        self.tau
    }
}

impl<'a> Iterator for ColumnRowIter<'a> {
    type Item = RowColsSnapshot;

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.blocks.get(self.blk_idx)?;
        if self.row_in_blk >= self.blk_len {
            // Move to next block
            self.blk_idx += 1;
            self.row_in_blk = 0;
            self.enter_block();
            return self.next();
        }

        // Build row snapshot
        let mut row = RowColsSnapshot::with_tau(self.tau);

        // is_first / is_last flags for the global row
        let is_first = (self.row_in_blk == 0) as u64;
        let is_last = (self.row_in_blk + 1 == self.blk_len) as u64;
        row.is_first = f_le_u64(is_first);
        row.is_last = f_le_u64(is_last);

        // Input movement (scalar)
        let step = &b.movement_log.steps[self.row_in_blk];
        row.input_mv = f_le_i64(step.input_mv as i64);

        // Per-tape fields
        for r in 0..self.tau {
            let op = &step.tapes[r];

            // mv ∈ {-1,0,1}
            row.mv[r] = f_le_i64(op.mv as i64);

            // write flag and symbol (0 if None)
            let flg = u64::from(op.write.is_some());
            let sym = op.write.unwrap_or(0) as u64;
            row.write_flag[r] = f_le_u64(flg);
            row.write_sym[r] = f_le_u64(sym);

            // move-then-write semantics: head is post-move
            self.cur_heads[r] += op.mv as i64;
            row.head[r] = f_le_i64(self.cur_heads[r]);

            // window length (constant across block)
            row.win_len[r] = f_le_u64(self.wlen[r]);

            // in/out offsets (constant inside the block)
            row.in_off[r] = f_le_u64(b.head_in_offsets[r] as u64);
            row.out_off[r] = f_le_u64(b.head_out_offsets[r] as u64);
        }

        // Advance iterators
        self.row_in_blk += 1;
        self.row_global += 1;

        Some(row)
    }
}
