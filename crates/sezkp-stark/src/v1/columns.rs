//! Columnar trace for STARK v1, including auxiliary columns for range checks.
//!
//! New in this revision:
//!  - Bit-decomposition for `write_sym` (4 bits).
//!  - Bit-decomposition for `head` and for `slack = win_len - 1 - head`
//!    using `HEAD_BITS` bits; this powers a non-negativity comparison
//!    to enforce `0 <= head <= win_len - 1` when `write_flag = 1`.
//!  - A canonical, bounded **interface digest** utility
//!    [`interface_boundary_digest`] for the folding line.
//!  - Per-block boundary helpers for leaves:
//!      * [`boundary_left_tail_digest`]
//!      * [`boundary_right_head_digest`]
//!      * (optional) raw boundary windows: [`left_tail_window`], [`right_head_window`].

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::Result;
use blake3::Hasher;
use sezkp_core::BlockSummary;

use crate::v1::field::F1;

/// Number of bits used to decompose the written symbol.
pub const SYM_BITS: usize = 4;
/// Number of bits used for head/slack range checks.
pub const HEAD_BITS: usize = 16;

/// Default bounded window (steps) taken from each side of the interface.
pub const IFACE_WINDOW_STEPS: usize = 32;

/// Canonical, bounded interface digest.
///
/// This digest is intentionally simple and deterministic. It includes:
///  - tape count `tau`,
///  - static in/out head offsets for both blocks, and
///  - the last `K` steps from the **left** block and first `K` steps from the
///    **right** block (where `K = IFACE_WINDOW_STEPS`), for each tape: `(mv,
///    write_flag, write_sym)`.
///
/// The folding line (B-line) can feed this digest into its ARE micro-proof.
///
#[must_use]
pub fn interface_boundary_digest(left: &BlockSummary, right: &BlockSummary) -> [u8; 32] {
    let tau = left.windows.len();
    let mut h = Hasher::new();
    h.update(b"sezkp/iface/v1");
    h.update(&(tau as u32).to_le_bytes());

    // Static offsets per tape (from block metadata). Use i32 encodings.
    for r in 0..tau {
        h.update(&(left.head_in_offsets[r] as i32).to_le_bytes());
        h.update(&(left.head_out_offsets[r] as i32).to_le_bytes());
        h.update(&(right.head_in_offsets[r] as i32).to_le_bytes());
        h.update(&(right.head_out_offsets[r] as i32).to_le_bytes());
    }

    // Last K steps from left
    let left_steps = &left.movement_log.steps;
    let k_l = IFACE_WINDOW_STEPS.min(left_steps.len());
    for step in &left_steps[left_steps.len().saturating_sub(k_l)..] {
        for r in 0..tau {
            let op = &step.tapes[r];
            let wflag = u32::from(op.write.is_some());
            let wsym = op.write.unwrap_or(0) as u32;
            h.update(&(op.mv as i32).to_le_bytes());
            h.update(&wflag.to_le_bytes());
            h.update(&wsym.to_le_bytes());
        }
    }

    // First K steps from right
    let right_steps = &right.movement_log.steps;
    let k_r = IFACE_WINDOW_STEPS.min(right_steps.len());
    for step in &right_steps[..k_r] {
        for r in 0..tau {
            let op = &step.tapes[r];
            let wflag = u32::from(op.write.is_some());
            let wsym = op.write.unwrap_or(0) as u32;
            h.update(&(op.mv as i32).to_le_bytes());
            h.update(&wflag.to_le_bytes());
            h.update(&wsym.to_le_bytes());
        }
    }

    *h.finalize().as_bytes()
}

/* ----------------------------- Leaf helpers -------------------------------- */

/// A single “boundary row” used by the per-block boundary windows.
#[derive(Clone, Copy, Debug)]
pub struct BoundaryRow {
    /// Move delta for this tape at this step (post-move semantics overall).
    pub mv: i32,
    /// 0/1 flag indicating writes.
    pub write_flag: u32,
    /// Written symbol (0 if none).
    pub write_sym: u32,
}

/// Return the last `k` steps (all tapes) of `block` in boundary-row encoding.
///
/// This materializes the **left tail** the leaf proof may wish to commit to.
#[must_use]
pub fn left_tail_window(block: &BlockSummary, k: usize) -> Vec<Vec<BoundaryRow>> {
    let tau = block.windows.len();
    let steps = &block.movement_log.steps;
    let take = IFACE_WINDOW_STEPS.min(k).min(steps.len());
    let mut out = vec![Vec::with_capacity(take); tau];
    for step in &steps[steps.len().saturating_sub(take)..] {
        for r in 0..tau {
            let op = &step.tapes[r];
            out[r].push(BoundaryRow {
                mv: op.mv as i32,
                write_flag: u32::from(op.write.is_some()),
                write_sym: op.write.unwrap_or(0) as u32,
            });
        }
    }
    out
}

/// Return the first `k` steps (all tapes) of `block` in boundary-row encoding.
///
/// This materializes the **right head** the leaf proof may wish to commit to.
#[must_use]
pub fn right_head_window(block: &BlockSummary, k: usize) -> Vec<Vec<BoundaryRow>> {
    let tau = block.windows.len();
    let steps = &block.movement_log.steps;
    let take = IFACE_WINDOW_STEPS.min(k).min(steps.len());
    let mut out = vec![Vec::with_capacity(take); tau];
    for step in &steps[..take] {
        for r in 0..tau {
            let op = &step.tapes[r];
            out[r].push(BoundaryRow {
                mv: op.mv as i32,
                write_flag: u32::from(op.write.is_some()),
                write_sym: op.write.unwrap_or(0) as u32,
            });
        }
    }
    out
}

/// Deterministic digest of the **left tail** (last `k` steps) of a single block.
#[must_use]
pub fn boundary_left_tail_digest(block: &BlockSummary, k: usize) -> [u8; 32] {
    let tau = block.windows.len();
    let mut h = Hasher::new();
    h.update(b"sezkp/iface/left_tail/v1");
    h.update(&(tau as u32).to_le_bytes());

    // Static offsets for this block
    for r in 0..tau {
        h.update(&(block.head_in_offsets[r] as i32).to_le_bytes());
        h.update(&(block.head_out_offsets[r] as i32).to_le_bytes());
    }

    // Last K steps
    let steps = &block.movement_log.steps;
    let take = IFACE_WINDOW_STEPS.min(k).min(steps.len());
    for step in &steps[steps.len().saturating_sub(take)..] {
        for r in 0..tau {
            let op = &step.tapes[r];
            let wflag = u32::from(op.write.is_some());
            let wsym = op.write.unwrap_or(0) as u32;
            h.update(&(op.mv as i32).to_le_bytes());
            h.update(&wflag.to_le_bytes());
            h.update(&wsym.to_le_bytes());
        }
    }

    *h.finalize().as_bytes()
}

/// Deterministic digest of the **right head** (first `k` steps) of a single block.
#[must_use]
pub fn boundary_right_head_digest(block: &BlockSummary, k: usize) -> [u8; 32] {
    let tau = block.windows.len();
    let mut h = Hasher::new();
    h.update(b"sezkp/iface/right_head/v1");
    h.update(&(tau as u32).to_le_bytes());

    // Static offsets for this block
    for r in 0..tau {
        h.update(&(block.head_in_offsets[r] as i32).to_le_bytes());
        h.update(&(block.head_out_offsets[r] as i32).to_le_bytes());
    }

    // First K steps
    let steps = &block.movement_log.steps;
    let take = IFACE_WINDOW_STEPS.min(k).min(steps.len());
    for step in &steps[..take] {
        for r in 0..tau {
            let op = &step.tapes[r];
            let wflag = u32::from(op.write.is_some());
            let wsym = op.write.unwrap_or(0) as u32;
            h.update(&(op.mv as i32).to_le_bytes());
            h.update(&wflag.to_le_bytes());
            h.update(&wsym.to_le_bytes());
        }
    }

    *h.finalize().as_bytes()
}

/* ----------------------------- Full trace view ----------------------------- */

/// Columnar view of the execution trace and auxiliaries.
#[derive(Clone, Debug)]
pub struct TraceColumns {
    /// Base-domain length (sum of per-block lengths).
    pub n: usize,
    /// Number of tapes.
    pub tau: usize,

    /* scalars per row */
    pub input_mv: Vec<F1>,
    pub is_first: Vec<F1>,
    pub is_last: Vec<F1>,

    /* per-tape columns, length tau; each inner Vec has length n */
    pub mv: Vec<Vec<F1>>,
    pub write_flag: Vec<Vec<F1>>,
    pub write_sym: Vec<Vec<F1>>,
    pub head: Vec<Vec<F1>>,
    pub win_len: Vec<Vec<F1>>,

    /* boundary metadata (per tape) */
    pub in_off: Vec<Vec<F1>>,
    pub out_off: Vec<Vec<F1>>,

    /* auxiliary columns for range/bit checks */
    /// `write_sym` bits (LSB first): [tau][SYM_BITS][n]
    pub sym_bits: Vec<Vec<Vec<F1>>>,
    /// `head` bits (LSB first): [tau][HEAD_BITS][n]
    pub head_bits: Vec<Vec<Vec<F1>>>,
    /// `slack` bits where `slack = win_len - 1 - head` (LSB first): [tau][HEAD_BITS][n]
    pub slack_bits: Vec<Vec<Vec<F1>>>,
}

impl TraceColumns {
    /// Build the columnar view from block summaries.
    pub fn build(blocks: &[BlockSummary]) -> Result<Self> {
        // Total rows = sum over blocks of (block_len)
        let n: usize = blocks
            .iter()
            .map(|b| (b.step_hi - b.step_lo + 1) as usize)
            .sum();
        let tau = blocks.first().map(|b| b.windows.len()).unwrap_or(0);

        let mut input_mv = vec![F1::from_u64(0); n];
        let mut is_first = vec![F1::from_u64(0); n];
        let mut is_last = vec![F1::from_u64(0); n];

        let mut mv = vec![vec![F1::from_u64(0); n]; tau];
        let mut write_flag = vec![vec![F1::from_u64(0); n]; tau];
        let mut write_sym = vec![vec![F1::from_u64(0); n]; tau];
        let mut head = vec![vec![F1::from_u64(0); n]; tau];
        let mut win_len = vec![vec![F1::from_u64(0); n]; tau];

        let mut in_off = vec![vec![F1::from_u64(0); n]; tau];
        let mut out_off = vec![vec![F1::from_u64(0); n]; tau];

        // Aux columns
        let mut sym_bits = vec![vec![vec![F1::from_u64(0); n]; SYM_BITS]; tau];
        let mut head_bits = vec![vec![vec![F1::from_u64(0); n]; HEAD_BITS]; tau];
        let mut slack_bits = vec![vec![vec![F1::from_u64(0); n]; HEAD_BITS]; tau];

        // Fill row-wise across blocks
        let mut row = 0usize;
        for b in blocks {
            let len = (b.step_hi - b.step_lo + 1) as usize;
            if len == 0 {
                continue;
            }
            // masks
            is_first[row] = F1::from_u64(1);
            is_last[row + len - 1] = F1::from_u64(1);

            // precompute window lengths
            let mut wlen: Vec<u64> = Vec::with_capacity(tau);
            for r in 0..tau {
                let left = b.windows[r].left;
                let right = b.windows[r].right;
                let wl = (right - left).unsigned_abs() + 1;
                wlen.push(wl);
            }

            // head running positions relative to window-left = 0 at entry
            let mut cur_heads = vec![0i64; tau];

            for (j, step) in b.movement_log.steps.iter().enumerate() {
                input_mv[row + j] = F1::from_i64(step.input_mv as i64);

                // per tape
                for r in 0..tau {
                    let op = &step.tapes[r];
                    mv[r][row + j] = F1::from_i64(op.mv as i64);
                    write_flag[r][row + j] = F1::from_u64(u64::from(op.write.is_some()));
                    write_sym[r][row + j] = F1::from_u64(op.write.unwrap_or(0) as u64);

                    // move then write semantics: head is post-move
                    cur_heads[r] += i64::from(op.mv);

                    // head is relative to left bound (so 0 at entry)
                    head[r][row + j] = F1::from_i64(cur_heads[r]);
                    win_len[r][row + j] = F1::from_u64(wlen[r]);

                    // in/out offsets are constant inside the block
                    in_off[r][row + j] = F1::from_u64(b.head_in_offsets[r] as u64);
                    out_off[r][row + j] = F1::from_u64(b.head_out_offsets[r] as u64);

                    // --------- bit decompositions ----------
                    // write_sym bits
                    let sym_u = u64::from_le_bytes(write_sym[r][row + j].to_le_bytes());
                    for k in 0..SYM_BITS {
                        let bit = (sym_u >> k) & 1;
                        sym_bits[r][k][row + j] = F1::from_u64(bit);
                    }
                    // head bits
                    let head_u = u64::from_le_bytes(head[r][row + j].to_le_bytes());
                    for k in 0..HEAD_BITS {
                        let bit = (head_u >> k) & 1;
                        head_bits[r][k][row + j] = F1::from_u64(bit);
                    }
                    // slack = (win_len - 1) - head
                    let slack_f = win_len[r][row + j] - F1::from_u64(1) - head[r][row + j];
                    let slack_u = u64::from_le_bytes(slack_f.to_le_bytes());
                    for k in 0..HEAD_BITS {
                        let bit = (slack_u >> k) & 1;
                        slack_bits[r][k][row + j] = F1::from_u64(bit);
                    }
                }
            }

            row += len;
        }

        Ok(Self {
            n,
            tau,
            input_mv,
            is_first,
            is_last,
            mv,
            write_flag,
            write_sym,
            head,
            win_len,
            in_off,
            out_off,
            sym_bits,
            head_bits,
            slack_bits,
        })
    }
}
