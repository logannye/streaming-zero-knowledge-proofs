//! Minimal ARE “AIR” (constraint helpers).
//!
//! These helpers mirror the (very small) Algebraic Replay Engine (ARE) safety
//! checks we already enforce at higher layers. They are intentionally tiny and
//! fast to keep the streaming path lightweight.
//!
//! What we check in this prototype:
//! - **Write-in-window**: every write must land inside the declared `[left,right]`
//!   window for its tape. (Movement is unrestricted; only writes are constrained.)
//!
//! What we **do not** check here (on purpose, for v0):
//! - Endpoint equality (left-tail/right-head) is enforced elsewhere (e.g. fold).
//!   This AIR treats declared endpoints/offsets as authoritative.
//!
//! These functions are used by the streaming commitment to validate each block.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(dead_code)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{bail, Result};
use sezkp_core::BlockSummary;

/// Run the write-in-window check once per block (matches Replay checks).
///
/// Heads start at `left + head_in_offsets[r]` for each tape `r`, then move by
/// `mv ∈ {-1,0,+1}` at each row. If a write happens at that row, the current
/// head position must be inside `[left, right]`.
///
/// # Errors
/// Returns an error if any write lands outside its declared per-tape window.
pub fn check_block_invariants(b: &BlockSummary) -> Result<()> {
    let tau = b.windows.len();

    // Absolute entry heads for each tape: base + offset_in
    let mut cur_heads = Vec::with_capacity(tau);
    for r in 0..tau {
        let base = b.windows[r].left;
        let off_in = i64::from(b.head_in_offsets[r]);
        cur_heads.push(base + off_in);
    }

    // Scan movement log: update heads; ensure writes are in-window.
    for step in &b.movement_log.steps {
        for (r, op) in step.tapes.iter().enumerate() {
            cur_heads[r] += i64::from(op.mv);

            if op.write.is_some() {
                let w = b.windows[r];
                if cur_heads[r] < w.left || cur_heads[r] > w.right {
                    bail!(
                        "write outside window on tape {r}: pos={}, window=[{},{}]",
                        cur_heads[r],
                        w.left,
                        w.right
                    );
                }
            }
        }
    }
    Ok(())
}

/// Count how many step rows this block contributes.
///
/// Useful for sanity checks in streaming/commit paths.
#[must_use]
pub fn block_rows(b: &BlockSummary) -> u64 {
    b.movement_log.steps.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, TapeOp, Window};

    #[test]
    fn writes_inside_window_ok() {
        let steps = vec![
            StepProjection { input_mv: 0, tapes: vec![TapeOp { write: None, mv: 1 }] },
            StepProjection { input_mv: 0, tapes: vec![TapeOp { write: Some(1), mv: 0 }] },
        ];
        let b = BlockSummary {
            version: 1,
            block_id: 1,
            step_lo: 1,
            step_hi: 2,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 2 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![1],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        };
        check_block_invariants(&b).unwrap();
        assert_eq!(block_rows(&b), 2);
    }

    #[test]
    fn write_outside_window_errs() {
        let steps = vec![StepProjection { input_mv: 0, tapes: vec![TapeOp { write: Some(1), mv: 1 }] }];
        let b = BlockSummary {
            version: 1,
            block_id: 1,
            step_lo: 1,
            step_hi: 1,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 0 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![0],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        };
        assert!(check_block_invariants(&b).is_err());
    }
}
