// crates/sezkp-trace/src/partition.rs

//! Partition a `TraceFile` into `BlockSummary` (σ_k) windows and logs.

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

use crate::format::{Step as FStep, TraceFile};
use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp as CoreTapeOp, Window};

/// Partition a trace into contiguous blocks of size `b` (last may be shorter),
/// producing σ_k (`BlockSummary`) with windows/offsets large enough to contain
/// all *post-move* head positions that the block touches.
///
/// This matches the ARE's "move then (optionally) write" semantics.
/// 
/// # Panics
/// Panics if `b == 0` (invalid block size).
#[must_use]
pub fn partition_trace(tf: &TraceFile, b: u32) -> Vec<BlockSummary> {
    let steps = &tf.steps;
    let t = steps.len();
    if t == 0 {
        return Vec::new();
    }
    assert!(b > 0, "partition_trace: block size b must be > 0");

    let tau = tf.tau as usize;
    let b = b as usize;

    // Keep a cumulative input-head position so σ_k.{in_head_in,out} are absolute.
    let mut global_input_head: i64 = 0;

    let mut out = Vec::new();
    let mut k: u32 = 1;

    for chunk_start in (0..t).step_by(b) {
        let chunk_end = (chunk_start + b).min(t);
        let block_steps: &[FStep] = &steps[chunk_start..chunk_end];

        // --- Gather per-tape head span (ARE order: move then (optionally) write).
        // Heads start at 0 for each tape at block entry (absolute via offsets).
        let mut cur_heads: Vec<i64> = vec![0; tau];
        let mut min_pos: Vec<i64> = vec![0; tau];
        let mut max_pos: Vec<i64> = vec![0; tau];

        // Track input head drift across the block.
        let in_head_in = global_input_head;
        for st in block_steps {
            // Input head drift.
            global_input_head += i64::from(st.input_mv);

            // Per-tape: first move, then (optionally) write at the *new* position.
            for (r, op) in st.tapes.iter().enumerate() {
                cur_heads[r] += i64::from(op.mv);
                if cur_heads[r] < min_pos[r] {
                    min_pos[r] = cur_heads[r];
                }
                if cur_heads[r] > max_pos[r] {
                    max_pos[r] = cur_heads[r];
                }
            }
        }
        let in_head_out = global_input_head;

        // --- Build windows and head offsets.
        let mut windows = Vec::with_capacity(tau);
        let mut head_in_offsets = Vec::with_capacity(tau);
        let mut head_out_offsets = Vec::with_capacity(tau);

        for r in 0..tau {
            let left = min_pos[r];
            let right = max_pos[r];
            windows.push(Window { left, right });

            // Entry head is 0 (relative), so the entry offset within the window is (0 - left).
            let off_in = 0i64 - left;
            // Exit head is cur_heads[r] (relative), so exit offset is (cur - left).
            let off_out = cur_heads[r] - left;

            // Offsets are non-negative as long as `left <= 0`. Clamp on overflow to keep
            // this prototype total (extremely large blocks could overflow u32).
            let off_in_u32 = u32::try_from(off_in).unwrap_or(u32::MAX);
            let off_out_u32 = u32::try_from(off_out).unwrap_or(u32::MAX);

            head_in_offsets.push(off_in_u32);
            head_out_offsets.push(off_out_u32);
        }

        // --- Convert steps to the runtime movement log format (core types).
        let mut proj_steps = Vec::with_capacity(block_steps.len());
        for st in block_steps {
            let tapes = st
                .tapes
                .iter()
                .map(|t| CoreTapeOp { write: t.write, mv: t.mv })
                .collect::<Vec<_>>();
            proj_steps.push(StepProjection { input_mv: st.input_mv, tapes });
        }

        // --- Assemble σ_k.
        let sigma = BlockSummary {
            version: 1,
            block_id: k,
            step_lo: (chunk_start as u64) + 1,
            step_hi: chunk_end as u64,
            // Advisory finite control for now.
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in,
            in_head_out,
            windows,
            head_in_offsets,
            head_out_offsets,
            movement_log: MovementLog { steps: proj_steps },
            pre_tags: vec![[0u8; 16]; tau],
            post_tags: vec![[0u8; 16]; tau],
        };

        out.push(sigma);
        k += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::generate_trace;

    #[test]
    fn partitions_empty_trace() {
        let tf = TraceFile { version: 1, tau: 2, steps: vec![], meta: None };
        let v = partition_trace(&tf, 4);
        assert!(v.is_empty());
    }

    #[test]
    fn partitions_basic_blocks() {
        let tf = generate_trace(10, 2);
        let v = partition_trace(&tf, 4);
        // 10 steps with b=4 -> blocks: [4, 4, 2]
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].step_lo, 1);
        assert_eq!(v[0].step_hi, 4);
        assert_eq!(v[1].step_lo, 5);
        assert_eq!(v[1].step_hi, 8);
        assert_eq!(v[2].step_lo, 9);
        assert_eq!(v[2].step_hi, 10);
    }
}
