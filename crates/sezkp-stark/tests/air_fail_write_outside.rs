//! AIR negative test: write outside declared window.
//!
//! Purpose:
//! - Ensure the v1 AIR’s “write in window” check fires when a write occurs at
//!   a head position not contained in the per-block window `[left, right]`.
//!
//! How it fails:
//! - We build a walk and set the window’s `right` bound to be one less than
//!   the final head position. We also force a write on the last row so the
//!   `write_flag` guards activate the range check. This causes the constraint
//!   (via bit-decomposed `head` and `slack = win_len - 1 - head`) to be non-zero.

#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::{ProvingBackend, StarkV1};

/// Build a block where the final head position is *just* outside the declared
/// window and a write happens at that row, triggering the guarded range check.
fn mk_blocks_fail_write_outside(t: usize) -> Vec<BlockSummary> {
    let mut steps = Vec::with_capacity(t);
    let mut head = 0i64;

    for i in 0..t {
        let mv = if i % 2 == 0 { 1 } else { 0 };
        head += mv as i64;
        // Force a write on the last row so the range constraint is enforced.
        let write = if i == t.saturating_sub(1) { Some(7) } else { None };
        steps.push(StepProjection {
            input_mv: 0,
            tapes: vec![TapeOp { write, mv }],
        });
    }

    // Final head is `head`; make the window end at `head - 1`, so the last
    // head position lies *outside* [left, right].
    let right = (head - 1).max(0);

    vec![BlockSummary {
        version: 1,
        block_id: 1,
        step_lo: 1,
        step_hi: t as u64,
        ctrl_in: 0,
        ctrl_out: 0,
        in_head_in: 0,
        in_head_out: 0,
        windows: vec![Window { left: 0, right }],
        head_in_offsets: vec![0],
        head_out_offsets: vec![head as u32],
        movement_log: MovementLog { steps },
        pre_tags: vec![[0u8; 16]; 1],
        post_tags: vec![[0u8; 16]; 1],
    }]
}

#[test]
fn air_fails_write_out_of_window() {
    let blocks = mk_blocks_fail_write_outside(16);
    let manifest_root = [8u8; 32];

    // Either prover or verifier must reject. Don’t check the error string.
    match StarkV1::prove(&blocks, manifest_root) {
        Err(_) => { /* Prover already rejected — pass. */ }
        Ok(art) => {
            assert!(
                StarkV1::verify(&art, &blocks, manifest_root).is_err(),
                "verification should fail for write outside window"
            );
        }
    }
}
