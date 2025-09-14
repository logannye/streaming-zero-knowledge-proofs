//! AIR negative test: boundary endpoints mismatch.
//!
//! Purpose:
//! - Ensure the v1 AIR’s boundary constraints (`is_first`, `is_last`) detect
//!   mismatched entry/exit offsets for the tape head.
//!
//! How it fails:
//! - We build a well-formed walk but then corrupt the *entry* head offset
//!   (`head_in_offsets[0]`) from 0 → 2, making the boundary constraint
//!   `is_first · (head - mv - off_in) = 0` fail at the first row.

#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::{ProvingBackend, StarkV1};

/// Construct a valid walk and then corrupt the entry offset to violate
/// the `is_first` boundary equation.
fn mk_blocks_bad_endpoint(t: usize) -> Vec<BlockSummary> {
    let mut steps = Vec::with_capacity(t);
    for i in 0..t {
        let mv = if i % 2 == 0 { 1 } else { 0 };
        steps.push(StepProjection {
            input_mv: 0,
            tapes: vec![TapeOp { write: None, mv }],
        });
    }

    let head_last = steps.iter().map(|s| s.tapes[0].mv as i64).sum::<i64>();
    let mut b = BlockSummary {
        version: 1,
        block_id: 1,
        step_lo: 1,
        step_hi: t as u64,
        ctrl_in: 0,
        ctrl_out: 0,
        in_head_in: 0,
        in_head_out: 0,
        windows: vec![Window {
            left: 0,
            right: (t as i64).max(1) - 1,
        }],
        head_in_offsets: vec![0],
        head_out_offsets: vec![head_last as u32],
        movement_log: MovementLog { steps },
        pre_tags: vec![[0u8; 16]; 1],
        post_tags: vec![[0u8; 16]; 1],
    };

    // Corrupt the entry offset (should be 0 for this walk).
    b.head_in_offsets[0] = 2;
    vec![b]
}

#[test]
fn air_fails_endpoint_boundary() {
    let blocks = mk_blocks_bad_endpoint(16);
    let manifest_root = [10u8; 32];

    // Either prover or verifier must reject. Do not assert on error text.
    match StarkV1::prove(&blocks, manifest_root) {
        Err(_) => { /* Prover already caught it — pass. */ }
        Ok(art) => {
            assert!(
                StarkV1::verify(&art, &blocks, manifest_root).is_err(),
                "verification should fail for endpoint boundary violation"
            );
        }
    }
}
