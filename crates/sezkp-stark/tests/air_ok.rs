//! End-to-end happy path: a valid block yields a proof that verifies.
//!
//! Purpose:
//! - Sanity-check the v1 pipeline (column commitments, openings, FRI, AIR)
//!   on a simple, valid single-tape block.

#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::{ProvingBackend, StarkV1};

/// Build a demo block with τ=1 and a simple walk: mv = {1,0,1,0,...}.
/// Every third row writes symbol 5 (within the allowed 4-bit range).
fn demo_block(t: usize) -> BlockSummary {
    let mut steps = Vec::with_capacity(t);
    for i in 0..t {
        let mv = if i % 2 == 0 { 1 } else { 0 };
        steps.push(StepProjection {
            input_mv: 0,
            tapes: vec![TapeOp {
                write: if i % 3 == 0 { Some(5) } else { None },
                mv,
            }],
        });
    }
    let head_last = steps.iter().map(|s| s.tapes[0].mv as i64).sum::<i64>();

    BlockSummary {
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
    }
}

#[test]
fn air_valid_proof_verifies() {
    let blocks = vec![demo_block(16)];
    let manifest_root = [7u8; 32];

    // Prefer the streaming prover (matches the rest of the suite),
    // but fall back to the in-memory prover if streaming is unavailable.
    let art = match StarkV1::prove_streaming(&blocks, manifest_root) {
        Ok(a) => a,
        Err(_) => StarkV1::prove(&blocks, manifest_root).expect("in-memory prove must succeed"),
    };

    // End-to-end verify must succeed.
    StarkV1::verify(&art, &blocks, manifest_root).expect("verify should succeed on valid block");
}
