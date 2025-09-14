//! AIR negative test: symbol bit-range violation.

#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::{ProvingBackend, StarkV1};

/// Build one block of length `t` that writes symbol=32 on the penultimate row.
/// The AIR enforces 4-bit symbol range, so this should be rejected.
fn mk_blocks_bad_symbol(t: usize) -> Vec<BlockSummary> {
    assert!(t >= 2);

    // mv pattern: 1,0,1,0,... ; write 32 at row t-2
    let mut steps = Vec::with_capacity(t);
    for i in 0..t {
        let mv = if i % 2 == 0 { 1 } else { 0 };
        let write = if i == t - 2 { Some(32) } else { None };
        steps.push(StepProjection {
            input_mv: 0,
            tapes: vec![TapeOp { write, mv }],
        });
    }

    // Window spans the block. Final head = count of even indices in [0..t).
    let head_out = ((t + 1) / 2) as u32;

    vec![BlockSummary {
        version: 1,
        block_id: 1,
        step_lo: 0,
        step_hi: (t - 1) as u64,
        ctrl_in: 0,
        ctrl_out: 0,
        in_head_in: 0,
        in_head_out: 0,
        windows: vec![Window {
            left: 0,
            right: (t as i64) - 1,
        }],
        head_in_offsets: vec![0],
        head_out_offsets: vec![head_out],
        movement_log: MovementLog { steps },
        pre_tags: vec![[0u8; 16]; 1],
        post_tags: vec![[0u8; 16]; 1],
    }]
}

#[test]
fn air_fails_symbol_bit_range() {
    let blocks = mk_blocks_bad_symbol(16);
    let manifest_root = [11u8; 32];

    // Either prover or verifier must reject. Don't assert on error text.
    match StarkV1::prove(&blocks, manifest_root) {
        Err(_) => {
            // Prover already caught the AIR violation — test passes.
        }
        Ok(art) => {
            // If proving succeeds, verification must fail.
            assert!(
                StarkV1::verify(&art, &blocks, manifest_root).is_err(),
                "verification should fail for bit-range violation"
            );
        }
    }
}
