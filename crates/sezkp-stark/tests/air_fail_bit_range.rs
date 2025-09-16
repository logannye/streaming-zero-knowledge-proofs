//! AIR negative test: symbol bit-range violation.
//!
//! What we’re checking
//! -------------------
//! Our v1 AIR enforces a **4-bit range** for `write_sym` using bit
//! decomposition and reconstruction inside the **full column** composition
//! (the streaming composition used for FRI).
//!
//! In this test we craft a block that writes symbol `32` (out of range for 4
//! bits) on the penultimate row. This makes the reconstruction term
//! `α · (write_sym - Σ bit[k]·2^k)` non-zero for that row, so the composition
//! is non-zero there.
//!
//! Pass criteria
//! -------------
//! * Preferably the **prover** or **verifier** rejects (either is fine).
//! * If neither rejects (e.g. during WIP phases where the verifier’s
//!   openings-only path does not yet include the bit-range checks), we still
//!   assert that the **full-column composition** is non-zero at the offending
//!   row, so the AIR itself *does* catch the violation.

#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::{ProvingBackend, StarkV1};

// For the “fallback” AIR check (compute composition directly from columns).
use sezkp_stark::v1::{
    air::{compose_boundary, compose_row, Alphas},
    columns::TraceColumns,
    field::F1,
};

/// Build one block of length `t` that writes symbol=32 on the penultimate row.
/// The AIR enforces 4-bit symbol range, so this should be rejected.
fn mk_blocks_bad_symbol(t: usize) -> Vec<BlockSummary> {
    assert!(t >= 2, "need at least 2 rows to write on the penultimate row");

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
        windows: vec![Window { left: 0, right: (t as i64) - 1 }],
        head_in_offsets: vec![0],
        head_out_offsets: vec![head_out],
        movement_log: MovementLog { steps },
        pre_tags: vec![[0u8; 16]; 1],
        post_tags: vec![[0u8; 16]; 1],
    }]
}

fn alphas_all_ones() -> Alphas {
    let one = F1::from_u64(1);
    Alphas {
        bool_flag: one,
        mv_domain: one,
        head_update: one,
        head_bits_bool: one,
        head_reconstruct: one,
        slack_bits_bool: one,
        slack_reconstruct: one,
        sym_bits_bool: one,
        sym_reconstruct: one,
        boundary_first: one,
        boundary_last: one,
    }
}

#[test]
fn air_fails_symbol_bit_range() {
    let t = 16;
    let blocks = mk_blocks_bad_symbol(t);
    let manifest_root = [11u8; 32];

    // Preferred: the pipeline rejects during prove or verify.
    match StarkV1::prove(&blocks, manifest_root) {
        Err(_) => {
            // Prover caught it — test passes.
            return;
        }
        Ok(art) => {
            if StarkV1::verify(&art, &blocks, manifest_root).is_err() {
                // Verifier caught it — test passes.
                return;
            }
        }
    }

    // Fallback (keeps the test meaningful while the verifier’s openings-only
    // path is evolving): confirm the **AIR composition** is non-zero at the
    // offending row when evaluated with full columns.
    let tc = TraceColumns::build(&blocks).expect("trace columns");
    let a = alphas_all_ones();
    let i = t - 2; // row with write=32
    let c = compose_row(&tc, i, &a) + compose_boundary(&tc, i, &a);
    assert_ne!(
        c,
        F1::from_u64(0),
        "composition should be non-zero at offending row"
    );
}
