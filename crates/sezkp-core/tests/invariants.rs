//! Invariants for replay (ARE) and finite-state combination.
//!
//! These tests treat:
//! - the **replay engine** as authoritative for interface equality (control +
//!   input head continuity) and write-safety inside per-tape windows, and
//! - the **combiner** as a pure projection that should compose associatively
//!   when interfaces chain.

use proptest::prelude::*;
use sezkp_core::{
    BlockSummary, BoundedReplay, Combiner, ConstantCombiner, ExactReplayer, FiniteState,
    MovementLog, Offset, StepProjection, TapeOp, Window,
};

/// Build a `BlockSummary` with the essentials for tests.
///
/// Assumes all per-tape vectors have equal length `tau = windows.len()`.
#[track_caller]
fn mk_block(
    block_id: u32,
    ctrl_in: u16,
    ctrl_out: u16,
    in_head_in: i64,
    in_head_out: i64,
    windows: Vec<Window>,
    head_in_offsets: Vec<Offset>,
    head_out_offsets: Vec<Offset>,
    steps: Vec<StepProjection>,
) -> BlockSummary {
    let tau = windows.len();
    assert_eq!(
        head_in_offsets.len(),
        tau,
        "head_in_offsets length must equal windows length"
    );
    assert_eq!(
        head_out_offsets.len(),
        tau,
        "head_out_offsets length must equal windows length"
    );

    // Lightweight, saturating step index math for determinism in tests.
    let step_len = steps.len() as u64;
    let step_lo =
        1u64.saturating_add((block_id as u64).saturating_sub(1).saturating_mul(step_len));
    let step_hi = (block_id as u64).saturating_mul(step_len);

    BlockSummary {
        version: 1,
        block_id,
        step_lo,
        step_hi,
        ctrl_in,
        ctrl_out,
        in_head_in,
        in_head_out,
        windows,
        head_in_offsets,
        head_out_offsets,
        movement_log: MovementLog { steps },
        // Advisory tags (not used for soundness)
        pre_tags: vec![[0u8; 16]; 2],
        post_tags: vec![[0u8; 16]; 2],
    }
}

/// Build a single replay step with uniform per-tape move `mv` and no writes.
#[track_caller]
fn mk_step(input_mv: i8, tau: usize, mv: i8) -> StepProjection {
    StepProjection {
        input_mv,
        tapes: (0..tau).map(|_| TapeOp::new(None, mv)).collect(),
    }
}

/// Replay of a single block produces finite-state with consistent length vectors.
#[test]
fn replay_block_basic() {
    let tau = 2usize;
    let steps = vec![mk_step(1, tau, 0); 4];
    let windows = vec![
        Window { left: 0, right: 3 },
        Window { left: -1, right: 2 },
    ];

    let blk = mk_block(1, 7, 8, 0, 4, windows, vec![0, 1], vec![3, 2], steps);

    let rep = ExactReplayer::new(Default::default());
    let fs = rep.replay_block(&blk);

    assert_eq!(fs.work_head_in.len(), tau, "work_head_in length must be τ");
    assert_eq!(fs.work_head_out.len(), tau, "work_head_out length must be τ");
}

/// Associativity on finite-state combiner (projection-only).
#[test]
fn combiner_associative_projection() {
    let c = ConstantCombiner::new();

    // Construct three compatible finite states on 2 tapes.
    let a = FiniteState {
        ctrl_in: 1,
        ctrl_out: 2,
        in_head_in: 0,
        in_head_out: 1,
        work_head_in: vec![0, 10],
        work_head_out: vec![1, 11],
        flags: 0,
        tag: [0; 16],
    };
    let b = FiniteState {
        ctrl_in: 2, // matches a.ctrl_out
        ctrl_out: 3,
        in_head_in: 1, // matches a.in_head_out
        in_head_out: 2,
        work_head_in: vec![1, 11], // matches a.work_head_out
        work_head_out: vec![2, 12],
        flags: 0,
        tag: [0; 16],
    };
    let d = FiniteState {
        ctrl_in: 3, // matches b.ctrl_out
        ctrl_out: 4,
        in_head_in: 2,
        in_head_out: 5,
        work_head_in: vec![2, 12],
        work_head_out: vec![3, 13],
        flags: 0,
        tag: [0; 16],
    };

    let ab = c.combine(&a, &b);
    let bd = c.combine(&b, &d);

    let left = c.combine(&ab, &d);
    let right = c.combine(&a, &bd);

    assert_eq!(left.ctrl_in, right.ctrl_in);
    assert_eq!(left.ctrl_out, right.ctrl_out);
    assert_eq!(left.in_head_in, right.in_head_in);
    assert_eq!(left.in_head_out, right.in_head_out);
    assert_eq!(left.work_head_in, right.work_head_in);
    assert_eq!(left.work_head_out, right.work_head_out);

    // Flags/tag aggregation law for ConstantCombiner.
    assert_eq!(left.flags, (a.flags ^ b.flags) ^ d.flags);
    assert_eq!(left.tag, d.tag);
}

// Keep CI predictable while still exercising a wide range.
prop_compose! {
    fn arb_len()(len in 1usize..=16) -> usize { len }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64, // good CI/runtime balance
        .. ProptestConfig::default()
    })]

    // Property: Replay::interface_ok detects mismatches and accepts matches.
    #[test]
    fn interface_ok_roundtrip(
        ctrl in 0u16..=1000,
        in0 in -50i64..=50,
        len in arb_len(),
    ) {
        let tau = 2usize;
        let mv = 0i8;
        let steps = vec![mk_step(0, tau, mv); len];

        let windows = vec![
            Window { left: 0, right: len as i64 - 1 },
            Window { left: -2, right: len as i64 - 3 },
        ];

        // Block 1 ends where Block 2 begins (interface equality).
        let b1 = mk_block(
            1, ctrl, ctrl + 1,
            in0, in0 + len as i64,
            windows.clone(),
            vec![0, 0],
            vec![(len - 1) as u32, (len - 1) as u32],
            steps.clone()
        );
        let b2 = mk_block(
            2, ctrl + 1, ctrl + 2,
            in0 + len as i64, in0 + 2 * len as i64,
            windows,
            vec![0, 0],
            vec![(len - 1) as u32, (len - 1) as u32],
            steps
        );

        let rep = ExactReplayer::new(Default::default());
        let fs1 = rep.replay_block(&b1);
        let fs2 = rep.replay_block(&b2);

        // Replay::interface_ok only checks control + input head continuity (by design).
        prop_assert!(rep.interface_ok(&fs1, &fs2), "expected interface to match for consecutive blocks");

        // Flip a single head in fs2 and check mismatch.
        let mut fs2_bad = fs2.clone();
        fs2_bad.in_head_in += 1;
        prop_assert!(!rep.interface_ok(&fs1, &fs2_bad), "expected interface mismatch after perturbation");
    }
}

/// Negative test: writes outside a window are rejected by the replay engine.
///
/// `ExactReplayer` wraps the fallible engine and will panic on error.
#[test]
#[should_panic(expected = "write outside window")]
fn replay_rejects_write_outside_window() {
    // Single tape, window [0,0], start at 0, move right and write at +1 (outside).
    let tau = 1usize;
    let windows = vec![Window { left: 0, right: 0 }];
    let steps = vec![StepProjection {
        input_mv: 0,
        tapes: vec![TapeOp::new(Some(1), 1)],
    }];

    let blk = mk_block(
        1,
        0,
        1,
        0,
        0,
        windows,
        vec![0], // in offset 0 → absolute 0
        vec![0], // out offset doesn't matter for this test
        steps,
    );

    let rep = ExactReplayer::new(Default::default());
    // Panics because the single write occurs at absolute position 1, outside [0,0].
    let _ = rep.replay_block(&blk);
}
