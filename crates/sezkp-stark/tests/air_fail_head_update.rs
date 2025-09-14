//! AIR negative test: head-update constraint (openings-only path).
//!
//! Purpose:
//! - Exercise the openings-only evaluation path for the transition constraint
//!   `C_head = (1 - is_last) · (head' - head - next_mv) = 0`.
//!
//! How it fails:
//! - We craft a single-row `RowOpenings` instance where `head = 10`,
//!   `next_mv = 1`, but `next_head = 12` (expected 11). With `is_last = 0`,
//!   the constraint evaluates to 1 ≠ 0, so the composition is non-zero.
//!
//! Notes:
//! - This test bypasses Merkle and transcript logic on purpose. It constructs
//!   dummy `Opening`s and evaluates the AIR purely from the provided openings.

#![allow(clippy::unwrap_used)]

use sezkp_stark::v1::{
    air::{compose_boundary_from_openings, compose_row_from_openings, Alphas, RowView},
    field::F1,
    proof::{Opening, PerTapeOpen, RowOpenings},
};

#[inline]
fn f1(x: u64) -> F1 {
    F1::from_u64(x)
}

fn open_u64(v: u64, idx: usize) -> Opening {
    Opening {
        value_le: v.to_le_bytes(),
        index: idx,
        chunk_index: 0,
        index_in_chunk: 0,
        chunk_root: [0u8; 32],
        path_in_chunk: vec![],
        path_to_chunk: vec![],
    }
}

fn alphas_all_ones() -> Alphas {
    Alphas {
        bool_flag: f1(1),
        mv_domain: f1(1),
        head_update: f1(1),
        head_bits_bool: f1(1),
        head_reconstruct: f1(1),
        slack_bits_bool: f1(1),
        slack_reconstruct: f1(1),
        sym_bits_bool: f1(1),
        sym_reconstruct: f1(1),
        boundary_first: f1(1),
        boundary_last: f1(1),
    }
}

#[test]
fn air_fails_head_update() {
    let a = alphas_all_ones();
    let row = 3usize;

    // Deliberately inconsistent: head' - head - next_mv = 12 - 10 - 1 = 1 ≠ 0.
    let per = PerTapeOpen {
        mv: open_u64(1, row),
        next_mv: open_u64(1, row + 1),
        write_flag: open_u64(0, row),
        write_sym: open_u64(0, row),
        head: open_u64(10, row),
        next_head: open_u64(12, row + 1),
        win_len: open_u64(16, row),
        in_off: open_u64(0, row),
        out_off: open_u64(0, row),
    };

    let q = RowOpenings {
        row,
        per_tape: vec![per],
        is_first: open_u64(0, row),
        is_last: open_u64(0, row), // not last ⇒ head-update is enforced
        input_mv: open_u64(0, row),
    };

    let view = RowView::from_openings(&q);
    let c = compose_row_from_openings(&view, &a) + compose_boundary_from_openings(&view, &a);

    // Must be non-zero due to the bad head update.
    assert_ne!(c, f1(0));
}
