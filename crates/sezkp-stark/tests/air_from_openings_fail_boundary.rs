//! Openings-only AIR negative checks: boundary offsets must match.
//!
//! Purpose:
//! - Validate that the openings-only AIR evaluation flags bad boundary data.
//!
//! What we test:
//! 1) **First row**: tamper `in_off` so `is_first · (head - mv - in_off) = 0` fails.
//! 2) **Last row**:  tamper `out_off` so `is_last  · (head - out_off)     = 0` fails.
//!
//! Notes:
//! - These tests bypass Merkle paths and transcripts: we build `RowOpenings`
//!   directly and evaluate the AIR from openings, exercising just the algebra.

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

fn alphas_ones() -> Alphas {
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
fn tamper_in_off_triggers_boundary_failure() {
    let a = alphas_ones();
    let row = 0usize;

    // Honest first-row witness (satisfies head - mv - in_off = 0).
    let honest = PerTapeOpen {
        mv: open_u64(1, row),
        next_mv: open_u64(1, row + 1),
        write_flag: open_u64(0, row),
        write_sym: open_u64(0, row),
        head: open_u64(5, row),
        next_head: open_u64(6, row + 1),
        win_len: open_u64(16, row),
        in_off: open_u64(4, row), // 5 - 1 - 4 = 0
        out_off: open_u64(0, row),
    };

    // Tamper `in_off` by flipping one bit → violates first-row boundary eq.
    let tampered = PerTapeOpen {
        in_off: open_u64(4 ^ 1, row),
        ..honest
    };

    let q = RowOpenings {
        row,
        per_tape: vec![tampered],
        is_first: open_u64(1, row),
        is_last: open_u64(0, row),
        input_mv: open_u64(0, row),
    };

    let view = RowView::from_openings(&q);
    let c = compose_row_from_openings(&view, &a) + compose_boundary_from_openings(&view, &a);
    assert_ne!(c, f1(0), "tampered in_off should break boundary constraint");
}

#[test]
fn tamper_out_off_triggers_boundary_failure() {
    let a = alphas_ones();
    let row = 11usize;

    // Honest last-row witness (satisfies head - out_off = 0).
    let honest = PerTapeOpen {
        mv: open_u64(0, row),
        next_mv: open_u64(0, row + 1),
        write_flag: open_u64(0, row),
        write_sym: open_u64(0, row),
        head: open_u64(9, row),
        next_head: open_u64(123, row + 1), // arbitrary; masked by is_last
        win_len: open_u64(16, row),
        in_off: open_u64(0, row),
        out_off: open_u64(9, row), // 9 - 9 = 0
    };

    // Tamper `out_off` → violates last-row boundary eq.
    let tampered = PerTapeOpen {
        out_off: open_u64(8, row),
        ..honest
    };

    let q = RowOpenings {
        row,
        per_tape: vec![tampered],
        is_first: open_u64(0, row),
        is_last: open_u64(1, row),
        input_mv: open_u64(0, row),
    };

    let view = RowView::from_openings(&q);
    let c = compose_row_from_openings(&view, &a) + compose_boundary_from_openings(&view, &a);
    assert_ne!(c, f1(0), "tampered out_off should break boundary constraint");
}
