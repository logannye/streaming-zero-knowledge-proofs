//! Openings-only AIR happy-path checks.
//!
//! Purpose:
//! - Confirm the openings-only AIR evaluation returns 0 (constraints satisfied)
//!   on both middle rows (no boundary masks) and boundary rows with consistent
//!   offsets.
//!
//! Cases:
//! 1) Middle row: `is_first = is_last = 0`, valid head-update and domains.
//! 2) First row:  `is_first = 1`, satisfies `head - mv - in_off = 0`.
//! 3) Last row:   `is_last  = 1`, satisfies `head - out_off = 0`.

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
fn openings_ok_middle_row_no_boundary() {
    let row = 5usize;

    // Middle-row constraints:
    // - flg boolean (take flg=0),
    // - mv domain (take mv=1),
    // - head-update with post-move semantics via next_mv=1: head'=11, head=10.
    let per = PerTapeOpen {
        mv: open_u64(1, row),
        next_mv: open_u64(1, row + 1),
        write_flag: open_u64(0, row),
        write_sym: open_u64(0, row),
        head: open_u64(10, row),
        next_head: open_u64(11, row + 1),
        win_len: open_u64(16, row),
        in_off: open_u64(0, row),
        out_off: open_u64(0, row),
    };

    let q = RowOpenings {
        row,
        per_tape: vec![per],
        is_first: open_u64(0, row),
        is_last: open_u64(0, row),
        input_mv: open_u64(0, row),
    };

    let view = RowView::from_openings(&q);
    let a = alphas_ones();
    let c = compose_row_from_openings(&view, &a) + compose_boundary_from_openings(&view, &a);
    assert_eq!(c, f1(0), "middle-row openings should satisfy AIR (C=0)");
}

#[test]
fn openings_ok_first_and_last_rows_with_offsets() {
    let a = alphas_ones();

    // --- First row: enforce head - mv - in_off = 0 and valid head-update.
    let row_first = 0usize;
    let per_first = PerTapeOpen {
        mv: open_u64(1, row_first),
        next_mv: open_u64(1, row_first + 1),
        write_flag: open_u64(0, row_first),
        write_sym: open_u64(0, row_first),
        head: open_u64(5, row_first),
        next_head: open_u64(6, row_first + 1),
        win_len: open_u64(16, row_first),
        in_off: open_u64(4, row_first), // 5 - 1 - 4 = 0
        out_off: open_u64(0, row_first),
    };
    let q_first = RowOpenings {
        row: row_first,
        per_tape: vec![per_first],
        is_first: open_u64(1, row_first),
        is_last: open_u64(0, row_first),
        input_mv: open_u64(0, row_first),
    };
    let view_first = RowView::from_openings(&q_first);
    let c_first = compose_row_from_openings(&view_first, &a)
        + compose_boundary_from_openings(&view_first, &a);
    assert_eq!(c_first, f1(0), "first-row openings should satisfy AIR (C=0)");

    // --- Last row: enforce head - out_off = 0; head-update masked by is_last=1.
    let row_last = 7usize;
    let per_last = PerTapeOpen {
        mv: open_u64(0, row_last),
        next_mv: open_u64(0, row_last + 1),
        write_flag: open_u64(0, row_last),
        write_sym: open_u64(0, row_last),
        head: open_u64(9, row_last),
        next_head: open_u64(123, row_last + 1), // masked by is_last
        win_len: open_u64(16, row_last),
        in_off: open_u64(0, row_last),
        out_off: open_u64(9, row_last), // 9 - 9 = 0
    };
    let q_last = RowOpenings {
        row: row_last,
        per_tape: vec![per_last],
        is_first: open_u64(0, row_last),
        is_last: open_u64(1, row_last),
        input_mv: open_u64(0, row_last),
    };
    let view_last = RowView::from_openings(&q_last);
    let c_last =
        compose_row_from_openings(&view_last, &a) + compose_boundary_from_openings(&view_last, &a);
    assert_eq!(c_last, f1(0), "last-row openings should satisfy AIR (C=0)");
}
