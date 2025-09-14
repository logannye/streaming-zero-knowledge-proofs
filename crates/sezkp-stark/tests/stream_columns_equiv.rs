#![allow(clippy::unwrap_used)]
#![allow(unused_mut)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::v1::{
    columns::TraceColumns,
    merkle::{hash_field_leaves_labeled, ColumnCommit},
    openings::OnDemandOpenings,
    params,
};

/// Build a tiny valid block set with tau=1, simple head walk and occasional writes.
fn demo_blocks(t: usize) -> Vec<BlockSummary> {
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

    vec![BlockSummary {
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
    }]
}

#[test]
fn streamed_column_roots_equal_in_memory() {
    let blocks = demo_blocks(32);

    // Streaming roots via on-demand builder
    let mut odo = OnDemandOpenings::new(&blocks, params::COL_CHUNK_LOG2);
    let streamed_roots = odo.build_roots();

    // In-memory baseline columns
    let tc = TraceColumns::build(&blocks).expect("trace columns");
    let mut cols: Vec<(&[sezkp_stark::v1::field::F1], String)> = Vec::new();
    cols.push((&tc.input_mv, "input_mv".into()));
    cols.push((&tc.is_first, "is_first".into()));
    cols.push((&tc.is_last, "is_last".into()));
    for (i, c) in tc.mv.iter().enumerate() {
        cols.push((c, format!("mv_{i}")));
    }
    for (i, c) in tc.write_flag.iter().enumerate() {
        cols.push((c, format!("wflag_{i}")));
    }
    for (i, c) in tc.write_sym.iter().enumerate() {
        cols.push((c, format!("wsym_{i}")));
    }
    for (i, c) in tc.head.iter().enumerate() {
        cols.push((c, format!("head_{i}")));
    }
    for (i, c) in tc.win_len.iter().enumerate() {
        cols.push((c, format!("winlen_{i}")));
    }
    for (i, c) in tc.in_off.iter().enumerate() {
        cols.push((c, format!("in_off_{i}")));
    }
    for (i, c) in tc.out_off.iter().enumerate() {
        cols.push((c, format!("out_off_{i}")));
    }

    // Compute roots in-memory and compare one-by-one
    assert_eq!(streamed_roots.len(), cols.len());
    for (i, (col, label)) in cols.iter().enumerate() {
        let leaves8: Vec<[u8; 8]> = col.iter().map(|x| x.to_le_bytes()).collect();
        let leaf_hashes = hash_field_leaves_labeled(&leaves8, label);
        let commit = ColumnCommit::from_hashed_leaves(&leaf_hashes, params::COL_CHUNK_LOG2);
        assert_eq!(
            streamed_roots[i].label, *label,
            "label mismatch at index {i}"
        );
        assert_eq!(
            streamed_roots[i].root,
            commit.root(),
            "root mismatch at column {} ({label})",
            i
        );
    }
}
