#![allow(clippy::unwrap_used)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_stark::v1::{
    merkle::verify_chunked_open,
    openings::OnDemandOpenings,
    params,
};

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
fn on_demand_openings_verify_for_many_rows_and_columns() {
    let blocks = demo_blocks(64);

    // Build streaming roots
    let mut odo = OnDemandOpenings::new(&blocks, params::COL_CHUNK_LOG2);
    let roots = odo.build_roots();

    // Build a label->root map for quick verify
    let root_map: std::collections::HashMap<_, _> =
        roots.iter().map(|r| (r.label.clone(), r.root)).collect();

    // Labels are in the streaming order used by the builder
    let tau = 1usize;
    let mut labels = vec!["input_mv".to_string(), "is_first".into(), "is_last".into()];
    for r in 0..tau {
        labels.push(format!("mv_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("wflag_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("wsym_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("head_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("winlen_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("in_off_{r}"));
    }
    for r in 0..tau {
        labels.push(format!("out_off_{r}"));
    }

    // Deterministic pseudo-random sampler
    let mut x = 0x9e3779b97f4a7c15u64;
    let mut rnd = || {
        x ^= x << 7;
        x ^= x >> 9;
        (x % 64) as usize
    };

    // Test 32 random (row, col) pairs
    for _ in 0..32 {
        let row = rnd();
        let col_i = rnd() % labels.len();
        let label = &labels[col_i];

        let open = odo.open(label, row);

        let ok = verify_chunked_open(
            *root_map.get(label).expect("root"),
            label,
            open.value_le,
            open.chunk_root,
            open.index_in_chunk,
            &open.path_in_chunk,
            open.chunk_index,
            &open.path_to_chunk,
        );
        assert!(ok, "verify_chunked_open failed for {label} @ row {row}");
    }
}
