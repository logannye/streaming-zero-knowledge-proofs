#![allow(clippy::unwrap_used)]
#![allow(unused_imports)]
#![allow(unused_mut)]

use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_crypto::{Blake3Transcript, Transcript};
use sezkp_stark::{
    v1::{
        air::{compose_boundary, compose_row, Alphas},
        columns::TraceColumns,
        field::F1,
        fri_stream::StreamingLayerBuilder,
        lde::deep_coset_lde_stream,
        merkle::{hash_field_leaves, MerkleTree},
        openings::OnDemandOpenings,
        params,
        verify::verify_v1,
    },
    ProvingBackend, StarkV1,
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
fn fri_roots_streaming_match_incore_baseline_and_verify() {
    let blocks = demo_blocks(64);

    // Column roots via streaming builder to bind transcript consistently.
    let mut odo = OnDemandOpenings::new(&blocks, params::COL_CHUNK_LOG2);
    let col_roots = odo.build_roots();

    // Build columns for AIR only
    let tc = TraceColumns::build(&blocks).expect("trace cols");

    // Transcript prelude (exactly like the prover)
    let mut tr = Blake3Transcript::new(params::DS_V1_DOMAIN);
    let manifest_root = [7u8; 32];
    tr.absorb("manifest_root", &manifest_root);
    tr.absorb_u64("n", tc.n as u64);
    tr.absorb_u64("tau", tc.tau as u64);
    tr.absorb_u64(params::DS_N_COLS, col_roots.len() as u64);
    for r in &col_roots {
        tr.absorb(params::DS_COL_ROOT, &r.root);
    }

    // AIR alphas
    let a = params::derive_alphas(&mut tr);
    let alphas = Alphas {
        bool_flag: a[0],
        mv_domain: a[1],
        head_update: a[2],
        head_bits_bool: a[3],
        head_reconstruct: a[4],
        slack_bits_bool: a[5],
        slack_reconstruct: a[6],
        sym_bits_bool: a[7],
        sym_reconstruct: a[0],
        boundary_first: a[2],
        boundary_last: a[2],
    };

    // Domain sizes and OOD z
    let blow = params::BLOWUP;
    let base_log2 = tc.n.trailing_zeros() as usize;
    let blow_log2 = blow.trailing_zeros() as usize;
    let lde_k_log2 = base_log2 + blow_log2;
    let lde_n = 1usize << lde_k_log2;
    let shift = F1::from_u64(3);

    let mut z = params::derive_ood_point(&mut tr);
    let one = F1::from_u64(1);
    let shift_inv = shift.inv();
    let is_on_coset = |zz: F1| {
        let mut t = zz * shift_inv;
        for _ in 0..lde_k_log2 {
            t = t * t;
        }
        t == one
    };
    while is_on_coset(z) {
        z = z + one;
    }

    // ---- Streaming layer-0 root (A3/A4 path)
    let mut l0_builder = StreamingLayerBuilder::new(lde_n);
    let mut lde_stream_vals_as_f1 = Vec::<F1>::with_capacity(lde_n); // for folds

    let mut base_eval = |i: usize| -> [u8; 8] {
        let v = compose_row(&tc, i, &alphas) + compose_boundary(&tc, i, &alphas);
        v.to_le_bytes()
    };
    deep_coset_lde_stream(
        &mut base_eval,
        tc.n,
        blow_log2,
        shift,
        z,
        12,
        |chunk_le| {
            l0_builder.absorb_leaves(chunk_le);
            for le in chunk_le {
                lde_stream_vals_as_f1.push(F1::from_u64(u64::from_le_bytes(*le)));
            }
        },
    );
    let root0_stream = l0_builder.finalize();

    // ---- In-core baseline layer-0 root (interpolate + eval + DEEP)
    use sezkp_ffts::{coset::evaluate_on_coset_pow2, ntt::interpolate_from_evals};
    let mut base_vals = Vec::with_capacity(tc.n);
    for i in 0..tc.n {
        base_vals.push(compose_row(&tc, i, &alphas) + compose_boundary(&tc, i, &alphas));
    }
    let coeffs = interpolate_from_evals(&base_vals);
    let mut lde_vals = evaluate_on_coset_pow2(&coeffs, lde_k_log2, shift);
    // DEEP divide
    let w = sezkp_ffts::goldilocks_primitive_root_2exp(lde_k_log2 as u32);
    let mut w_pow = one;
    for i in 0..lde_n {
        let x = shift * w_pow;
        lde_vals[i] = lde_vals[i] * (x - z).inv();
        w_pow *= w;
    }
    let root0_mem = {
        let leaves = hash_field_leaves(&lde_vals.iter().map(|v| v.to_le_bytes()).collect::<Vec<_>>());
        let mt = MerkleTree::from_leaves(&leaves);
        mt.root()
    };

    assert_eq!(root0_stream, root0_mem, "layer-0 root mismatch");

    // ---- Derive betas and fold several layers; compare roots (sanity)
    let n_folds = lde_k_log2;
    let betas = params::derive_betas_for_fri(&mut tr, n_folds);

    // Fold 1 (stream vector vs baseline vector): they should match
    if lde_n > 1 {
        let half = lde_n / 2;
        let beta = betas[0];
        let mut fold_stream_vec = vec![F1::from_u64(0); half];
        for i in 0..half {
            fold_stream_vec[i] =
                lde_stream_vals_as_f1[i] + beta * lde_stream_vals_as_f1[i + half];
        }
        let mut fold_mem_vec = vec![F1::from_u64(0); half];
        for i in 0..half {
            fold_mem_vec[i] = lde_vals[i] + beta * lde_vals[i + half];
        }

        // Compare layer-1 roots
        let r_stream = {
            let leaves = hash_field_leaves(&fold_stream_vec.iter().map(|v| v.to_le_bytes()).collect::<Vec<_>>());
            MerkleTree::from_leaves(&leaves).root()
        };
        let r_mem = {
            let leaves = hash_field_leaves(&fold_mem_vec.iter().map(|v| v.to_le_bytes()).collect::<Vec<_>>());
            MerkleTree::from_leaves(&leaves).root()
        };
        assert_eq!(r_stream, r_mem, "layer-1 root mismatch");
    }

    // ---- Full proof via streaming entrypoint must verify
    let art = StarkV1::prove_streaming(&blocks, manifest_root).expect("prove v1");
    StarkV1::verify(&art, &blocks, manifest_root).expect("verify v1");
}
