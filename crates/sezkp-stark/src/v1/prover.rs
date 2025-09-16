//! Prover for STARK v1 (column commitments + FRI + row openings).
//!
//! A5: add **zero-knowledge masking** to the streamed composition. We derive
//! low-degree mask polynomials from the transcript (post column roots, pre
//! queries) and add `R(x)` to the base-domain composition before streaming
//! into the LDE/DEEP engine. The verifier mirrors the transcript draws to
//! remain aligned; the openings-only AIR check remains unchanged.
//!
//! This file also implements **1A** of the fully-streaming FRI queries: the
//! layer-0 Merkle paths for FRI are extracted directly from the streamed
//! layer-0 codeword using `fri_stream::merkle_path_from_le_chunker`, without
//! materializing a `MerkleTree` for layer-0.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::Result;
use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};

use crate::v1::{
    air::{compose_boundary, compose_row, Alphas},
    columns::TraceColumns,
    field::F1,
    fri_stream::{merkle_path_from_le_chunker, StreamingLayerBuilder},
    lde::deep_coset_lde_stream,
    masking::{derive_mask_coeffs, eval_masks_sum_at, DEFAULT_MASK_DEG, DEFAULT_N_MASKS},
    merkle::{hash_field_leaves, MerkleTree},
    openings::OnDemandOpenings,
    params,
    proof::{FriRoots, PerTapeOpen, ProofV1, RowOpenings},
};

use sezkp_ffts::goldilocks_primitive_root_2exp;

#[inline]
fn to_le_vec(vals: &[F1]) -> Vec<[u8; 8]> {
    vals.iter().map(|v| v.to_le_bytes()).collect()
}

#[inline]
fn next_wrap(idx: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else if idx + 1 < len {
        idx + 1
    } else {
        0
    }
}

/// Produce a v1 proof (streaming layer-0 root + on-demand column openings + ZK masks).
pub fn prove_v1(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofV1> {
    // 1) Columnar view for AIR composition only.
    // We do NOT commit this view directly; column commitments are streamed.
    let tc = TraceColumns::build(blocks)?;

    // Transcript prelude.
    let mut tr = Blake3Transcript::new(params::DS_V1_DOMAIN);
    tr.absorb("manifest_root", &manifest_root);
    tr.absorb_u64("n", tc.n as u64);
    tr.absorb_u64("tau", tc.tau as u64);

    /* ------------------- Column commitments (streamed roots) ---------------- */

    // Streamed, chunked column commitments; returns outer roots per label.
    let mut odo = OnDemandOpenings::new(blocks, params::COL_CHUNK_LOG2);
    let col_roots = odo.build_roots();

    tr.absorb_u64(params::DS_N_COLS, col_roots.len() as u64);
    for r in &col_roots {
        tr.absorb(params::DS_COL_ROOT, &r.root);
    }

    /* ------------------------- Derive AIR alphas ---------------------------- */

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
        sym_reconstruct: a[0], // reuse some randomness for placeholders
        boundary_first: a[2],
        boundary_last: a[2],
    };

    /* -------------------- Draw ZK mask polynomials (A5) --------------------- */

    // Mask polynomials depend only on transcript state (not the witness).
    let mask_coeffs = derive_mask_coeffs(&mut tr, DEFAULT_MASK_DEG, DEFAULT_N_MASKS);

    /* ------------------- Streaming LDE + DEEP (layer-0) --------------------- */

    // Domain sizes.
    let blow = params::BLOWUP;
    debug_assert!(blow.is_power_of_two(), "BLOWUP must be a power of two");
    let base_log2 = tc.n.trailing_zeros() as usize;
    let blow_log2 = blow.trailing_zeros() as usize;
    let lde_k_log2 = base_log2 + blow_log2;
    let lde_n = 1usize << lde_k_log2;

    // Base-domain primitive root for x = ω^i (for mask evaluation at ω^i).
    let w_base = goldilocks_primitive_root_2exp(base_log2 as u32);

    // Coset shift and OOD point (ensure z ∉ {shift · ω^i}).
    let shift = F1::from_u64(3);
    let mut z = params::derive_ood_point(&mut tr);
    {
        let one = F1::from_u64(1);
        let shift_inv = shift.inv();
        // z lies on the coset iff (z/shift)^(2^k) == 1
        let is_on_coset = |zz: F1| {
            let mut t = zz * shift_inv; // z/shift
            for _ in 0..lde_k_log2 {
                t = t * t;
            }
            t == one
        };
        while is_on_coset(z) {
            z = z + one; // deterministic nudge off the coset
        }
    }

    // Keep layer-0 root streaming-only, but also collect values for higher layers.
    let mut lde_vals: Vec<F1> = Vec::with_capacity(lde_n);
    let mut l0_builder = StreamingLayerBuilder::new(lde_n);

    // Base-domain composition with ZK mask R(ω^i), streamed into LDE/DEEP engine.
    let mut last_i = 0usize;
    let mut x_pow = F1::from_u64(1); // ω^0
    let mut base_eval = |i: usize| -> [u8; 8] {
        // Maintain ω^i incrementally in-order; if we ever go backwards, restart.
        if i < last_i {
            last_i = 0;
            x_pow = F1::from_u64(1);
        }
        for _ in last_i..i {
            x_pow = x_pow * w_base;
        }
        last_i = i;

        let comp = compose_row(&tc, i, &alphas) + compose_boundary(&tc, i, &alphas);
        let mask = eval_masks_sum_at(&mask_coeffs, x_pow);
        (comp + mask).to_le_bytes()
    };

    // Emit layer-0 values in chunks (elements), keeping memory flat.
    let out_chunk_log2 = 12usize; // 4096 elems/chunk
    deep_coset_lde_stream(
        &mut base_eval,
        tc.n,
        blow_log2,
        shift,
        z,
        out_chunk_log2,
        |chunk_le| {
            // Contribute to streaming layer-0 Merkle root…
            l0_builder.absorb_leaves(chunk_le);
            // …and (for now) also retain values for in-memory upper layers.
            for le in chunk_le {
                let v = F1::from_u64(u64::from_le_bytes(*le));
                lde_vals.push(v);
            }
        },
    );
    debug_assert_eq!(lde_vals.len(), lde_n, "LDE stream size mismatch");

    /* ------------------- FRI: commit roots with O(n/2) scratch -------------- */

    // Bind layer-0 root BEFORE sampling β.
    let mut fri_roots_vec = Vec::<[u8; 32]>::with_capacity(lde_k_log2 + 1);
    {
        let root0 = l0_builder.finalize();
        tr.absorb(params::DS_FRI_LAYER_ROOT, &root0);
        fri_roots_vec.push(root0);
    }

    // Number of folds and betas (after binding root0).
    let mut tmp = lde_n;
    let mut n_folds = 0usize;
    while tmp > 1 {
        tmp >>= 1;
        n_folds += 1;
    }
    let betas = params::derive_betas_for_fri(&mut tr, n_folds);

    // Fold in-place into `scratch`, committing each layer root.
    let mut cur_len = lde_n;
    let mut scratch = vec![F1::from_u64(0); lde_n / 2];

    if n_folds > 0 {
        // First fold from layer-0 → layer-1
        let beta0 = betas[0];
        let next_len = cur_len / 2;
        for i in 0..next_len {
            scratch[i] = lde_vals[i] + beta0 * lde_vals[i + next_len];
        }
        cur_len = next_len;

        // Root for layer 1
        {
            let leaves = hash_field_leaves(&to_le_vec(&scratch[..cur_len]));
            let mt = MerkleTree::from_leaves(&leaves);
            let root1 = mt.root();
            tr.absorb(params::DS_FRI_LAYER_ROOT, &root1);
            fri_roots_vec.push(root1);
        }

        // Remaining folds (layer r → r+1)
        for r in 1..n_folds {
            let half = cur_len / 2;
            let beta = betas[r];
            for i in 0..half {
                let a = scratch[i];
                let b = scratch[i + half];
                scratch[i] = a + beta * b;
            }
            cur_len = half;

            let leaves = hash_field_leaves(&to_le_vec(&scratch[..cur_len]));
            let mt = MerkleTree::from_leaves(&leaves);
            let root = mt.root();
            tr.absorb(params::DS_FRI_LAYER_ROOT, &root);
            fri_roots_vec.push(root);
        }
    }

    // Final FRI value y* (the single element of the last layer).
    let final_val = if n_folds == 0 { lde_vals[0] } else { scratch[0] };
    let fri_final_value_le = final_val.to_le_bytes();

    /* ------------------------ AIR query row openings ------------------------ */

    // Sample base-row indices AFTER FRI roots were absorbed (keeps schedule aligned).
    let rows = params::derive_queries(&mut tr, tc.n, params::NUM_QUERIES);

    // On-demand openings against streamed column commitments.
    let mut query_openings = Vec::with_capacity(rows.len());
    for row in rows {
        // Scalars
        let input_mv_open = odo.open("input_mv", row);
        let is_first_open = odo.open("is_first", row);
        let is_last_open = odo.open("is_last", row);

        // Per-tape (also open next-row values used by head-update).
        let ip1 = next_wrap(row, tc.n);
        let mut per_tape = Vec::with_capacity(tc.tau);
        for r in 0..tc.tau {
            let mv_o = odo.open(&format!("mv_{r}"), row);
            let nmv_o = odo.open(&format!("mv_{r}"), ip1);
            let wflag_o = odo.open(&format!("wflag_{r}"), row);
            let wsym_o = odo.open(&format!("wsym_{r}"), row);
            let head_o = odo.open(&format!("head_{r}"), row);
            let nhead_o = odo.open(&format!("head_{r}"), ip1);
            let winlen_o = odo.open(&format!("winlen_{r}"), row);
            let inoff_o = odo.open(&format!("in_off_{r}"), row);
            let outoff_o = odo.open(&format!("out_off_{r}"), row);

            per_tape.push(PerTapeOpen {
                mv: mv_o,
                next_mv: nmv_o,
                write_flag: wflag_o,
                write_sym: wsym_o,
                head: head_o,
                next_head: nhead_o,
                win_len: winlen_o,
                in_off: inoff_o,
                out_off: outoff_o,
            });
        }

        query_openings.push(RowOpenings {
            row,
            per_tape,
            is_first: is_first_open,
            is_last: is_last_open,
            input_mv: input_mv_open,
        });
    }

    /* ------------------- FRI queries (layer-0 streaming) -------------------- */

    // After roots are bound into the transcript, derive FRI query indices.
    let fri_rows = params::derive_queries(&mut tr, lde_n, params::NUM_QUERIES);

    // Number of layers = roots.len(); emit exactly (n_layers - 1) pairs per query.
    let n_layers = fri_roots_vec.len();
    let mut fri_queries = Vec::with_capacity(fri_rows.len());

    // Seed queries with the right-sized positions list.
    for _ in 0..fri_rows.len() {
        fri_queries.push(crate::v1::proof::FriQuery {
            positions: vec![0; n_layers],
            pairs: Vec::with_capacity(n_layers.saturating_sub(1)),
        });
    }

    // --- Layer 0: open **streaming** against the layer-0 codeword.
    {
        let n0 = lde_n;
        let half0 = n0 / 2;

        for (qi, &idx0) in fri_rows.iter().enumerate() {
            let j0 = idx0 ^ half0;

            // Open idx0 via a fresh, stateless chunker.
            let (vi0_le, pi0_sibs) = merkle_path_from_le_chunker(
                n0,
                |sink: &mut dyn FnMut(&[[u8; 8]])| {
                    // Fresh local state per run.
                    let mut last_i_q = 0usize;
                    let mut x_pow_q = F1::from_u64(1);
                    let mut base_eval_q = |i: usize| -> [u8; 8] {
                        if i < last_i_q {
                            last_i_q = 0;
                            x_pow_q = F1::from_u64(1);
                        }
                        for _ in last_i_q..i {
                            x_pow_q = x_pow_q * w_base;
                        }
                        last_i_q = i;

                        let comp =
                            compose_row(&tc, i, &alphas) + compose_boundary(&tc, i, &alphas);
                        let mask = eval_masks_sum_at(&mask_coeffs, x_pow_q);
                        (comp + mask).to_le_bytes()
                    };

                    deep_coset_lde_stream(
                        &mut base_eval_q,
                        tc.n,
                        blow_log2,
                        shift,
                        z,
                        out_chunk_log2,
                        |chunk| sink(chunk),
                    );
                },
                idx0,
            );

            // Open j0 via another fresh, stateless chunker.
            let (vj0_le, pj0_sibs) = merkle_path_from_le_chunker(
                n0,
                |sink: &mut dyn FnMut(&[[u8; 8]])| {
                    let mut last_i_q = 0usize;
                    let mut x_pow_q = F1::from_u64(1);
                    let mut base_eval_q = |i: usize| -> [u8; 8] {
                        if i < last_i_q {
                            last_i_q = 0;
                            x_pow_q = F1::from_u64(1);
                        }
                        for _ in last_i_q..i {
                            x_pow_q = x_pow_q * w_base;
                        }
                        last_i_q = i;

                        let comp =
                            compose_row(&tc, i, &alphas) + compose_boundary(&tc, i, &alphas);
                        let mask = eval_masks_sum_at(&mask_coeffs, x_pow_q);
                        (comp + mask).to_le_bytes()
                    };

                    deep_coset_lde_stream(
                        &mut base_eval_q,
                        tc.n,
                        blow_log2,
                        shift,
                        z,
                        out_chunk_log2,
                        |chunk| sink(chunk),
                    );
                },
                j0,
            );

            fri_queries[qi].positions[0] = idx0;
            if n_layers > 1 {
                fri_queries[qi].positions[1] = idx0 % (lde_n / 2);
            }
            fri_queries[qi]
                .pairs
                .push((vi0_le, pi0_sibs, vj0_le, pj0_sibs));
        }
    }

    // --- Layers 1..(n_layers-2): open on current layer, then fold.
    if n_layers > 1 {
        // Compute layer 1 values (from layer 0) once, across halves.
        let mut cur_len_q = lde_n / 2;
        {
            let beta0 = betas[0];
            for i in 0..cur_len_q {
                scratch[i] = lde_vals[i] + beta0 * lde_vals[i + cur_len_q];
            }
        }

        // For each intermediate layer r (1..=n_layers-2):
        for r in 1..=n_layers - 2 {
            let half = cur_len_q / 2;

            // Open on layer r (currently in scratch[..cur_len_q]).
            let leaves_r = hash_field_leaves(&to_le_vec(&scratch[..cur_len_q]));
            let mt_r = MerkleTree::from_leaves(&leaves_r);

            for qi in 0..fri_rows.len() {
                let idx_r = fri_queries[qi].positions[r];
                let j_r = idx_r ^ half;

                let pi_r = mt_r.open(idx_r);
                let pj_r = mt_r.open(j_r);
                let vi_r_le = scratch[idx_r].to_le_bytes();
                let vj_r_le = scratch[j_r].to_le_bytes();

                // Record pair for layer r.
                fri_queries[qi].pairs.push((vi_r_le, pi_r.sibs, vj_r_le, pj_r.sibs));

                // Propagate next index.
                if r + 1 <= n_layers - 2 {
                    fri_queries[qi].positions[r + 1] = idx_r % half;
                } else {
                    fri_queries[qi].positions[n_layers - 1] = idx_r % half;
                }
            }

            // Fold r → r+1
            if r < n_layers - 1 {
                let beta = betas[r];
                for i in 0..half {
                    let a = scratch[i];
                    let b = scratch[i + half];
                    scratch[i] = a + beta * b;
                }
                cur_len_q = half;
            }
        }
    }

    Ok(ProofV1 {
        manifest_root,
        tau: tc.tau,
        domain_n: lde_n,
        col_roots,
        queries: query_openings,
        fri_roots: FriRoots { roots: fri_roots_vec },
        fri_queries,
        fri_final_value_le,
    })
}
