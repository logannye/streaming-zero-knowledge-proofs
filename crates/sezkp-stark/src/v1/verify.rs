//! Verifier for STARK v1 (row openings + AIR + FRI).
//!
//! A5 alignment: the prover draws ZK masks after alphas and before queries.
//! We mirror the same transcript draws here to keep challenge order aligned.
//! The openings-only AIR check remains mask-free (constraints must be 0).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_imports)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{bail, ensure, Result};
use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};
use std::collections::HashMap;

use crate::v1::{
    air::{compose_boundary_from_openings, compose_row_from_openings, Alphas, RowView},
    field::F1,
    fri::fri_verify,
    masking::{derive_mask_coeffs, DEFAULT_MASK_DEG, DEFAULT_N_MASKS},
    merkle::verify_chunked_open,
    params,
    proof::ProofV1,
};

fn verify_opening(
    root_map: &HashMap<String, [u8; 32]>,
    label: &str,
    open: &crate::v1::proof::Opening,
) -> Result<()> {
    let root = root_map
        .get(label)
        .ok_or_else(|| anyhow::anyhow!("missing col root for {label}"))?;
    let ok = verify_chunked_open(
        *root,
        label,
        open.value_le,
        open.chunk_root,
        open.index_in_chunk,
        &open.path_in_chunk,
        open.chunk_index,
        &open.path_to_chunk,
    );
    ensure!(
        ok,
        "chunked merkle path failed for column {label} @ {}",
        open.index
    );
    Ok(())
}

pub fn verify_v1(proof: &ProofV1, blocks: &[BlockSummary]) -> Result<()> {
    // ---- Shape only (no full trace rebuild) ---------------------------------
    let blow = params::BLOWUP;
    ensure!(blow.is_power_of_two(), "BLOWUP must be a power of two");
    ensure!(
        proof.domain_n % blow == 0,
        "FRI domain_n not multiple of blowup"
    );
    let n = proof.domain_n / blow;
    ensure!(n.is_power_of_two(), "trace length n must be a power of two");
    let tau = proof.tau;

    if let Some(b0) = blocks.first() {
        ensure!(
            b0.windows.len() == tau,
            "tau mismatch vs. block windows: got {}, expected {}",
            tau,
            b0.windows.len()
        );
    }

    // ---- Transcript prelude + bind column roots -----------------------------
    let mut tr = Blake3Transcript::new(params::DS_V1_DOMAIN);
    tr.absorb("manifest_root", &proof.manifest_root);
    tr.absorb_u64("n", n as u64);
    tr.absorb_u64("tau", tau as u64);
    tr.absorb_u64(params::DS_N_COLS, proof.col_roots.len() as u64);
    for cr in &proof.col_roots {
        tr.absorb(params::DS_COL_ROOT, &cr.root);
    }

    // ---- Alphas --------------------------------------------------------------
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

    // ---- ZK mask draws (alignment only; not used in openings check) ---------
    let _mask_coeffs = derive_mask_coeffs(&mut tr, DEFAULT_MASK_DEG, DEFAULT_N_MASKS);

    // ---- Force transcript alignment up to AIR row sampling ------------------
    // Prover consumed an OOD challenge before binding FRI roots & betas.
    let _z_sync = params::derive_ood_point(&mut tr);

    // Mirror: absorb FRI roots and draw betas before deriving AIR row queries.
    let n_layers = proof.fri_roots.roots.len();
    let mut tr_rows = tr.clone();
    if n_layers > 0 {
        tr_rows.absorb(params::DS_FRI_LAYER_ROOT, &proof.fri_roots.roots[0]);
        let _ = params::derive_betas_for_fri(&mut tr_rows, n_layers.saturating_sub(1));
        for r in 1..n_layers {
            tr_rows.absorb(params::DS_FRI_LAYER_ROOT, &proof.fri_roots.roots[r]);
        }
    }
    // Derive the AIR query rows from the transcript and enforce they match.
    let expected_rows = params::derive_queries(&mut tr_rows, n, params::NUM_QUERIES);
    ensure!(
        expected_rows.len() == proof.queries.len(),
        "AIR query count mismatch (expected {}, got {})",
        expected_rows.len(),
        proof.queries.len()
    );
    for (i, q) in proof.queries.iter().enumerate() {
        ensure!(
            q.row == expected_rows[i],
            "AIR query row mismatch at position {}: got {}, expected {}",
            i,
            q.row,
            expected_rows[i]
        );
    }

    // ---- Verify openings + AIR directly from openings -----------------------
    let root_map: HashMap<_, _> = proof
        .col_roots
        .iter()
        .map(|c| (c.label.clone(), c.root))
        .collect();

    for q in &proof.queries {
        // Scalars
        verify_opening(&root_map, "input_mv", &q.input_mv)?;
        verify_opening(&root_map, "is_first", &q.is_first)?;
        verify_opening(&root_map, "is_last", &q.is_last)?;

        // Per-tape
        for (r, t) in q.per_tape.iter().enumerate() {
            verify_opening(&root_map, &format!("mv_{r}"), &t.mv)?;
            verify_opening(&root_map, &format!("mv_{r}"), &t.next_mv)?;
            verify_opening(&root_map, &format!("wflag_{r}"), &t.write_flag)?;
            verify_opening(&root_map, &format!("wsym_{r}"), &t.write_sym)?;
            verify_opening(&root_map, &format!("head_{r}"), &t.head)?;
            verify_opening(&root_map, &format!("head_{r}"), &t.next_head)?;
            verify_opening(&root_map, &format!("winlen_{r}"), &t.win_len)?;
            verify_opening(&root_map, &format!("in_off_{r}"), &t.in_off)?;
            verify_opening(&root_map, &format!("out_off_{r}"), &t.out_off)?;
        }

        let rv = RowView::from_openings(q);
        let c =
            compose_row_from_openings(&rv, &alphas) + compose_boundary_from_openings(&rv, &alphas);
        if c != F1::from_u64(0) {
            bail!("AIR composition non-zero at row {}", q.row);
        }
    }

    // ---- FRI checks (on a transcript aligned to the prover for betas) -------
    let mut tr_fri = tr;
    crate::v1::fri::fri_verify(
        &mut tr_fri,
        &proof.fri_roots.roots,
        &proof.fri_queries,
        proof.fri_final_value_le,
    )?;

    Ok(())
}
