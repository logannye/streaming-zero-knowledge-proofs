//! Minimal FRI (prototype): layer commits and per-row openings.
//!
//! Folding rule (canonical orientation):
//!   For layer vector y of length N with half = N/2,
//!     y'[i] = y[i] + β · y[i + half]   for i in [0, half)
//! We Merkle-commit each layer and absorb roots into the transcript.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{ensure, Result};
use sezkp_crypto::Transcript;

use crate::v1::{
    field::F1,
    merkle::{hash_field_leaves, MerkleProof, MerkleTree},
    params,
    proof::FriQuery,
};

#[inline]
fn to_le_vec(vals: &[F1]) -> Vec<[u8; 8]> {
    vals.iter().map(|v| v.to_le_bytes()).collect()
}

/// (Kept for compatibility in tests) Commit to FRI layers from a full layer-0 vector.
///
/// Transcript order matches the main prover:
/// 1) Bind layer-0 root
/// 2) Derive betas
/// 3) Fold and bind subsequent layer roots
#[must_use]
pub fn fri_commit<T: Transcript>(
    tr: &mut T,
    a0: Vec<F1>,
) -> (Vec<[u8; 32]>, Vec<Vec<F1>>, Vec<F1>) {
    assert!(a0.len().is_power_of_two(), "FRI layer0 len must be pow2");

    // Keep all layers for test/compat use.
    let mut layers = Vec::<Vec<F1>>::new();
    layers.push(a0);

    // Layer 0 root, absorb before sampling betas.
    let root0 = {
        let leaves0 = hash_field_leaves(&to_le_vec(&layers[0]));
        let mt0 = MerkleTree::from_leaves(&leaves0);
        let r0 = mt0.root();
        tr.absorb(params::DS_FRI_LAYER_ROOT, &r0);
        r0
    };

    // Number of folds = log2(len)
    let mut tmp_len = layers[0].len();
    let mut n_folds = 0usize;
    while tmp_len > 1 {
        tmp_len >>= 1;
        n_folds += 1;
    }

    // Derive betas AFTER binding the layer-0 root (mirrors prover & verifier).
    let betas = params::derive_betas_for_fri(tr, n_folds);

    // Produce folded layers y' = y_lo + beta * y_hi
    for r in 0..n_folds {
        let cur = layers.last().expect("layer present");
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        let beta = betas[r];
        for i in 0..half {
            next.push(cur[i] + beta * cur[i + half]);
        }
        layers.push(next);
    }

    // Commit each layer root (layer 0 already bound).
    let mut roots = Vec::<[u8; 32]>::with_capacity(layers.len());
    roots.push(root0);
    for layer in layers.iter().skip(1) {
        let leaves = hash_field_leaves(&to_le_vec(layer));
        let mt = MerkleTree::from_leaves(&leaves);
        let root = mt.root();
        tr.absorb(params::DS_FRI_LAYER_ROOT, &root);
        roots.push(root);
    }

    (roots, layers, betas)
}

/// (Kept for compatibility in tests) Open a FRI query across all layers.
#[must_use]
pub fn fri_open_query(layers: &[Vec<F1>], _roots: &[[u8; 32]], mut idx: usize) -> FriQuery {
    let mut positions = Vec::<usize>::with_capacity(layers.len());
    let mut pairs =
        Vec::<([u8; 8], Vec<[u8; 32]>, [u8; 8], Vec<[u8; 32]>)>::with_capacity(
            layers.len().saturating_sub(1),
        );

    for layer in layers {
        positions.push(idx);
        if layer.len() == 1 {
            break;
        }

        let half = layer.len() / 2;
        let j = idx ^ half; // sibling position

        let leaves = hash_field_leaves(&to_le_vec(layer));
        let mt = MerkleTree::from_leaves(&leaves);
        let pi = mt.open(idx);
        let pj = mt.open(j);

        let vi_le = layer[idx].to_le_bytes();
        let vj_le = layer[j].to_le_bytes();

        pairs.push((vi_le, pi.sibs, vj_le, pj.sibs));
        idx %= half; // index into the next layer
    }

    FriQuery { positions, pairs }
}

/// Verify FRI queries end-to-end against provided roots and final value.
pub fn fri_verify<T: Transcript>(
    tr: &mut T,
    roots: &[[u8; 32]],
    queries: &[FriQuery],
    final_value_le: [u8; 8],
) -> Result<()> {
    ensure!(!roots.is_empty(), "no FRI roots");
    let n_layers = roots.len();

    // Mirror the prover: bind the layer-0 root before sampling betas.
    tr.absorb(params::DS_FRI_LAYER_ROOT, &roots[0]);

    // Re-derive betas (number of folds = roots.len() - 1).
    let betas = params::derive_betas_for_fri(tr, n_layers.saturating_sub(1));

    // Last-layer root must equal hash(final_value).
    {
        let last = roots[n_layers - 1];
        let final_hash = hash_field_leaves(&[final_value_le])[0];
        ensure!(last == final_hash, "final FRI value mismatch with last root");
    }

    for q in queries {
        ensure!(q.positions.len() == n_layers, "positions length mismatch");
        ensure!(q.pairs.len() == n_layers.saturating_sub(1), "pairs length mismatch");

        // At layer ℓ, the domain size is N_ℓ = 2^(n_layers-1-ℓ), half = N_ℓ/2.
        let mut idx = q.positions[0];
        let mut layer_len = 1usize << (n_layers - 1);

        for l in 0..(n_layers - 1) {
            let half = layer_len / 2;
            let j = idx ^ half;

            let (vi_le, path_i, vj_le, path_j) = &q.pairs[l];

            // Verify the two Merkle paths against the root of layer l.
            let leaf_i = hash_field_leaves(&[*vi_le])[0];
            let leaf_j = hash_field_leaves(&[*vj_le])[0];

            let ok_i = MerkleTree::verify(
                roots[l],
                leaf_i,
                idx,
                &MerkleProof {
                    sibs: path_i.clone(),
                    index: idx,
                },
            );
            let ok_j = MerkleTree::verify(
                roots[l],
                leaf_j,
                j,
                &MerkleProof {
                    sibs: path_j.clone(),
                    index: j,
                },
            );
            ensure!(ok_i && ok_j, "FRI Merkle path failed at layer {}", l);

            // Fold check against the first value of the next layer's pair (contract).
            let vi = F1::from_u64(u64::from_le_bytes(*vi_le)); // value at idx
            let vj = F1::from_u64(u64::from_le_bytes(*vj_le)); // value at j = idx ^ half
            let beta = betas[l];

            // Canonicalize orientation so fold is always (lower, upper).
            let (lower, upper) = if idx < half { (vi, vj) } else { (vj, vi) };
            let v_fold = lower + beta * upper;

            // Next index must be idx % half (structural propagation).
            let expected_idx_next = idx % half;
            ensure!(
                q.positions[l + 1] == expected_idx_next,
                "FRI index propagation failed at layer {}",
                l
            );

            if l + 1 < n_layers - 1 {
                let (vi1_le, _, _, _) = &q.pairs[l + 1];
                let vi1 = F1::from_u64(u64::from_le_bytes(*vi1_le));
                ensure!(vi1 == v_fold, "FRI fold mismatch at layer {}", l);
            } else {
                // Last fold should equal the final value.
                ensure!(v_fold.to_le_bytes() == final_value_le, "final FRI value mismatch");
            }

            idx = expected_idx_next;
            layer_len = half;
        }
    }

    Ok(())
}
