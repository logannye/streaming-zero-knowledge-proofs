//! v1 parameter constants + centralized transcript/domain labels + challenge helpers.
//!
//! These are the only knobs the prover & verifier should read directly.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use sezkp_crypto::Transcript;

use crate::v1::field::F1;

/* ------------------------------ Security knobs ------------------------------ */

/// Target soundness (bits) for the prototype.
pub const SOUNDNESS_BITS: usize = 100;

/// FRI folding rate (2 means halve domain each layer).
pub const FRI_RATE: usize = 2;

/// Trace-domain blowup (evaluation domain size / trace length).
pub const BLOWUP: usize = 8;

/// Number of random query positions sampled from the transcript.
pub const NUM_QUERIES: usize = 30;

/// Minimum log2 domain size (2^k). Useful to avoid tiny domains in tests.
pub const DOMAIN_MIN_LOG2: usize = 12;

/// Column commitment chunk size as log2; chunk = 1 << COL_CHUNK_LOG2 rows.
pub const COL_CHUNK_LOG2: usize = 10; // 1024 rows per chunk

/// Suggested streaming chunk for future fully-streamed LDE/FRI (2^k elements).
/// (Reserved; current streaming keeps only one layer in memory.)
pub const STREAM_CHUNK_LOG2: usize = 14; // 16,384

/* -------------------------- Transcript label strings ------------------------ */

/// Top-level protocol domain string for v1.
pub const DS_V1_DOMAIN: &str = "sezkp-stark/v1";

/// Label for binding the number of columns into the transcript.
pub const DS_N_COLS: &str = "n_cols";

/// Label used when absorbing per-column Merkle roots into the transcript.
pub const DS_COL_ROOT: &str = "col_root";

/// Domain-sep for *leaf hashing* of column commitments (used inside Merkle).
pub const DS_COL_LEAF: &str = "col_leaf";

/// Label to derive AIR linear-combination coefficients (alphas).
pub const DS_ALPHAS: &str = "alphas";

/// Label to derive random row query indices (AIR).
pub const DS_QUERIES: &str = "row_queries";

/// Label to derive FRI layer folding coefficients (betas).
pub const DS_FRI_BETAS: &str = "fri_betas";

/// Label used when absorbing FRI layer Merkle roots.
pub const DS_FRI_LAYER_ROOT: &str = "fri_layer_root";

/// (Optional) Label to derive an OOD/DEEP evaluation point.
pub const DS_OOD_POINT: &str = "ood_point";

/// (Optional) Mixer for DEEP or mask terms if needed.
pub const DS_DEEP_ALPHA: &str = "deep_alpha";

/* ------------------------------- Derivers ---------------------------------- */

/// Number of alphas used in the composition polynomial.
pub const NUM_ALPHAS: usize = 8;

/// Derive `NUM_ALPHAS` field elements from the transcript with `DS_ALPHAS`.
#[must_use]
pub fn derive_alphas<T: Transcript>(tr: &mut T) -> [F1; NUM_ALPHAS] {
    let bytes = tr.challenge_bytes(DS_ALPHAS, 8 * NUM_ALPHAS);
    let mut out = [F1::from_u64(0); NUM_ALPHAS];
    for i in 0..NUM_ALPHAS {
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = F1::from_u64(u64::from_le_bytes(le));
    }
    out
}

/// Derive `k` query positions in `[0, n)` using `DS_QUERIES`.
#[must_use]
pub fn derive_queries<T: Transcript>(tr: &mut T, n: usize, k: usize) -> Vec<usize> {
    let bytes = tr.challenge_bytes(DS_QUERIES, 8 * k);
    let mut out = Vec::with_capacity(k);
    for i in 0..k {
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let v = u64::from_le_bytes(le) as usize;
        out.push(v % n.max(1));
    }
    out
}

/// Derive exactly `n_layers` FRI folding coefficients (betas) using `DS_FRI_BETAS`.
#[must_use]
pub fn derive_betas_for_fri<T: Transcript>(tr: &mut T, n_layers: usize) -> Vec<F1> {
    let bytes = tr.challenge_bytes(DS_FRI_BETAS, 8 * n_layers);
    let mut out = Vec::with_capacity(n_layers);
    for i in 0..n_layers {
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out.push(F1::from_u64(u64::from_le_bytes(le)));
    }
    out
}

/// Derive one field element as an OOD/DEEP evaluation point with `DS_OOD_POINT`.
#[must_use]
pub fn derive_ood_point<T: Transcript>(tr: &mut T) -> F1 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&tr.challenge_bytes(DS_OOD_POINT, 8));
    F1::from_u64(u64::from_le_bytes(le))
}
