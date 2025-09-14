//! Stream-friendly zero-knowledge masking helpers.
//!
//! We derive a small family of **low-degree random polynomials** from the
//! transcript (post column commitments, pre AIR queries) and add them to the
//! composition stream. This ensures the committed codeword is statistically
//! independent from the witness beyond what the transcript binds.
//!
//! Design goals:
//! - **Transcript-bound**: the prover and verifier both derive identical mask
//!   coefficients from the transcript only (no witness inputs).
//! - **Low degree**: each mask has a tiny fixed degree (e.g. 3), keeping the
//!   overall degree budget unchanged up to constants.
//! - **Stream friendly**: coefficients are derived once; evaluation at points
//!   `x` is done with Horner's rule using constant state.
//!
//! Usage pattern:
//! 1. Prover & verifier **both call** `derive_mask_coeffs` at the same point
//!    in the transcript schedule (we bind it after alphas, before row queries).
//! 2. Prover evaluates `R(x)` on the base domain (with `x = ω^i`) and adds it
//!    into the composition value before streaming into the LDE/DEEP engine.
//! 3. Verifier does NOT need these values during the openings-only AIR check;
//!    it only needs to consume the same transcript challenges to remain in
//!    perfect sync with the prover for subsequent randomness draws.

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

/// Domain separator for mask draws.
pub const DS_MASKS: &str = "masks";

/// Sensible defaults (can be tuned): one cubic mask.
pub const DEFAULT_N_MASKS: usize = 1;
/// Degree here is the number of coefficients; using 4 => cubic.
pub const DEFAULT_MASK_DEG: usize = 4;

/// Derive `k` independent low-degree mask polynomials from the transcript.
///
/// Returns a vector `coeffs[k][deg]` of field coefficients (ascending order).
///
/// API contract:
/// - Both prover and verifier must call this at the **same point** in the
///   transcript schedule to keep challenges aligned.
/// - This function **only** depends on transcript state; it reads no witness.
#[must_use]
pub fn derive_mask_coeffs<T: Transcript>(tr: &mut T, deg: usize, k: usize) -> Vec<Vec<F1>> {
    // Bind a DS label and the shape to the transcript to keep draws structured.
    tr.absorb(DS_MASKS, DS_MASKS.as_bytes());
    tr.absorb_u64("n_masks", k as u64);
    tr.absorb_u64("deg", deg as u64);

    let mut out = vec![vec![F1::from_u64(0); deg]; k];

    for i in 0..k {
        for j in 0..deg {
            // Request 8 random bytes and map to F1 via from_u64.
            let bytes = tr.challenge_bytes("mask_coeff", 8);
            debug_assert!(
                bytes.len() == 8,
                "transcript returned unexpected length for mask coeff"
            );
            let mut buf8 = [0u8; 8];
            buf8.copy_from_slice(&bytes[..8]);
            let v = u64::from_le_bytes(buf8);
            out[i][j] = F1::from_u64(v);
        }
    }
    out
}

/// Evaluate a single low-degree mask polynomial at point `x` via Horner's rule.
///
/// `coeffs` are in ascending order (c0 + c1 x + ... + c_{d-1} x^{d-1}).
#[inline]
#[must_use]
pub fn eval_mask_at(coeffs: &[F1], x: F1) -> F1 {
    let mut acc = F1::from_u64(0);
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Evaluate and accumulate multiple mask polynomials at the same point `x`.
#[inline]
#[must_use]
pub fn eval_masks_sum_at(all_coeffs: &[Vec<F1>], x: F1) -> F1 {
    let mut s = F1::from_u64(0);
    for coeffs in all_coeffs {
        s = s + eval_mask_at(coeffs, x);
    }
    s
}
