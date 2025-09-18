//! Coset LDE tests.
//!
//! Invariants tested:
//! 1) `shift = 1` matches plain NTT on the base subgroup.
//! 2) Scaling-by-`shift^j` in coefficient space equals evaluating the original
//!    polynomial on the multiplicative coset with that `shift`.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::cast_possible_truncation)]

use sezkp_ffts::{coset::evaluate_on_coset_pow2, ntt::evaluate_on_pow2_domain, Goldilocks as F};

#[inline]
#[track_caller]
fn det_coeffs(n: usize) -> Vec<F> {
    // Deterministic coefficients without `rand`.
    (0..n)
        .map(|i| F::from_u64((i as u64).wrapping_mul(0xDEAD_BEEF_u64 ^ 0x42)))
        .collect()
}

#[test]
fn coset_shift_one_matches_plain_ntt() {
    for k in 1..=12 {
        let n = 1usize << k;
        let coeffs = det_coeffs(n);

        let evals_plain = evaluate_on_pow2_domain(&coeffs, k);
        let evals_coset = evaluate_on_coset_pow2(&coeffs, k, F::from_u64(1));

        assert_eq!(
            evals_coset, evals_plain,
            "coset shift=1 should equal plain NTT (n = 2^{k})"
        );
    }
}

#[test]
fn coset_scaling_invariant() {
    // Scaling invariant:
    // If we scale coefficient j by shift^j, then evaluating on the base subgroup
    // equals evaluating the original polynomial on the coset with that shift.
    let shift = F::from_u64(7);
    for k in 4..=12 {
        let n = 1usize << k;
        let coeffs = det_coeffs(n);

        let mut pow = F::from_u64(1);
        let mut scaled = Vec::with_capacity(n);
        for &c in &coeffs {
            scaled.push(c * pow);
            pow *= shift; // pow = shift^j
        }

        let evals_scaled_on_base = evaluate_on_pow2_domain(&scaled, k);
        let evals_orig_on_coset = evaluate_on_coset_pow2(&coeffs, k, shift);

        assert_eq!(
            evals_scaled_on_base, evals_orig_on_coset,
            "scaling-by-shift^j invariant failed (n = 2^{k})"
        );
    }
}
