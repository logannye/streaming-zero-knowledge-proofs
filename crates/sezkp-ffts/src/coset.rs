//! Simple multiplicative cosets for power-of-two subgroup domains (Goldilocks).
//!
//! A coset of a subgroup domain `⟨gen⟩` is `shift · ⟨gen⟩` with `shift ∈ F*`.
//! In STARKs, we often evaluate polynomials on such cosets (low-degree extension).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::ntt::forward_ntt_in_place;
use crate::{domain::Pow2Domain, Goldilocks as F};

/// A multiplicative coset of a power-of-two subgroup domain:
/// `C = shift · ⟨gen⟩`, where `gen` generates the base subgroup.
#[derive(Clone, Debug)]
pub struct CosetDomain {
    /// Base `2^k` subgroup domain.
    pub base: Pow2Domain,
    /// Shift (coset representative), **must be non-zero**.
    pub shift: F,
}

impl CosetDomain {
    /// Construct a coset from a base domain and a non-zero shift.
    ///
    /// # Panics
    /// Panics in debug builds if `shift == 0`.
    #[inline]
    #[must_use]
    pub fn new(base: Pow2Domain, shift: F) -> Self {
        debug_assert!(shift != F::zero(), "coset shift must be non-zero");
        Self { base, shift }
    }

    /// Number of elements in the coset (same as base).
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.base.size
    }

    /// `i`-th element: `shift * base.element(i)`.
    #[inline]
    #[must_use]
    pub fn element(&self, i: usize) -> F {
        self.shift * self.base.element(i)
    }
}

/// Build a coset from a base domain and an explicit shift.
///
/// # Panics
/// Panics in debug builds if `shift == 0`.
#[inline]
#[must_use]
pub fn coset_from_pow2(base: Pow2Domain, shift: F) -> CosetDomain {
    CosetDomain::new(base, shift)
}

/// Convenience: pick a default shift for a given `2^k` base domain.
///
/// In production, sample uniformly from `F*` and reject subgroup elements.
/// Here we use `3` for demos (non-zero, cheap).
#[inline]
#[must_use]
pub fn default_coset(base: Pow2Domain) -> CosetDomain {
    let shift = F::from_u64(3);
    coset_from_pow2(base, shift)
}

/* ------------------------ Coset LDE helper functions ------------------------ */

/// Evaluate a polynomial (given by coefficients) on a coset of size `2^k`.
///
/// Standard trick: evaluating `f(shift·x)` over subgroup points `x` equals the NTT
/// of **shift-scaled coefficients** `g_j = coeff_j * shift^j`.
///
/// Semantics when `coeffs.len() > 2^k`: we **truncate** to the first `2^k`
/// coefficients (i.e., arithmetic modulo `x^{2^k} - 1`). When `coeffs.len() < 2^k`,
/// we zero-pad the higher coefficients.
///
/// # Panics
/// Debug builds assert `shift != 0` and `k_log2 > 0`.
#[must_use]
pub fn evaluate_on_coset_pow2(coeffs: &[F], k_log2: usize, shift: F) -> Vec<F> {
    debug_assert!(k_log2 > 0, "domain size must be at least 2");
    debug_assert!(shift != F::zero(), "coset shift must be non-zero");

    let n = 1usize << k_log2;

    // Scale coefficients by shift^j and zero-pad/truncate to n.
    let mut scaled = vec![F::from_u64(0); n];
    let mut pow = F::from_u64(1);
    let m = coeffs.len().min(n);
    for j in 0..m {
        scaled[j] = coeffs[j] * pow;
        pow *= shift;
    }

    forward_ntt_in_place(&mut scaled);
    scaled
}
