//! Simple multiplicative cosets for power-of-two subgroup domains (Goldilocks).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use crate::ntt::forward_ntt_in_place;
use crate::{domain::Pow2Domain, Goldilocks as F};

/// A multiplicative coset of a power-of-two subgroup domain:
/// `C = shift · ⟨gen⟩`, where `gen` generates the base subgroup.
#[derive(Clone, Debug)]
pub struct CosetDomain {
    /// Base `2^k` subgroup domain.
    pub base: Pow2Domain,
    /// Shift (coset representative), ideally chosen outside the subgroup.
    pub shift: F,
}

impl CosetDomain {
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
#[inline]
#[must_use]
pub fn coset_from_pow2(base: Pow2Domain, shift: F) -> CosetDomain {
    CosetDomain { base, shift }
}

/// Convenience: pick a default shift for a given `2^k` base domain.
///
/// In production, sample uniformly from `F*` and reject subgroup elements.
/// Here we use `3` for demos.
#[inline]
#[must_use]
pub fn default_coset(base: Pow2Domain) -> CosetDomain {
    let shift = F::from_u64(3);
    CosetDomain { base, shift }
}

/* ------------------------ Coset LDE helper functions ------------------------ */

/// Evaluate a polynomial (given by coefficients) on a coset of size `2^k`.
///
/// Standard trick: `f(shift·x)` at subgroup points `x` equals the NTT of
/// coefficients scaled by `shift^j` (i.e., `g_j = coeff_j * shift^j`).
///
/// Semantics when `coeffs.len() > 2^k`:
/// we **truncate** to the first `2^k` coefficients (mod `x^{2^k}-1` behavior).
#[must_use]
pub fn evaluate_on_coset_pow2(coeffs: &[F], k_log2: usize, shift: F) -> Vec<F> {
    let n = 1usize << k_log2;

    // Scale coefficients by shift^j and zero-pad to n.
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
