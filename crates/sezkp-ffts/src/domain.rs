//! Evaluation-domain helpers for the Goldilocks field.
//!
//! We construct size-`2^k` multiplicative subgroups by taking a fixed generator
//! `g = 7` and setting `ω_k = g^((p-1)/2^k)`, which has exact order `2^k` in
//! the Goldilocks field (2-adicity 32).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::{Fp64, Goldilocks as F, GOLDILOCKS};

/// A power-of-two multiplicative subgroup domain.
#[derive(Clone, Debug)]
pub struct Pow2Domain {
    /// Domain size (`2^k`).
    pub size: usize,
    /// A generator of the size-`size` subgroup.
    pub gen: F,
}

impl Pow2Domain {
    /// Return the `i`-th element: `gen^i`.
    #[inline]
    #[must_use]
    pub fn element(&self, i: usize) -> F {
        self.gen.pow(i as u64)
    }
}

/// Compute a `2^k` domain for Goldilocks. `1 <= k <= 32`.
///
/// Construction:
/// Pick a base generator `g = 7`, then set `ω = g^((p-1)/2^k)`.
/// Debug-mode checks assert the order is exactly `2^k`.
#[must_use]
pub fn pow2_domain(k: usize) -> Pow2Domain {
    assert!((1..=32).contains(&k), "k must be in 1..=32 for Goldilocks");

    // (p-1)/2^k
    let p_minus_1 = (GOLDILOCKS as u128) - 1;
    let exp = (p_minus_1 >> k) as u64;

    // NOTE: `F` is a type alias; construct via the underlying tuple struct.
    const BASE_GEN: Fp64<GOLDILOCKS> = Fp64::<GOLDILOCKS>(7);
    let w_k = BASE_GEN.pow(exp);

    // Debug assertions to help catch accidental misuse or wrong parameters.
    debug_assert_eq!(w_k.pow(1u64 << k), F::one(), "ω^(2^k) should be 1");
    if k > 0 {
        debug_assert_ne!(
            w_k.pow(1u64 << (k - 1)),
            F::one(),
            "ω should have exact order 2^k"
        );
    }

    Pow2Domain {
        size: 1usize << k,
        gen: w_k,
    }
}
