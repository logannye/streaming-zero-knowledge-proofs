//! Field glue for STARK v1: Goldilocks wrapper and helpers.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

/// Field used by v1 (Goldilocks from `sezkp-ffts`).
pub use sezkp_ffts::Goldilocks as F1;

use sezkp_ffts::{Fp64, GOLDILOCKS};

/// From `u64` into the field.
#[inline]
#[must_use]
pub fn f_from_u64(x: u64) -> F1 {
    Fp64::<GOLDILOCKS>(x % GOLDILOCKS)
}

/// From `i64` into the field.
#[inline]
#[must_use]
pub fn f_from_i64(x: i64) -> F1 {
    if x >= 0 {
        f_from_u64(x as u64)
    } else {
        // (-x) mod p, then additive inverse.
        let m = ((-x) as u64) % GOLDILOCKS;
        let v = if m == 0 { 0 } else { GOLDILOCKS - m };
        Fp64::<GOLDILOCKS>(v)
    }
}
