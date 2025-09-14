//! Twiddle-factor helpers for power-of-two NTT over Goldilocks.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use crate::domain::Pow2Domain;
use crate::Goldilocks as F;

/// Compute stage twiddles for a length-`n` NTT with primitive `n`-th root `omega`.
/// Returns a vector of length `n/2` where entry `j` is `omega^j`.
#[inline]
#[must_use]
pub fn stage_twiddles(dom: &Pow2Domain) -> Vec<F> {
    let n = dom.size;
    debug_assert!(n.is_power_of_two());
    let mut tw = Vec::with_capacity(n / 2);
    let mut cur = F::from_u64(1);
    for _ in 0..(n / 2) {
        tw.push(cur);
        cur *= dom.gen;
    }
    tw
}
