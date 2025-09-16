//! Streaming LDE + DEEP transformation for layer-0 FRI values.
//!
//! This module provides a DEEP-on-the-fly coset evaluator that streams the
//! resulting values in chunks to a consumer, avoiding a hard dependency on
//! an in-memory `Vec<F1>` at the call site.
//!
//! Pipeline:
//!   base evals C(i)  --(interpolate)--> coeffs
//!     --(evaluate on coset with shift)--> y[i] = C(x_i)
//!     --(DEEP divide by (x_i - z))--> y[i]/(x_i - z)  (emitted in chunks)

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_mut)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use crate::v1::field::F1;
use sezkp_ffts::{
    coset::evaluate_on_coset_pow2, goldilocks_primitive_root_2exp, ntt::interpolate_from_evals,
};

/// Drives: base-domain -> (interpolate) -> LDE on coset -> DEEP divide,
/// streaming the resulting y[i]/(x_i - z) in chunks to a consumer.
///
/// * `base_compose_eval(i)` must return the AIR composition value C(i) at
///   base row i as 8-byte little-endian field encoding.
/// * `n_base` is the base domain size (trace length), a power of two.
/// * `blow_log2` is the log2 blowup factor (so LDE domain size is n_base << blow_log2).
/// * `shift` is the standard coset shift.
/// * `z` is the OOD evaluation point; caller must ensure z is off the coset.
/// * `out_chunk_log2` controls the output chunk size: `1<<out_chunk_log2`.
///
/// Internally, we currently use in-memory kernels from `sezkp_ffts`. The
/// consumer still receives values in chunks, so swapping in an out-of-core/
/// blocked NTT later will not change the call site.
pub fn deep_coset_lde_stream<F: FnMut(&[[u8; 8]])>(
    mut base_compose_eval: impl FnMut(usize) -> [u8; 8],
    n_base: usize,
    blow_log2: usize,
    shift: F1,
    z: F1,
    out_chunk_log2: usize,
    mut consume: F,
) {
    assert!(n_base.is_power_of_two(), "n_base must be a power of two");
    let base_log2 = n_base.trailing_zeros() as usize;
    let lde_k_log2 = base_log2 + blow_log2;
    let lde_n = 1usize << lde_k_log2;

    /* ---------------- Base-domain evaluations: C(i) ------------------------ */
    let mut base_vals = Vec::with_capacity(n_base);
    for i in 0..n_base {
        let le = base_compose_eval(i);
        let v = F1::from_u64(u64::from_le_bytes(le));
        base_vals.push(v);
    }

    /* ---------------- Interpolate to coefficients (INTT) ------------------- */
    let coeffs = interpolate_from_evals(&base_vals);

    /* ---------------- Evaluate on multiplicative coset --------------------- */
    // y[i] = C(x_i) with x_i = shift * ω^i, |domain| = lde_n
    let mut y = evaluate_on_coset_pow2(&coeffs, lde_k_log2, shift);

    /* ---------------- Apply DEEP: divide by (x_i - z) ---------------------- */
    // Emit results in caller-specified chunk sizes without exposing `F1`.
    let chunk = 1usize << out_chunk_log2;
    let mut buf: Vec<[u8; 8]> = Vec::with_capacity(chunk);

    let one = F1::from_u64(1);
    let w = goldilocks_primitive_root_2exp(lde_k_log2 as u32);
    let mut w_pow = one; // ω^0

    for i in 0..lde_n {
        let x = shift * w_pow;
        let denom = x - z;
        debug_assert!(denom != F1::from_u64(0), "OOD point z must not lie on the coset");
        let out = y[i] * denom.inv();

        buf.push(out.to_le_bytes());
        if buf.len() == buf.capacity() {
            consume(&buf);
            buf.clear();
        }

        w_pow *= w;
    }
    if !buf.is_empty() {
        consume(&buf);
    }
}
