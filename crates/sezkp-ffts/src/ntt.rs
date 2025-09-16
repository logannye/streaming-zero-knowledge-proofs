//! In-place radix-2 Cooley–Tukey NTT/INTT for Goldilocks.
//!
//! The forward transform maps **coefficients → evaluations** over a 2^k subgroup,
//! and the inverse transform maps **evaluations → coefficients**.
//!
//! Design notes:
//! - Uses bit-reversed reordering (DIT) and per-stage twiddle tables.
//! - Twiddles are computed per call and kept local; for repeated sizes you may
//!   consider caching twiddles externally.
//! - Length `n` must be a power of two.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::{goldilocks_primitive_root_2exp, Goldilocks as F};

#[inline]
fn bitrev(mut x: usize, bits: usize) -> usize {
    let mut y = 0usize;
    for _ in 0..bits {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    y
}

#[inline]
fn bit_reverse_permute(a: &mut [F]) {
    let n = a.len();
    debug_assert!(n.is_power_of_two(), "length must be power of two");
    let bits = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = bitrev(i, bits);
        if j > i {
            a.swap(i, j);
        }
    }
}

#[inline]
fn build_twiddles_forward(n_log2: usize) -> Vec<Vec<F>> {
    // Stage s in [1..=n_log2] has half = 2^(s-1) twiddles.
    let mut out = Vec::with_capacity(n_log2);
    for s in 1..=n_log2 {
        let half = 1usize << (s - 1);
        let w_len = goldilocks_primitive_root_2exp(s as u32);
        let mut ws = Vec::with_capacity(half);
        let mut w = F::from_u64(1);
        for _ in 0..half {
            ws.push(w);
            w *= w_len;
        }
        out.push(ws);
    }
    out
}

#[inline]
fn build_twiddles_inverse(n_log2: usize) -> Vec<Vec<F>> {
    let mut out = Vec::with_capacity(n_log2);
    for s in 1..=n_log2 {
        let half = 1usize << (s - 1);
        let w_len_inv = goldilocks_primitive_root_2exp(s as u32).inv();
        let mut ws = Vec::with_capacity(half);
        let mut w = F::from_u64(1);
        for _ in 0..half {
            ws.push(w);
            w *= w_len_inv;
        }
        out.push(ws);
    }
    out
}

/// Forward NTT in place (coefficients → values). Length must be a power of two.
///
/// Complexity: Θ(n log n) multiplications/additions.
pub fn forward_ntt_in_place(a: &mut [F]) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    assert!(n.is_power_of_two(), "NTT size must be power of two");
    bit_reverse_permute(a);

    let n_log2 = n.trailing_zeros() as usize;
    let tw = build_twiddles_forward(n_log2);

    let mut len = 2usize;
    let mut stage = 1usize;
    while len <= n {
        let half = len / 2;
        let w_stage = &tw[stage - 1];

        let mut j = 0usize;
        while j < n {
            // DIT butterfly: (u, v) -> (u + w*v, u - w*v)
            for i in 0..half {
                let u = a[j + i];
                let v = a[j + i + half] * w_stage[i];
                a[j + i] = u + v;
                a[j + i + half] = u - v;
            }
            j += len;
        }

        stage += 1;
        len <<= 1;
    }
}

/// Inverse NTT in place (values → coefficients). Length must be a power of two.
///
/// This mirrors the forward transform but uses inverse per-stage twiddles.
/// After the butterfly passes, we scale by `n^{-1}` to recover coefficients.
pub fn inverse_ntt_in_place(a: &mut [F]) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    assert!(n.is_power_of_two(), "NTT size must be power of two");
    bit_reverse_permute(a);

    let n_log2 = n.trailing_zeros() as usize;
    let tw_inv = build_twiddles_inverse(n_log2);

    let mut len = 2usize;
    let mut stage = 1usize;
    while len <= n {
        let half = len / 2;
        let w_stage = &tw_inv[stage - 1];

        let mut j = 0usize;
        while j < n {
            // Mirror of forward: t = w^{-1} * a[j+i+half]
            for i in 0..half {
                let u = a[j + i];
                let t = a[j + i + half] * w_stage[i];
                a[j + i] = u + t;
                a[j + i + half] = u - t;
            }
            j += len;
        }

        stage += 1;
        len <<= 1;
    }

    // Multiply by n^{-1}.
    let inv_n = F::from_u64(n as u64).inv();
    for x in a.iter_mut() {
        *x *= inv_n;
    }
}

/// Evaluate a polynomial (given by coefficients) on a `2^k` domain using NTT.
///
/// If `coeffs.len() < 2^k`, the input is zero-padded.
/// If `coeffs.len() > 2^k`, the input is truncated (mod `x^{2^k} - 1` semantics).
#[must_use]
pub fn evaluate_on_pow2_domain(coeffs: &[F], k_log2: usize) -> Vec<F> {
    let n = 1usize << k_log2;
    let mut buf = vec![F::from_u64(0); n];
    let m = coeffs.len().min(n);
    buf[..m].copy_from_slice(&coeffs[..m]);
    forward_ntt_in_place(&mut buf);
    buf
}

/// Interpolate coefficients from evaluations on a `2^k` domain using INTT.
#[must_use]
pub fn interpolate_from_evals(evals: &[F]) -> Vec<F> {
    let mut buf = evals.to_vec();
    inverse_ntt_in_place(&mut buf);
    buf
}
