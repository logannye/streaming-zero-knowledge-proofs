//! Very small prime field + naive DFT bootstrap, plus Goldilocks helpers.
//!
//! - `Fp64<P>`: prime field modulo a 64-bit prime `P` (const generic).
//! - `dft`/`idft`: naive **O(n²)** DFT using a provided primitive root `omega`.
//! - Goldilocks helpers: 64-bit field `p = 2^64 - 2^32 + 1`, primitive 2^k roots.
//! - Modules: `domain`, `ntt`, `twiddle`, `coset` for power-of-two NTTs and LDEs.
//!
//! This crate is intentionally small and straightforward—great for benchmarks,
//! pedagogy, and scaffolded protocol experiments.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown
)]

pub mod domain;
pub use domain::{pow2_domain, Pow2Domain};

pub mod coset;
pub mod ntt;     // in-place NTT/INTT and (eval <-> coeff) helpers
pub mod twiddle; // stage twiddle helpers

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// 64-bit prime field element (const generic modulus).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fp64<const P: u64>(
    /// Canonical representative modulo `P`. Public for convenience.
    pub u64,
);

impl<const P: u64> Fp64<P> {
    /// Zero.
    #[inline]
    #[must_use]
    pub fn zero() -> Self {
        Self(0)
    }

    /// One.
    #[inline]
    #[must_use]
    pub fn one() -> Self {
        Self(1 % P)
    }

    /// Add two raw residues modulo `P` without overflow (via u128).
    #[inline]
    #[must_use]
    pub fn add_raw(a: u64, b: u64) -> u64 {
        let s = (a as u128) + (b as u128);
        let s = if s >= (P as u128) { s - (P as u128) } else { s };
        s as u64
    }

    /// Subtract two raw residues modulo `P` without overflow (via u128).
    #[inline]
    #[must_use]
    pub fn sub_raw(a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            // (a + P) - b, done in u128 to avoid debug overflow.
            ((a as u128) + (P as u128) - (b as u128)) as u64
        }
    }

    /// Multiply two raw residues modulo `P` using a 128-bit intermediate.
    #[inline]
    #[must_use]
    pub fn mul_raw(a: u64, b: u64) -> u64 {
        let prod = (a as u128) * (b as u128);
        (prod % (P as u128)) as u64
    }

    /// Exponentiation by squaring.
    #[inline]
    #[must_use]
    pub fn pow(self, mut e: u64) -> Self {
        let mut base = self;
        let mut acc = Self::one();
        while e > 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        acc
    }

    /// Multiplicative inverse (P assumed prime).
    #[inline]
    #[must_use]
    pub fn inv(self) -> Self {
        self.pow(P - 2)
    }

    /// From signed `i64` (two's-complement mapping into the field).
    #[inline]
    #[must_use]
    pub fn from_i64(x: i64) -> Self {
        Self((x as i128).rem_euclid(P as i128) as u64)
    }

    /// From `u64` reduced mod `P`.
    #[inline]
    #[must_use]
    pub fn from_u64(x: u64) -> Self {
        Self(x % P)
    }

    /// Into little-endian 8 bytes (canonical for this field).
    #[inline]
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Additive inverse.
    #[inline]
    #[must_use]
    pub fn neg(self) -> Self {
        if self.0 == 0 { self } else { Self(P - self.0) }
    }
}

impl<const P: u64> Default for Fp64<P> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<const P: u64> Add for Fp64<P> {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(Self::add_raw(self.0, rhs.0))
    }
}
impl<const P: u64> Sub for Fp64<P> {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(Self::sub_raw(self.0, rhs.0))
    }
}
impl<const P: u64> Mul for Fp64<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(Self::mul_raw(self.0, rhs.0))
    }
}
impl<const P: u64> AddAssign for Fp64<P> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl<const P: u64> SubAssign for Fp64<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl<const P: u64> MulAssign for Fp64<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl<const P: u64> Neg for Fp64<P> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self.neg()
    }
}

/// Naive DFT: `y_k = Σ_j a_j * ω^(j*k)`. Complexity **O(n²)**.
#[must_use]
pub fn dft<const P: u64>(a: &[Fp64<P>], omega: Fp64<P>) -> Vec<Fp64<P>> {
    let n = a.len() as u64;
    let mut out = vec![Fp64::<P>::zero(); n as usize];
    for k in 0..n {
        let mut acc = Fp64::<P>::zero();
        for j in 0..n {
            acc += a[j as usize] * omega.pow(j * k);
        }
        out[k as usize] = acc;
    }
    out
}

/// Inverse DFT: `a_j = (1/n) * Σ_k y_k * (ω^{-1})^(j*k)`. Complexity **O(n²)**.
///
/// # Panics
/// Panics if `n ≡ 0 (mod P)` (non-invertible).
#[must_use]
pub fn idft<const P: u64>(y: &[Fp64<P>], omega: Fp64<P>) -> Vec<Fp64<P>> {
    let n = y.len() as u64;
    assert!(n % P != 0, "idft: length n must be invertible modulo P");
    let inv_n = Fp64::<P>(n % P).inv();
    let omega_inv = omega.inv();

    let mut out = vec![Fp64::<P>::zero(); n as usize];
    for j in 0..n {
        let mut acc = Fp64::<P>::zero();
        for k in 0..n {
            acc += y[k as usize] * omega_inv.pow(j * k);
        }
        out[j as usize] = acc * inv_n;
    }
    out
}

/* ---------------- Goldilocks helpers ---------------- */

/// Goldilocks prime `p = 2^64 - 2^32 + 1`.
pub const GOLDILOCKS: u64 = 0xffff_ffff_0000_0001;

/// Goldilocks field element type.
pub type Goldilocks = Fp64<GOLDILOCKS>;

/// Return a primitive `2^k` root of unity in Goldilocks.
/// (Uses `g=7`; Goldilocks has 2-adicity 32.)
#[must_use]
pub fn goldilocks_primitive_root_2exp(k: u32) -> Goldilocks {
    assert!(k <= 32, "k too large for Goldilocks 2-adicity");
    let g = Goldilocks::from_u64(7);
    let exp = ((GOLDILOCKS - 1) >> k) as u64;
    g.pow(exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: u64 = 97;

    #[test]
    fn dft_roundtrip_small() {
        let g = Fp64::<P>(5);
        let omega = g.pow((P - 1) / 8); // order 8
        let a = vec![
            Fp64::<P>(1),
            Fp64::<P>(2),
            Fp64::<P>(3),
            Fp64::<P>(4),
            Fp64::<P>(5),
            Fp64::<P>(6),
            Fp64::<P>(7),
            Fp64::<P>(8),
        ];
        let y = dft(&a, omega);
        let a2 = idft(&y, omega);
        assert_eq!(a, a2);
    }

    #[test]
    fn goldi_roots_pow2() {
        for k in 1..=8 {
            let w = goldilocks_primitive_root_2exp(k);
            let n = 1u64 << k;
            assert_eq!(w.pow(n).0, 1);
        }
    }
}
