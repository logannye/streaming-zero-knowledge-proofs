//! Round-trip tests: coeffs --NTT--> evals --INTT--> coeffs

use sezkp_ffts::{
    ntt::{forward_ntt_in_place, inverse_ntt_in_place},
    Goldilocks as F,
};

#[inline]
#[track_caller]
fn det_vec(n: usize, seed: u64) -> Vec<F> {
    // Tiny LCG to avoid bringing in `rand`.
    let (mut a, c, m) = (
        1_664_525u64.wrapping_mul(seed).wrapping_add(1_013_904_223),
        1_013_904_223u64,
        1u64 << 32,
    );
    (0..n)
        .map(|i| {
            a = a.wrapping_mul(1_664_525).wrapping_add(c) % m;
            F::from_u64(a ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        })
        .collect()
}

#[test]
fn ntt_roundtrip_various_sizes() {
    for k in 1..=12 {
        let n = 1usize << k;
        let mut v = det_vec(n, 1_337);
        let original = v.clone();

        forward_ntt_in_place(&mut v);
        inverse_ntt_in_place(&mut v);

        assert_eq!(v, original, "round-trip failed (n = 2^{k})");
    }
}

#[test]
fn ntt_roundtrip_special_vectors() {
    // All zeros.
    for k in 1..=10 {
        let n = 1usize << k;
        let mut v = vec![F::from_u64(0); n];
        let original = v.clone();

        forward_ntt_in_place(&mut v);
        inverse_ntt_in_place(&mut v);

        assert_eq!(v, original, "zeros round-trip failed (n = 2^{k})");
    }

    // Delta (1, 0, 0, ...).
    for k in 1..=10 {
        let n = 1usize << k;
        let mut v = vec![F::from_u64(0); n];
        v[0] = F::from_u64(1);
        let original = v.clone();

        forward_ntt_in_place(&mut v);
        inverse_ntt_in_place(&mut v);

        assert_eq!(v, original, "delta round-trip failed (n = 2^{k})");
    }

    // Arithmetic progression.
    for k in 1..=10 {
        let n = 1usize << k;
        let mut v: Vec<F> = (0..n).map(|i| F::from_u64(i as u64)).collect();
        let original = v.clone();

        forward_ntt_in_place(&mut v);
        inverse_ntt_in_place(&mut v);

        assert_eq!(v, original, "AP round-trip failed (n = 2^{k})");
    }
}
