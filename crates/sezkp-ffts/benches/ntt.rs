use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use sezkp_ffts::{
    coset::evaluate_on_coset_pow2,
    ntt::{forward_ntt_in_place, inverse_ntt_in_place},
    Goldilocks as F,
};

#[inline]
fn det_vec(n: usize, seed: u64) -> Vec<F> {
    let (mut a, c, m) = (
        1664525u64.wrapping_mul(seed).wrapping_add(1013904223),
        1013904223u64,
        1u64 << 32,
    );
    (0..n)
        .map(|i| {
            a = a.wrapping_mul(1664525).wrapping_add(c) % m;
            F::from_u64(a ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        })
        .collect()
}

fn bench_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_goldilocks_pow2");
    for &k in &[16usize, 18usize] {
        let n = 1usize << k;
        group.throughput(Throughput::Elements(n as u64));

        // Base coefficients (deterministic, stable across runs).
        let base = det_vec(n, 2024);

        // Forward NTT
        group.bench_function(BenchmarkId::new("forward_ntt_in_place", format!("2^{k}")), |b| {
            b.iter_batched(
                || black_box(base.clone()),
                |mut v| {
                    forward_ntt_in_place(black_box(&mut v));
                    black_box(v);
                },
                BatchSize::LargeInput,
            )
        });

        // Precompute forward evals for inverse NTT bench.
        let mut evals = base.clone();
        forward_ntt_in_place(&mut evals);

        // Inverse NTT
        group.bench_function(BenchmarkId::new("inverse_ntt_in_place", format!("2^{k}")), |b| {
            b.iter_batched(
                || black_box(evals.clone()),
                |mut v| {
                    inverse_ntt_in_place(black_box(&mut v));
                    black_box(v);
                },
                BatchSize::LargeInput,
            )
        });

        // Coset LDE from coefficient domain (common path in STARKs)
        group.bench_function(
            BenchmarkId::new("evaluate_on_coset_pow2", format!("2^{k}")),
            |b| {
                b.iter_batched(
                    || black_box(base.clone()),
                    |coeffs| {
                        // Shift = 3 is our demo default in the prover.
                        black_box(evaluate_on_coset_pow2(black_box(&coeffs), k, F::from_u64(3)));
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ntt);
criterion_main!(benches);
