//! Micro “perf” smoke test for ARE proof construction.
//!
//! This is **not** a real benchmark (we avoid Criterion here to keep
//! dev-deps small). It simply runs the legacy MAC-style proof many times
//! to catch obvious regressions (e.g., unbounded allocs or panics).

#![deny(rust_2018_idioms)]

use sezkp_fold::are::InterfaceWitness;
use sezkp_fold::are_replay::prove_replay;

fn are_bytes(pr: &sezkp_fold::are_replay::AreProof) -> Vec<u8> {
    bincode::serialize(pr).expect("serialize are proof")
}

#[test]
fn micro_perf_smoke() {
    // Fixed public inputs: trivial interface witness.
    let iface = InterfaceWitness {
        left_ctrl_out: 0,
        right_ctrl_in: 0,
        boundary_writes_digest: [0u8; 32],
    };

    // Accumulator to keep the compiler from optimizing away the loop.
    let mut acc = [0u8; 32];

    // Run a few thousand iterations to exercise proof+serialization paths.
    for _ in 0..10_000 {
        let pr = prove_replay(&iface);
        let bytes = are_bytes(&pr);
        // Fold into acc to keep effects observable.
        for i in 0..32 {
            acc[i] ^= bytes.get(i).copied().unwrap_or(0);
        }
    }

    // Trivial assertion to use `acc` and avoid “unused” warnings.
    assert_eq!(acc.len(), 32);
}
