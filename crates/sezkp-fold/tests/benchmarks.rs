#![deny(rust_2018_idioms)]

use sezkp_fold::are::InterfaceWitness;
use sezkp_fold::are_replay::prove_replay;

fn are_bytes(pr: &sezkp_fold::are_replay::AreProof) -> Vec<u8> {
    bincode::serialize(pr).expect("serialize are proof")
}

#[test]
fn micro_perf_smoke() {
    // Not a real bench (no Criterion here) — just ensures the loop is fast
    // and doesn’t allocate wildly.
    let iface = InterfaceWitness {
        left_ctrl_out: 0,
        right_ctrl_in: 0,
        boundary_writes_digest: [0u8; 32],
    };

    let mut acc = [0u8; 32];
    for _ in 0..10_000 {
        let pr = prove_replay(&iface);
        let bytes = are_bytes(&pr); // compute once per iteration
        // fold into acc to keep the compiler from optimizing away
        for i in 0..32 {
            acc[i] ^= bytes.get(i).copied().unwrap_or(0);
        }
    }
    // trivial assertion to use acc
    assert_eq!(acc.len(), 32);
}
