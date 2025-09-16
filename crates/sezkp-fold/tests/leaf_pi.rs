//! Leaf gadget tests: π production/verification and basic tampering cases.
//!
//! What we assert:
//! - A single-block leaf proof verifies.
//! - The leaf commitment looks sane (len = 1, digest non-zero).
//! - Tampering with π limbs or swapping the boundary halves is detected.
//! - `Pi` and `CryptoLeafProof` survive bincode round-trips.

#![allow(unused_variables)]
#![allow(dead_code)]

use sezkp_fold::api::Leaf;
use sezkp_fold::are::Pi;
use sezkp_fold::leaf::{CryptoLeaf, CryptoLeafProof};
use sezkp_trace::{generator::generate_trace, partition::partition_trace};

/// Convenience: extract (root, len) to sanity-check leaf commitment.
#[inline]
fn commit_summary((c, _p, _pr): &(sezkp_fold::api::Commitment, Pi, CryptoLeafProof)) -> ([u8; 32], u32) {
    (c.root, c.len)
}

#[test]
fn leaf_pi_prove_verify_roundtrip_and_tamper() {
    // Build a small trace and a single block.
    let tr = generate_trace(64, 2);
    let blocks = partition_trace(&tr, 1);
    let blk = &blocks[0];

    // Prove leaf and verify.
    let (pi, c, pr) = CryptoLeaf::prove_leaf(blk);
    assert!(CryptoLeaf::verify_leaf(&c, &pi, &pr), "leaf verify should pass");

    // Commitment sanity: single-leaf commitment with a nonzero digest.
    let (root, len) = commit_summary(&(c, pi, pr.clone()));
    assert_eq!(len, 1);
    assert_ne!(root, [0u8; 32]);

    // Tamper 1: flip a byte in the first π limb.
    let mut pi_bad = pi;
    let mut le = pi_bad.acc[0].to_le_bytes();
    le[0] ^= 0x01;
    pi_bad.acc[0] = sezkp_stark::v1::field::F1::from_u64(u64::from_le_bytes(le));
    assert!(
        !CryptoLeaf::verify_leaf(&c, &pi_bad, &pr),
        "tampered π must fail verification"
    );

    // Tamper 2: swap the boundary halves encoded in limbs (0..1) <-> (2..3).
    let mut pi_swap = pi;
    pi_swap.acc.swap(0, 2);
    pi_swap.acc.swap(1, 3);
    assert!(
        !CryptoLeaf::verify_leaf(&c, &pi_swap, &pr),
        "swapped boundary limbs must fail"
    );

    // Serde round-trips (bincode) for both the projection and the proof.
    let pi_bin = bincode::serialize(&pi).expect("serialize Pi");
    let pi_back: Pi = bincode::deserialize(&pi_bin).expect("deserialize Pi");
    assert_eq!(pi, pi_back);

    let pr_bin = bincode::serialize(&pr).expect("serialize CryptoLeafProof");
    let pr_back: CryptoLeafProof = bincode::deserialize(&pr_bin).expect("deserialize CryptoLeafProof");
    assert_eq!(pr.mac, pr_back.mac, "MAC must survive round-trip");
}
