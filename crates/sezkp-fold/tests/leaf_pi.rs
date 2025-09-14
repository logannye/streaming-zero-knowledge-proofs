// crates/sezkp-fold/tests/leaf_pi.rs

#![allow(unused_variables)]
#![allow(dead_code)]
use sezkp_fold::are::Pi;
use sezkp_fold::leaf::{CryptoLeaf, CryptoLeafProof};
use sezkp_fold::api::Leaf;
use sezkp_trace::{generator::generate_trace, partition::partition_trace};

fn bundle_top((c, p, _): &(sezkp_fold::api::Commitment, Pi, CryptoLeafProof)) -> ([u8; 32], u32) {
    (c.root, c.len)
}

fn are_bytes(pr: &sezkp_fold::are_replay::AreProof) -> Vec<u8> {
    bincode::serialize(pr).expect("serialize are proof")
}

fn tamper_are(pr: &sezkp_fold::are_replay::AreProof) -> sezkp_fold::are_replay::AreProof {
    // Flip a byte and try to deserialize; if that fails, flip a different byte
    let mut b = are_bytes(pr);
    if !b.is_empty() { b[0] ^= 1; }
    bincode::deserialize(&b).unwrap_or_else(|_| {
        // Fallback: force a simple tampering for V1Mac only
        match pr {
            sezkp_fold::are_replay::AreProof::V1Mac(m) => {
                let mut x = *m;
                x[0] ^= 1;
                sezkp_fold::are_replay::AreProof::V1Mac(x)
            }
            _ => pr.clone(),
        }
    })
}

#[test]
fn leaf_pi_prove_verify_roundtrip_and_tamper() {
    // Build a small trace and one block
    let tr = generate_trace(64, 2);
    let blocks = partition_trace(&tr, 1);
    let blk = &blocks[0];

    // Prove leaf
    let (pi, c, pr) = CryptoLeaf::prove_leaf(blk);
    assert!(CryptoLeaf::verify_leaf(&c, &pi, &pr), "leaf verify should pass");

    // Quick sanity on commitment
    let (root, len) = bundle_top(&(c, pi, pr.clone()));
    assert_eq!(len, 1);
    assert_ne!(root, [0u8; 32]);

    // Tamper: flip a limb in π.acc
    let mut pi_bad = pi;
    let mut le = pi_bad.acc[0].to_le_bytes();
    le[0] ^= 0x01;
    pi_bad.acc[0] = sezkp_stark::v1::field::F1::from_u64(u64::from_le_bytes(le));
    assert!(
        !CryptoLeaf::verify_leaf(&c, &pi_bad, &pr),
        "tampered π must fail verification"
    );

    // Tamper: swap boundary halves encoded in limbs (0..1) <-> (2..3)
    let mut pi_swap = pi;
    pi_swap.acc.swap(0, 2);
    pi_swap.acc.swap(1, 3);
    assert!(
        !CryptoLeaf::verify_leaf(&c, &pi_swap, &pr),
        "swapped boundary limbs must fail"
    );

    // Serde round-trips (bincode)
    let pi_bin = bincode::serialize(&pi).unwrap();
    let pi_back: Pi = bincode::deserialize(&pi_bin).unwrap();
    assert_eq!(pi, pi_back);

    let pr_bin = bincode::serialize(&pr).unwrap();
    let pr_back: CryptoLeafProof = bincode::deserialize(&pr_bin).unwrap();
    assert_eq!(pr.mac, pr_back.mac);
}
