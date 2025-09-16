//! Interface (ARE) micro-proof tests.
//!
//! This exercises the leaf → π projection, extracts the RH/LH boundary
//! prefixes expected by the ARE AIR, and checks both the “happy path”
//! and an adversarial tamper case. It also cross-checks the helper that
//! produces an ARE proof directly from child π states.

#![allow(unused_imports)]
#![allow(dead_code)]

use sezkp_fold::api::Leaf;
use sezkp_fold::are::Pi;
use sezkp_fold::are_replay::{prove_replay_from_children, verify_replay_from_children, AreProof};
use sezkp_stark::v1::air::{prove_iface_replay, verify_iface_replay, LeafIfacePublic};
use sezkp_trace::{generator::generate_trace, partition::partition_trace};

#[inline]
fn le_to_u64(x: &sezkp_stark::v1::field::F1) -> u64 {
    u64::from_le_bytes(x.to_le_bytes())
}

#[test]
fn are_iface_stark_happy_and_adversarial() {
    // Construct a tiny 2-block trace with a clean boundary.
    let tr = generate_trace(64, 2);
    let blocks = partition_trace(&tr, 2);
    let left = &blocks[0];
    let right = &blocks[1];

    // Build π for both leaves using the leaf gadget (to get packed limbs).
    let (pi_l, _, _) = sezkp_fold::leaf::CryptoLeaf::prove_leaf(left);
    let (pi_r, _, _) = sezkp_fold::leaf::CryptoLeaf::prove_leaf(right);

    // Extract prefixes as the AreIfaceAir expects.
    let _lt_l = [le_to_u64(&pi_l.acc[0]), le_to_u64(&pi_l.acc[1])];
    let rh_l = [le_to_u64(&pi_l.acc[2]), le_to_u64(&pi_l.acc[3])];
    let lt_r = [le_to_u64(&pi_r.acc[0]), le_to_u64(&pi_r.acc[1])];
    let _rh_r = [le_to_u64(&pi_r.acc[2]), le_to_u64(&pi_r.acc[3])];

    // Public inputs for the interface check (only RH of left and LT of right used).
    let li = LeafIfacePublic {
        l_tail_prefix: [0, 0],
        r_head_prefix: rh_l,
        ctrl_out: pi_l.ctrl_out,
        ctrl_in: 0,
    };
    let ri = LeafIfacePublic {
        l_tail_prefix: lt_r,
        r_head_prefix: [0, 0],
        ctrl_out: 0,
        ctrl_in: pi_r.ctrl_in,
    };

    // Happy path: prove + verify with matching prefixes.
    let pr = prove_iface_replay(&li, &ri).expect("iface proof");
    assert!(verify_iface_replay(&li, &ri, &pr), "ARE iface should verify");

    // Adversarial: flip a bit in the right leaf's LT prefix (break equality with left's RH).
    let mut ri_bad = ri.clone();
    ri_bad.l_tail_prefix[0] ^= 1;
    assert!(
        !verify_iface_replay(&li, &ri_bad, &pr),
        "tampered public input must fail"
    );

    // Cross-check: produce ARE proof from child π via the fold helper.
    let pr2 =
        prove_replay_from_children(&pi_l, &pi_r, &sezkp_fold::are::InterfaceWitness::trivial(0));
    match pr2 {
        AreProof::V2Stark(ref s) => assert!(verify_iface_replay(&li, &ri, s)),
        _ => panic!("expected V2Stark from prove_replay_from_children"),
    }
    assert!(verify_replay_from_children(&pi_l, &pi_r, &pr2));
}
