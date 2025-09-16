//! Basic “harness” tests for ARE and `Pi` serialization.
//!
//! What we check here:
//! - V1 (MAC) ARE proofs round-trip and detect tampering.
//! - `Pi` (the tiny finite-state capsule) serializes/deserializes cleanly.

#![deny(rust_2018_idioms)]

use sezkp_fold::are::{InterfaceWitness, Pi};
use sezkp_fold::are_replay::{prove_replay, verify_replay};

/// Serialize an ARE proof to bytes (bincode).
#[inline]
fn are_bytes(pr: &sezkp_fold::are_replay::AreProof) -> Vec<u8> {
    bincode::serialize(pr).expect("serialize are proof")
}

/// Produce a tampered ARE proof by flipping a byte in the encoded payload.
/// Falls back to perturbing the first byte of the V1 MAC if deserialization
/// of the flipped buffer fails.
fn tamper_are(pr: &sezkp_fold::are_replay::AreProof) -> sezkp_fold::are_replay::AreProof {
    let mut b = are_bytes(pr);
    if !b.is_empty() {
        b[0] ^= 1;
    }
    bincode::deserialize(&b).unwrap_or_else(|_| {
        match pr {
            sezkp_fold::are_replay::AreProof::V1Mac(m) => {
                let mut x = *m;
                x[0] ^= 1;
                sezkp_fold::are_replay::AreProof::V1Mac(x)
            }
            // If more variants are added in the future, skip tampering here.
            _ => pr.clone(),
        }
    })
}

#[test]
fn are_mac_roundtrip_ok() {
    let iface = InterfaceWitness {
        left_ctrl_out: 7,
        right_ctrl_in: 7,
        boundary_writes_digest: [42u8; 32],
    };

    // Legacy MAC-style proof must verify against the same witness.
    let pr = prove_replay(&iface);
    assert!(verify_replay(&iface, &pr));
}

#[test]
fn are_mac_detects_mutation() {
    let iface = InterfaceWitness {
        left_ctrl_out: 7,
        right_ctrl_in: 7,
        boundary_writes_digest: [42u8; 32],
    };

    // Perturb the proof; verification should fail.
    let pr = prove_replay(&iface);
    let pr = tamper_are(&pr);
    assert!(!verify_replay(&iface, &pr));
}

#[test]
fn pi_serde_roundtrip() {
    // Round-trip a Pi via bincode (covers the custom wire format).
    let mut pi = Pi::default();
    pi.ctrl_in = 1;
    pi.ctrl_out = 2;
    pi.flags = 0x55AA_F00D;

    let bytes = bincode::serialize(&pi).expect("serialize Pi");
    let pi2: Pi = bincode::deserialize(&bytes).expect("deserialize Pi");
    assert_eq!(pi, pi2);
}
