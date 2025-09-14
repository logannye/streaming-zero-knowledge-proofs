#![deny(rust_2018_idioms)]

use sezkp_fold::are::{InterfaceWitness, Pi};
use sezkp_fold::are_replay::{prove_replay, verify_replay};

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
fn are_mac_roundtrip_ok() {
    let iface = InterfaceWitness {
        left_ctrl_out: 7,
        right_ctrl_in: 7,
        boundary_writes_digest: [42u8; 32],
    };
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
    let pr = prove_replay(&iface);
    let pr = tamper_are(&pr);
    assert!(!verify_replay(&iface, &pr));
}

#[test]
fn pi_serde_roundtrip() {
    // Round-trip a Pi via bincode (through manual wire).
    let mut pi = Pi::default();
    pi.ctrl_in = 1;
    pi.ctrl_out = 2;
    pi.flags = 0x55AA_F00D;
    let bytes = bincode::serialize(&pi).unwrap();
    let pi2: Pi = bincode::deserialize(&bytes).unwrap();
    assert_eq!(pi, pi2);
}
