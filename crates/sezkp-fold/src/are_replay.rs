//! ARE (interface replay) proofs used during folding.
//!
//! This module maintains **two** wire-compatible proof variants:
//! - `V1Mac`: legacy Blake3 MAC over the interface witness (deprecated).
//! - `V2Stark`: preferred path using a tiny STARK over child π prefixes.
//!
//! Keeping both variants allows painless upgrades while preserving
//! forwards/backwards read-compat for artifacts.
//
//  Note: The streaming layer no longer exposes raw `π` on the wire; callers
//  should commit to `π` with `api::commit_pi` and carry the opaque commitment
//  alongside whichever ARE proof variant they use. Internally, verifiers will
//  still need access to the underlying `π` to check V2 proofs.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::are::{InterfaceWitness, Pi};
use sezkp_stark::v1::air::{
    prove_iface_replay, verify_iface_replay, AreProofStark, LeafIfacePublic,
};

/// Central domain separator for ARE (interface replay).
pub const DS_ARE: &str = "fold/are";
/// Back-compat DS for V1 MAC (legacy).
pub const DS_ARE_V1: &str = "fold/are/v1";
/// Version label for the Stark variant (kept here for clarity).
pub const DS_ARE_V2: &str = "fold/are/v2";

/// ARE proof encoding (wire-stable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AreProof {
    /// Deprecated; kept for backwards compatibility.
    V1Mac([u8; 32]),
    /// Preferred micro-proof (upgradeable to real micro-STARK).
    V2Stark(AreProofStark),
}

/* ------------------------------- V1 (MAC) ---------------------------------- */

/// Construct the legacy MAC over the interface witness (deprecated).
#[must_use]
pub fn prove_replay(iface: &InterfaceWitness) -> AreProof {
    let mut h = Hasher::new();
    h.update(DS_ARE_V1.as_bytes());
    h.update(&iface.left_ctrl_out.to_le_bytes());
    h.update(&iface.right_ctrl_in.to_le_bytes());
    h.update(&iface.boundary_writes_digest);
    AreProof::V1Mac(*h.finalize().as_bytes())
}

/// Verify the legacy MAC proof (deprecated).
#[must_use]
pub fn verify_replay(iface: &InterfaceWitness, proof: &AreProof) -> bool {
    match proof {
        AreProof::V1Mac(mac) => {
            let expect = prove_replay(iface);
            if let AreProof::V1Mac(expect_mac) = expect {
                mac == &expect_mac
            } else {
                false
            }
        }
        AreProof::V2Stark(_) => {
            // Newer proof variant not verifiable from InterfaceWitness alone.
            false
        }
    }
}

/* ------------------------- V2: child-π-backed path ------------------------- */

#[inline]
fn limbs_from_pi(pi: &Pi) -> ([u64; 2], [u64; 2]) {
    // Extract left-tail and right-head 2×u64 prefixes from π.acc.
    let le = |i: usize| u64::from_le_bytes(pi.acc[i].to_le_bytes());
    let lt = [le(0), le(1)]; // left-tail prefix (2 limbs)
    let rh = [le(2), le(3)]; // right-head prefix (2 limbs)
    (lt, rh)
}

/// Prove ARE interface from **children π** (preferred V2 path).
///
/// The STARK checks that `right.head_prefix == left.tail_prefix` and control
/// chaining is respected at the interface.
#[must_use]
pub fn prove_replay_from_children(left: &Pi, right: &Pi, _iface: &InterfaceWitness) -> AreProof {
    // rh(left) must equal lt(right)
    let (_lt_l, rh_l) = limbs_from_pi(left);
    let (lt_r, _rh_r) = limbs_from_pi(right);

    let li = LeafIfacePublic {
        l_tail_prefix: [0, 0], // not used from left side
        r_head_prefix: rh_l,
        ctrl_out: left.ctrl_out,
        ctrl_in: 0, // not used from left side
    };
    let ri = LeafIfacePublic {
        l_tail_prefix: lt_r,
        r_head_prefix: [0, 0], // not used from right side
        ctrl_out: 0, // not used from right side
        ctrl_in: right.ctrl_in,
    };

    let pr = prove_iface_replay(&li, &ri).expect("ARE iface proof");
    AreProof::V2Stark(pr)
}

/// Verify ARE interface from **children π** (preferred V2 path).
#[must_use]
pub fn verify_replay_from_children(left: &Pi, right: &Pi, proof: &AreProof) -> bool {
    let (_lt_l, rh_l) = limbs_from_pi(left);
    let (lt_r, _rh_r) = limbs_from_pi(right);

    let li = LeafIfacePublic {
        l_tail_prefix: [0, 0],
        r_head_prefix: rh_l,
        ctrl_out: left.ctrl_out,
        ctrl_in: 0,
    };
    let ri = LeafIfacePublic {
        l_tail_prefix: lt_r,
        r_head_prefix: [0, 0],
        ctrl_out: 0,
        ctrl_in: right.ctrl_in,
    };

    match proof {
        AreProof::V2Stark(p) => verify_iface_replay(&li, &ri, p),
        AreProof::V1Mac(_) => false,
    }
}
