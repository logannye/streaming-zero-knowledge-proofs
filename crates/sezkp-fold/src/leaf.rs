//! Concrete Leaf gadget: π-consistency proof + transcript binding.
//!
//! Leaf commitment **must** match `sezkp_merkle::leaf_hash` exactly.
//! The proof consists of a micro-proof binding the π limbs + boundary digests
//! and an outer transcript MAC under `DS_LEAF` that binds
//! `(C, π-commitment, digests, proof)`.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use serde::{Deserialize, Serialize};
use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};
use sezkp_merkle::leaf_hash;

use crate::api::{commit_pi, Commitment, Leaf, PiCommitment, DS_LEAF};
use crate::are::Pi;

use sezkp_stark::v1::air::{prove_leaf_pi, verify_leaf_pi, PiPublic, StarkProofV1};
use sezkp_stark::v1::field::F1;

/// Proof object for the leaf.
///
/// - `public` are the public inputs seen by the micro-proof circuit
///   (π limbs + boundary digests).
/// - `proof` is the micro-proof attesting those public inputs.
/// - `mac` binds everything (including the micro-proof bytes) to the transcript
///   domain `DS_LEAF`, so the caller doesn't have to re-hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoLeafProof {
    /// Public inputs to LeafPiAir (π limbs + boundary digests).
    pub public: PiPublic,
    /// Micro-proof over `public`.
    pub proof: StarkProofV1,
    /// Outer transcript MAC under `DS_LEAF` (binds C, π-commitment, digests, proof).
    pub mac: [u8; 32],
}

/// Assemble a `Pi` from `PiPublic` (pack limbs into 4 F1 registers).
#[inline]
fn pi_from_public(p: &PiPublic) -> Pi {
    let mut pi = Pi::default();
    pi.ctrl_in = p.ctrl_in;
    pi.ctrl_out = p.ctrl_out;
    pi.flags = p.flags;
    for (i, limb) in p.acc_limbs.iter().copied().enumerate().take(4) {
        pi.acc[i] = F1::from_u64(limb);
    }
    pi
}

/// Concrete Leaf gadget (V2).
pub struct CryptoLeaf;

impl Leaf for CryptoLeaf {
    type Proof = CryptoLeafProof;

    fn prove_leaf(block: &BlockSummary) -> (Pi, Commitment, Self::Proof) {
        // 1) Inner micro-proof: produces public view + proof
        let (public, inner) = prove_leaf_pi(block).expect("leaf π proof");

        // 2) Assemble π from the public view
        let pi = pi_from_public(&public);

        // 3) Manifest-compatible commitment to the block's public shape
        let c = Commitment::new(leaf_hash(block), 1);

        // 4) Outer transcript MAC binding (C, π-commitment, boundary digests, micro-proof)
        let pi_cmt = commit_pi(&pi);
        let mut tr = Blake3Transcript::new(DS_LEAF);
        tr.absorb("c.root", &c.root);
        tr.absorb_u64("c.len", c.len as u64);
        tr.absorb("pi.commit", &pi_cmt.0);
        tr.absorb("left_tail", &public.left_tail_digest);
        tr.absorb("right_head", &public.right_head_digest);
        tr.absorb("leaf_pi.mac", &inner.mac);

        let mac_vec = tr.challenge_bytes("mac", 32);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_vec);

        (pi, c, CryptoLeafProof { public, proof: inner, mac })
    }

    // Verifier sees only the π commitment, not the raw π.
    fn verify_leaf(commit: &Commitment, pi_cmt: &PiCommitment, proof: &Self::Proof) -> bool {
        // 1) Reconstruct π from the public inputs and check its commitment.
        let pi_rebuilt = pi_from_public(&proof.public);
        if commit_pi(&pi_rebuilt) != *pi_cmt {
            return false;
        }

        // 2) Verify the inner micro-proof over the public inputs.
        if !verify_leaf_pi(&proof.public, &proof.proof) {
            return false;
        }

        // 3) Rebuild the outer transcript and check the MAC (binding to π commitment).
        let mut tr = Blake3Transcript::new(DS_LEAF);
        tr.absorb("c.root", &commit.root);
        tr.absorb_u64("c.len", commit.len as u64);
        tr.absorb("pi.commit", &pi_cmt.0);
        tr.absorb("left_tail", &proof.public.left_tail_digest);
        tr.absorb("right_head", &proof.public.right_head_digest);
        tr.absorb("leaf_pi.mac", &proof.proof.mac);

        let mac_vec = tr.challenge_bytes("mac", 32);
        mac_vec.as_slice() == &proof.mac
    }
}
