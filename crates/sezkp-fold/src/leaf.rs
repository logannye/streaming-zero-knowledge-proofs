//! Concrete Leaf gadget: π-consistency proof + transcript binding.
//!
//! Leaf commitment **must** match `sezkp-merkle::leaf_hash` exactly:
//!   - raw little-endian fields in the same order
//!   - windows.len() then each {left,right}
//!   - head_in_offsets values, then head_out_offsets values (no lengths)
//!   - movement_log.steps.len()
//!   - NO domain tag, NO CBOR, NO pre/post tags
//!
//! The proof consists of a micro-proof binding the π limbs + boundary digests
//! and an outer transcript MAC under `DS_LEAF` that binds (C, π, digests, proof).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};

use crate::api::{Commitment, Leaf, DS_LEAF};
use crate::are::Pi;

use sezkp_stark::v1::air::{prove_leaf_pi, verify_leaf_pi, PiPublic, StarkProofV1};
use sezkp_stark::v1::field::F1;

/// Proof object for the leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoLeafProof {
    /// Public inputs to LeafPiAir (π limbs + boundary digests)
    pub public: PiPublic,
    /// Compact commitment (MAC) to `public`
    pub proof: StarkProofV1,
    /// Outer transcript MAC under `DS_LEAF` (binds C, π, digests, proof)
    pub mac: [u8; 32],
}

/// Byte-for-byte replica of `sezkp_merkle::leaf_hash`.
fn commit_block(block: &BlockSummary) -> [u8; 32] {
    let mut h = Hasher::new();

    // Core scalars
    h.update(&block.version.to_le_bytes());   // u16
    h.update(&block.block_id.to_le_bytes());  // u32
    h.update(&block.step_lo.to_le_bytes());   // u64
    h.update(&block.step_hi.to_le_bytes());   // u64
    h.update(&block.ctrl_in.to_le_bytes());   // u16
    h.update(&block.ctrl_out.to_le_bytes());  // u16
    h.update(&block.in_head_in.to_le_bytes());  // i64
    h.update(&block.in_head_out.to_le_bytes()); // i64

    // Windows: length, then each (left, right)
    h.update(&(block.windows.len() as u64).to_le_bytes());
    for w in &block.windows {
        h.update(&w.left.to_le_bytes());   // i64
        h.update(&w.right.to_le_bytes());  // i64
    }

    // Head offsets: values only (no lengths)
    for &x in &block.head_in_offsets {
        h.update(&x.to_le_bytes()); // u32
    }
    for &x in &block.head_out_offsets {
        h.update(&x.to_le_bytes()); // u32
    }

    // Movement log length (bind geometry only, not the log contents)
    h.update(&(block.movement_log.steps.len() as u64).to_le_bytes());

    *h.finalize().as_bytes()
}

/// Assemble a `Pi` from `PiPublic` (pack limbs into 4 F1 registers).
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

/// Rebuild the public π view from a `Pi` (extract the 4 limbs).
fn public_from_pi(pi: &Pi, left_tail_digest: [u8; 32], right_head_digest: [u8; 32]) -> PiPublic {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(pi.acc[i].to_le_bytes());
    }
    PiPublic {
        ctrl_in: pi.ctrl_in,
        ctrl_out: pi.ctrl_out,
        flags: pi.flags,
        acc_limbs: limbs,
        left_tail_digest,
        right_head_digest,
    }
}

/// Concrete Leaf gadget.
pub struct CryptoLeaf;

impl Leaf for CryptoLeaf {
    type Proof = CryptoLeafProof;

    fn prove_leaf(block: &BlockSummary) -> (Pi, Commitment, Self::Proof) {
        // 1) Inner micro-proof: produces public view + MAC
        let (public, inner) = prove_leaf_pi(block).expect("leaf π proof");

        // 2) Assemble π from the public view (independent prefixes already packed)
        let pi = pi_from_public(&public);

        // 3) Manifest-compatible commitment to the block's public shape
        let c = Commitment::new(commit_block(block), 1);

        // 4) Outer transcript MAC binding (C, π, boundary digests, inner proof MAC)
        let mut tr = Blake3Transcript::new(DS_LEAF);
        tr.absorb("c.root", &c.root);
        tr.absorb_u64("c.len", c.len as u64);
        tr.absorb_u64("pi.ctrl_in", pi.ctrl_in as u64);
        tr.absorb_u64("pi.ctrl_out", pi.ctrl_out as u64);
        tr.absorb_u64("pi.flags", pi.flags as u64);
        for (i, a) in pi.acc.iter().enumerate() {
            tr.absorb(&format!("pi.acc[{i}]"), &a.to_le_bytes());
        }
        tr.absorb("left_tail", &public.left_tail_digest);
        tr.absorb("right_head", &public.right_head_digest);
        tr.absorb("leaf_pi.mac", &inner.mac);

        let mac_vec = tr.challenge_bytes("mac", 32);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_vec);

        (pi, c, CryptoLeafProof { public, proof: inner, mac })
    }

    fn verify_leaf(commit: &Commitment, pi: &Pi, proof: &Self::Proof) -> bool {
        // 1) Public view must match the provided π limbs/flags/ctrl_*.
        let rebuilt = public_from_pi(
            pi,
            proof.public.left_tail_digest,
            proof.public.right_head_digest,
        );
        if rebuilt != proof.public {
            return false;
        }

        // 2) Verify the inner micro-proof over the public inputs.
        if !verify_leaf_pi(&proof.public, &proof.proof) {
            return false;
        }

        // 3) Rebuild the outer transcript and check the MAC.
        let mut tr = Blake3Transcript::new(DS_LEAF);
        tr.absorb("c.root", &commit.root);
        tr.absorb_u64("c.len", commit.len as u64);
        tr.absorb_u64("pi.ctrl_in", pi.ctrl_in as u64);
        tr.absorb_u64("pi.ctrl_out", pi.ctrl_out as u64);
        tr.absorb_u64("pi.flags", pi.flags as u64);
        for (i, a) in pi.acc.iter().enumerate() {
            tr.absorb(&format!("pi.acc[{i}]"), &a.to_le_bytes());
        }
        tr.absorb("left_tail", &proof.public.left_tail_digest);
        tr.absorb("right_head", &proof.public.right_head_digest);
        tr.absorb("leaf_pi.mac", &proof.proof.mac);

        let mac_vec = tr.challenge_bytes("mac", 32);
        mac_vec.as_slice() == &proof.mac
    }
}
