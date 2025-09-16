//! Concrete Fold and Wrap gadgets (V2).
//!
//! Verifiers consume only **π commitments** (opaque on the wire). The prover
//! binds those commitments into the transcript, so streaming verification never
//! needs to observe raw π internals.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_variables)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use serde::{Deserialize, Serialize};
use sezkp_crypto::{Blake3Transcript, Transcript};
use blake3::Hasher;

use crate::api::{
    commit_pi, Commitment, Fold as FoldT, PiCommitment, Wrap as WrapT, DS_FOLD, DS_WRAP,
};
use crate::are::{self, CombineAux, InterfaceWitness, Pi};
use crate::are_replay::{prove_replay_from_children, AreProof};

/// Manifest/Merkle-compatible parent combiner.
/// We must match the canonical combiner used by the manifest builder.
#[inline]
fn combine_commitments(left: &Commitment, right: &Commitment) -> Commitment {
    // MUST mirror sezkp_merkle::merkle_parent: BLAKE3( left || right )
    let mut h = Hasher::new();
    h.update(&left.root);
    h.update(&right.root);
    let root = *h.finalize().as_bytes();
    Commitment::new(root, left.len + right.len)
}

/// Proof for a fold step: binds the interface, ARE proof, and a transcript MAC.
///
/// Note: the ARE proof is presently a micro-proof placeholder. The MAC binds
/// the π **commitments** of (left, right, parent) so verifiers only need those.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoFoldProof {
    /// Interface bundle (for ctrl continuity and documentation).
    pub iface: InterfaceWitness,
    /// ARE replay proof (encoded; currently not re-verified from commitments).
    pub are: AreProof,
    /// Transcript MAC over all public data for this fold, including π commits.
    pub mac: [u8; 32],
}

/// Concrete Fold gadget (V2).
pub struct CryptoFold;

impl FoldT for CryptoFold {
    type Proof = CryptoFoldProof;

    fn fold(
        left: (&Commitment, &Pi),
        right: (&Commitment, &Pi),
        iface: &InterfaceWitness,
    ) -> (Commitment, Pi, Self::Proof) {
        // 1) ARE over child π public bits (prover side).
        let are_proof = prove_replay_from_children(left.1, right.1, iface);

        // 2) Parent π via constant-degree combiner.
        let aux = CombineAux::default();
        let pi_par = are::combine(left.1, right.1, &aux);

        // 3) Parent commitment (manifest/merkle-compatible).
        let c_par = combine_commitments(left.0, right.0);

        // 4) Transcript MAC binds *(C, π-commit)* for L/R/Parent + interface + ARE bytes.
        let l_pi_cmt = commit_pi(left.1);
        let r_pi_cmt = commit_pi(right.1);
        let p_pi_cmt = commit_pi(&pi_par);

        let mut tr = Blake3Transcript::new(DS_FOLD);
        // Left
        tr.absorb("L.c.root", &left.0.root);
        tr.absorb_u64("L.c.len", left.0.len as u64);
        tr.absorb("L.pi.commit", &l_pi_cmt.0);
        // Right
        tr.absorb("R.c.root", &right.0.root);
        tr.absorb_u64("R.c.len", right.0.len as u64);
        tr.absorb("R.pi.commit", &r_pi_cmt.0);
        // Parent
        tr.absorb("P.c.root", &c_par.root);
        tr.absorb_u64("P.c.len", c_par.len as u64);
        tr.absorb("P.pi.commit", &p_pi_cmt.0);
        // Interface + ARE proof bytes
        tr.absorb_u64("iface.left_ctrl_out", iface.left_ctrl_out as u64);
        tr.absorb_u64("iface.right_ctrl_in", iface.right_ctrl_in as u64);
        tr.absorb("iface.boundary_digest", &iface.boundary_writes_digest);
        let are_bytes = bincode::serialize(&are_proof).expect("serialize are_proof");
        tr.absorb("ARE.proof", &are_bytes);

        let mac_vec = tr.challenge_bytes("mac", 32);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_vec);

        (
            c_par,
            pi_par,
            CryptoFoldProof {
                iface: iface.clone(),
                are: are_proof,
                mac,
            },
        )
    }

    // Verifiers receive only π commitments on the wire.
    fn verify_fold(
        parent: (&Commitment, &PiCommitment),
        left: (&Commitment, &PiCommitment),
        right: (&Commitment, &PiCommitment),
        proof: &Self::Proof,
    ) -> bool {
        // 1) Parent commitment must match the Merkle combiner of children.
        let expect = combine_commitments(left.0, right.0);
        if expect.root != parent.0.root || expect.len != parent.0.len {
            return false;
        }

        // 2) Recompute the transcript MAC using only commitments and public interface.
        let mut tr = Blake3Transcript::new(DS_FOLD);
        // Left
        tr.absorb("L.c.root", &left.0.root);
        tr.absorb_u64("L.c.len", left.0.len as u64);
        tr.absorb("L.pi.commit", &left.1 .0);
        // Right
        tr.absorb("R.c.root", &right.0.root);
        tr.absorb_u64("R.c.len", right.0.len as u64);
        tr.absorb("R.pi.commit", &right.1 .0);
        // Parent
        tr.absorb("P.c.root", &parent.0.root);
        tr.absorb_u64("P.c.len", parent.0.len as u64);
        tr.absorb("P.pi.commit", &parent.1 .0);
        // Interface + ARE
        tr.absorb_u64("iface.left_ctrl_out", proof.iface.left_ctrl_out as u64);
        tr.absorb_u64("iface.right_ctrl_in", proof.iface.right_ctrl_in as u64);
        tr.absorb("iface.boundary_digest", &proof.iface.boundary_writes_digest);
        let are_bytes = bincode::serialize(&proof.are).expect("serialize are_proof");
        tr.absorb("ARE.proof", &are_bytes);

        let mac_vec = tr.challenge_bytes("mac", 32);
        mac_vec.as_slice() == &proof.mac
    }
}

/* --------------------------------- Wrap V2 -------------------------------- */

/// Proof for a wrap step over `(C_root, π_root)`.
///
/// For streaming verification we stick to a MAC that binds the **π commitment**
/// (opaque) together with the commitment `C_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CryptoWrapProof {
    /// Transcript MAC that attests to `(C_root, π_commit)` under a wrap DS.
    V1Mac([u8; 32]),
    /// (Optional) micro-proof placeholder kept for future upgrades.
    V2Stark(()),
}

/// Concrete Wrap gadget.
pub struct CryptoWrap;

impl WrapT for CryptoWrap {
    type Proof = CryptoWrapProof;

    fn wrap(root: (&Commitment, &Pi)) -> Self::Proof {
        // Bind the π **commitment** into the MAC so verifiers don't need raw π.
        let pi_cmt = commit_pi(root.1);
        let mut tr = Blake3Transcript::new(DS_WRAP);
        tr.absorb("c.root", &root.0.root);
        tr.absorb_u64("c.len", root.0.len as u64);
        tr.absorb("pi.commit", &pi_cmt.0);
        let mac = {
            let v = tr.challenge_bytes("mac", 32);
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            out
        };
        CryptoWrapProof::V1Mac(mac)
    }

    fn verify_wrap(root: (&Commitment, &PiCommitment), proof: &Self::Proof) -> bool {
        match proof {
            CryptoWrapProof::V1Mac(mac) => {
                let mut tr = Blake3Transcript::new(DS_WRAP);
                tr.absorb("c.root", &root.0.root);
                tr.absorb_u64("c.len", root.0.len as u64);
                tr.absorb("pi.commit", &root.1 .0);
                let v = tr.challenge_bytes("mac", 32);
                v.as_slice() == mac
            }
            CryptoWrapProof::V2Stark(_) => {
                // No raw π available to reconstruct public inputs; reject for now.
                false
            }
        }
    }
}
