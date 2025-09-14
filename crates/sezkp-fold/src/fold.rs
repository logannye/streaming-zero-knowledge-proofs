//! Concrete Fold and Wrap gadgets (V2).

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

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_crypto::{Blake3Transcript, Transcript};

use crate::api::{Commitment, Fold as FoldT, Wrap as WrapT, DS_FOLD};
use crate::are::{CombineAux, InterfaceWitness, Pi};
use crate::are;
use crate::are_replay::{prove_replay_from_children, verify_replay_from_children, AreProof};

use sezkp_stark::v1::air::{prove_wrap_public, verify_wrap_public, WrapProofV1, WrapPublic};

/// Manifest/Merkle-compatible parent combiner:
/// root = blake3("sezkp/manifest/node/v1" || L.root || R.root)
/// len  = L.len + R.len   (length is tracked but not hashed)
#[inline]
fn combine_commitments(left: &Commitment, right: &Commitment) -> Commitment {
    let mut h = blake3::Hasher::new();
    h.update(&left.root);
    h.update(&right.root);
    let root = *h.finalize().as_bytes();
    Commitment::new(root, left.len + right.len)
}

/// Proof for a fold step: binds the interface + ARE proof + transcript MAC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoFoldProof {
    /// Interface bundle (for ctrl continuity and documentation).
    pub iface: InterfaceWitness,
    /// ARE replay proof (now V2 micro-STARK by default).
    pub are: AreProof,
    /// Transcript MAC over all public data for this fold.
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
        // 1) ARE over child π public bits.
        let are_proof = prove_replay_from_children(left.1, right.1, iface);

        // 2) Parent π via constant-degree combiner.
        let aux = CombineAux::default();
        let pi_par = are::combine(left.1, right.1, &aux);

        // 3) Parent commitment (manifest/merkle-compatible).
        let c_par = combine_commitments(left.0, right.0);

        // 4) Transcript MAC binds everything, incl. ARE public tuple + proof bytes.
        let le_to_u64 = |x: &sezkp_stark::v1::field::F1| u64::from_le_bytes(x.to_le_bytes());
        let l_rh0 = le_to_u64(&left.1.acc[2]);
        let l_rh1 = le_to_u64(&left.1.acc[3]);
        let r_lt0 = le_to_u64(&right.1.acc[0]);
        let r_lt1 = le_to_u64(&right.1.acc[1]);

        let mut tr = Blake3Transcript::new(DS_FOLD);
        // Left
        tr.absorb("L.c.root", &left.0.root);
        tr.absorb_u64("L.c.len", left.0.len as u64);
        tr.absorb_u64("L.pi.ctrl_in", left.1.ctrl_in as u64);
        tr.absorb_u64("L.pi.ctrl_out", left.1.ctrl_out as u64);
        tr.absorb_u64("L.pi.flags", left.1.flags as u64);
        for (i, a) in left.1.acc.iter().enumerate() {
            tr.absorb(&format!("L.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // Right
        tr.absorb("R.c.root", &right.0.root);
        tr.absorb_u64("R.c.len", right.0.len as u64);
        tr.absorb_u64("R.pi.ctrl_in", right.1.ctrl_in as u64);
        tr.absorb_u64("R.pi.ctrl_out", right.1.ctrl_out as u64);
        tr.absorb_u64("R.pi.flags", right.1.flags as u64);
        for (i, a) in right.1.acc.iter().enumerate() {
            tr.absorb(&format!("R.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // Parent
        tr.absorb("P.c.root", &c_par.root);
        tr.absorb_u64("P.c.len", c_par.len as u64);
        tr.absorb_u64("P.pi.ctrl_in", pi_par.ctrl_in as u64);
        tr.absorb_u64("P.pi.ctrl_out", pi_par.ctrl_out as u64);
        tr.absorb_u64("P.pi.flags", pi_par.flags as u64);
        for (i, a) in pi_par.acc.iter().enumerate() {
            tr.absorb(&format!("P.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // ARE public tuple + proof bytes
        tr.absorb_u64("ARE.li.ctrl_out", left.1.ctrl_out as u64);
        tr.absorb_u64("ARE.ri.ctrl_in", right.1.ctrl_in as u64);
        tr.absorb_u64("ARE.li.rh[0]", l_rh0);
        tr.absorb_u64("ARE.li.rh[1]", l_rh1);
        tr.absorb_u64("ARE.ri.lt[0]", r_lt0);
        tr.absorb_u64("ARE.ri.lt[1]", r_lt1);
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

    fn verify_fold(
        parent: (&Commitment, &Pi),
        left: (&Commitment, &Pi),
        right: (&Commitment, &Pi),
        proof: &Self::Proof,
    ) -> bool {
        // 1) Expected parent (must mirror combine_commitments).
        let expect = combine_commitments(left.0, right.0);
        if expect.root != parent.0.root || expect.len != parent.0.len {
            return false;
        }

        // 2) π-combination relation.
        let aux = CombineAux::default();
        let expect_pi = are::combine(left.1, right.1, &aux);
        if expect_pi != *parent.1 {
            return false;
        }

        // 3) Verify ARE.
        if !verify_replay_from_children(left.1, right.1, &proof.are) {
            return false;
        }

        // 4) Verify transcript MAC.
        let le_to_u64 = |x: &sezkp_stark::v1::field::F1| u64::from_le_bytes(x.to_le_bytes());
        let l_rh0 = le_to_u64(&left.1.acc[2]);
        let l_rh1 = le_to_u64(&left.1.acc[3]);
        let r_lt0 = le_to_u64(&right.1.acc[0]);
        let r_lt1 = le_to_u64(&right.1.acc[1]);

        let mut tr = Blake3Transcript::new(DS_FOLD);
        // Left
        tr.absorb("L.c.root", &left.0.root);
        tr.absorb_u64("L.c.len", left.0.len as u64);
        tr.absorb_u64("L.pi.ctrl_in", left.1.ctrl_in as u64);
        tr.absorb_u64("L.pi.ctrl_out", left.1.ctrl_out as u64);
        tr.absorb_u64("L.pi.flags", left.1.flags as u64);
        for (i, a) in left.1.acc.iter().enumerate() {
            tr.absorb(&format!("L.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // Right
        tr.absorb("R.c.root", &right.0.root);
        tr.absorb_u64("R.c.len", right.0.len as u64);
        tr.absorb_u64("R.pi.ctrl_in", right.1.ctrl_in as u64);
        tr.absorb_u64("R.pi.ctrl_out", right.1.ctrl_out as u64);
        tr.absorb_u64("R.pi.flags", right.1.flags as u64);
        for (i, a) in right.1.acc.iter().enumerate() {
            tr.absorb(&format!("R.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // Parent
        tr.absorb("P.c.root", &parent.0.root);
        tr.absorb_u64("P.c.len", parent.0.len as u64);
        tr.absorb_u64("P.pi.ctrl_in", parent.1.ctrl_in as u64);
        tr.absorb_u64("P.pi.ctrl_out", parent.1.ctrl_out as u64);
        tr.absorb_u64("P.pi.flags", parent.1.flags as u64);
        for (i, a) in parent.1.acc.iter().enumerate() {
            tr.absorb(&format!("P.pi.acc[{i}]"), &a.to_le_bytes());
        }
        // ARE public + proof bytes
        tr.absorb_u64("ARE.li.ctrl_out", left.1.ctrl_out as u64);
        tr.absorb_u64("ARE.ri.ctrl_in", right.1.ctrl_in as u64);
        tr.absorb_u64("ARE.li.rh[0]", l_rh0);
        tr.absorb_u64("ARE.li.rh[1]", l_rh1);
        tr.absorb_u64("ARE.ri.lt[0]", r_lt0);
        tr.absorb_u64("ARE.ri.lt[1]", r_lt1);
        let are_bytes = bincode::serialize(&proof.are).expect("serialize are_proof");
        tr.absorb("ARE.proof", &are_bytes);

        let mac_vec = tr.challenge_bytes("mac", 32);
        mac_vec.as_slice() == &proof.mac
    }
}

/* --------------------------------- Wrap V2 -------------------------------- */

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Proof for a wrap step: binds the interface + ARE proof + transcript MAC.
pub enum CryptoWrapProof {
    /// Transcript MAC that attests to (C_root, π_root) under `DS_WRAP`.
    V1Mac([u8; 32]),
    /// Preferred micro-proof (upgradeable to real micro-STARK).
    V2Stark(WrapProofV1),
}

/// Concrete Wrap gadget
pub struct CryptoWrap;

impl WrapT for CryptoWrap {
    type Proof = CryptoWrapProof;

    fn wrap(root: (&Commitment, &Pi)) -> Self::Proof {
        let le_to_u64 = |x: &sezkp_stark::v1::field::F1| u64::from_le_bytes(x.to_le_bytes());
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = le_to_u64(&root.1.acc[i]);
        }
        let p = WrapPublic {
            c_root: root.0.root,
            c_len: root.0.len,
            ctrl_in: root.1.ctrl_in,
            ctrl_out: root.1.ctrl_out,
            flags: root.1.flags,
            acc_limbs: limbs,
        };
        let pr = prove_wrap_public(&p).expect("wrap proof");
        CryptoWrapProof::V2Stark(pr)
    }

    fn verify_wrap(root: (&Commitment, &Pi), proof: &Self::Proof) -> bool {
        match proof {
            CryptoWrapProof::V2Stark(pr) => {
                let le_to_u64 = |x: &sezkp_stark::v1::field::F1| u64::from_le_bytes(x.to_le_bytes());
                let mut limbs = [0u64; 4];
                for i in 0..4 {
                    limbs[i] = le_to_u64(&root.1.acc[i]);
                }
                let p = WrapPublic {
                    c_root: root.0.root,
                    c_len: root.0.len,
                    ctrl_in: root.1.ctrl_in,
                    ctrl_out: root.1.ctrl_out,
                    flags: root.1.flags,
                    acc_limbs: limbs,
                };
                verify_wrap_public(&p, pr)
            }
            CryptoWrapProof::V1Mac(mac) => {
                let d = {
                    let mut h = Hasher::new();
                    h.update(&root.0.root);
                    h.update(&root.0.len.to_le_bytes());
                    h.update(&root.1.ctrl_in.to_le_bytes());
                    h.update(&root.1.ctrl_out.to_le_bytes());
                    h.update(&root.1.flags.to_le_bytes());
                    for a in &root.1.acc {
                        h.update(&a.to_le_bytes());
                    }
                    *h.finalize().as_bytes()
                };
                &d == mac
            }
        }
    }
}
