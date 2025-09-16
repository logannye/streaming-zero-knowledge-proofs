//! Algebraic Replay Engine (ARE) primitives used by folding gadgets.
//!
//! Defines a tiny finite-state projection `Pi` and a constant-degree combiner
//! used at internal merge nodes. The unique interface is represented by
//! [`InterfaceWitness`] and checked via a lightweight replay proof from
//! [`crate::are_replay`] (legacy MAC or a small STARK).
//!
//! ## π semantics (frozen for v1)
//!
//! - `ctrl_in`, `ctrl_out`: reserved for A/B alignment (0 in this revision).
//! - `flags`: bit0 indicates that boundary digests are present in `acc`
//!   (as of v1, leaves set `flags |= 1`).
//! - `acc[0..4]`: four 64-bit little-endian limbs of a combined boundary
//!   digest (see docs/ARE). Packing both sides keeps the capsule fixed-width.

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

use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sezkp_stark::v1::field::F1;

use crate::are_replay::{prove_replay, verify_replay, AreProof};

/// Number of tiny field registers in [`Pi::acc`].
pub const Q: usize = 4;

/// Constant-size projection carried up the fold tree (see module docs for semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pi {
    /// A/B alignment.
    pub ctrl_in: u32,
    /// B/A alignment.
    pub ctrl_out: u32,
    /// Flags (bit 0 ⇒ boundary digests present).
    pub flags: u32,
    /// Small accumulator over boundary digests.
    pub acc: [F1; Q],
}

impl Default for Pi {
    #[inline]
    fn default() -> Self {
        Self {
            ctrl_in: 0,
            ctrl_out: 0,
            flags: 0,
            acc: [F1::from_u64(0); Q],
        }
    }
}

/// Aux data for constant-degree combination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CombineAux {
    /// Auxiliary gamma values added component-wise in the combiner.
    pub gamma: [F1; Q],
    /// Flag mask XOR-ed in the combiner.
    pub flag_mask: u32,
}

impl Default for CombineAux {
    #[inline]
    fn default() -> Self {
        Self {
            gamma: [F1::from_u64(0); Q],
            flag_mask: 0,
        }
    }
}

/// Constant-degree combiner `π_out = G(π_L, π_R; aux)`.
#[inline]
#[must_use]
pub fn combine(pi_l: &Pi, pi_r: &Pi, aux: &CombineAux) -> Pi {
    let mut acc = [F1::from_u64(0); Q];
    for i in 0..Q {
        acc[i] = pi_l.acc[i] + pi_r.acc[i] + aux.gamma[i];
    }
    Pi {
        ctrl_in: pi_l.ctrl_in,
        ctrl_out: pi_r.ctrl_out,
        flags: (pi_l.flags | pi_r.flags) ^ aux.flag_mask,
        acc,
    }
}

/// Witness for the unique interface replay between two subtrees/blocks.
///
/// Caller must ensure it represents the *single* boundary between the two
/// adjacent intervals being combined.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceWitness {
    /// Left-side control output.
    pub left_ctrl_out: u32,
    /// Right-side control input.
    pub right_ctrl_in: u32,
    /// Digest (e.g., BLAKE3) over boundary writes in the small replay window.
    pub boundary_writes_digest: [u8; 32],
}

impl InterfaceWitness {
    /// Create a trivial interface witness with the given control input/output.
    #[inline]
    #[must_use]
    pub fn trivial(ctrl: u32) -> Self {
        Self {
            left_ctrl_out: ctrl,
            right_ctrl_in: ctrl,
            boundary_writes_digest: [0u8; 32],
        }
    }
}

/// Result of an interface replay: boolean plus a proof payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Whether the interface is valid.
    pub ok: bool,
    /// Proof of the interface replay.
    pub proof: AreProof,
}

/// Prove the bounded interface and return `(result, merged_pi)`.
///
/// This is the producer-side path used during folding. The returned `Pi` is
/// the combined parent state (using a default `CombineAux`).
#[inline]
#[must_use]
pub fn replay_check_prove(pi_l: &Pi, pi_r: &Pi, iface: &InterfaceWitness) -> (ReplayResult, Pi) {
    let ctrl_ok = pi_l.ctrl_out == iface.left_ctrl_out && pi_r.ctrl_in == iface.right_ctrl_in;
    let proof = prove_replay(iface);
    let aux = CombineAux::default();
    let pi_out = combine(pi_l, pi_r, &aux);
    (ReplayResult { ok: ctrl_ok, proof }, pi_out)
}

/// Verify an interface replay result against the parent/children `Pi` states.
///
/// Returns `true` only if:
/// 1) the proof verifies against `iface`,
/// 2) `res.ok` is true (producer observed a valid interface), and
/// 3) the parent equals the deterministic combination of `(left,right)`.
#[inline]
#[must_use]
pub fn replay_check_verify(
    parent: &Pi,
    left: &Pi,
    right: &Pi,
    iface: &InterfaceWitness,
    res: &ReplayResult,
) -> bool {
    if !(res.ok && verify_replay(iface, &res.proof)) {
        return false;
    }
    let aux = CombineAux::default();
    let expect = combine(left, right, &aux);
    expect == *parent
}

/// Back-compat shim (kept until all gadgets use the split API).
#[inline]
#[must_use]
pub fn replay_check(pi_l: &Pi, pi_r: &Pi, iface: &InterfaceWitness) -> (bool, Pi) {
    let (res, pi_out) = replay_check_prove(pi_l, pi_r, iface);
    let ok = replay_check_verify(&pi_out, pi_l, pi_r, iface, &res);
    (ok, pi_out)
}

/* ---------------------- Manual serde for Pi / CombineAux ------------------- */

#[derive(Serialize, Deserialize)]
struct PiWire {
    ctrl_in: u32,
    ctrl_out: u32,
    flags: u32,
    acc: [[u8; 8]; Q],
}

impl Serialize for Pi {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut acc_le = [[0u8; 8]; Q];
        for i in 0..Q {
            acc_le[i] = self.acc[i].to_le_bytes();
        }
        PiWire {
            ctrl_in: self.ctrl_in,
            ctrl_out: self.ctrl_out,
            flags: self.flags,
            acc: acc_le,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Pi {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = PiWire::deserialize(d)?;
        let mut acc = [F1::from_u64(0); Q];
        for i in 0..Q {
            acc[i] = F1::from_u64(u64::from_le_bytes(w.acc[i]));
        }
        Ok(Pi {
            ctrl_in: w.ctrl_in,
            ctrl_out: w.ctrl_out,
            flags: w.flags,
            acc,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CombineAuxWire {
    gamma: [[u8; 8]; Q],
    flag_mask: u32,
}

impl Serialize for CombineAux {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut gamma_le = [[0u8; 8]; Q];
        for i in 0..Q {
            gamma_le[i] = self.gamma[i].to_le_bytes();
        }
        CombineAuxWire {
            gamma: gamma_le,
            flag_mask: self.flag_mask,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for CombineAux {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = CombineAuxWire::deserialize(d)?;
        let mut gamma = [F1::from_u64(0); Q];
        for i in 0..Q {
            gamma[i] = F1::from_u64(u64::from_le_bytes(w.gamma[i]));
        }
        Ok(CombineAux {
            gamma,
            flag_mask: w.flag_mask,
        })
    }
}

/* --------- Optional helpers: raw (de)serialization of small F1 vectors ----- */

/// Serialize a small vector of [`F1`] to a writer (little-endian u64 words).
pub fn serialize_f1_vec<W: std::io::Write>(a: &[F1], mut s: W) -> Result<()> {
    let len = a.len() as u32;
    s.write_all(&len.to_le_bytes())?;
    for &x in a {
        let le: [u8; 8] = x.to_le_bytes();
        s.write_all(&le)?;
    }
    Ok(())
}

/// Deserialize a small vector of [`F1`] from a reader (little-endian u64 words).
pub fn deserialize_f1_vec<R: std::io::Read>(mut d: R) -> Result<Vec<F1>> {
    let mut len_buf = [0u8; 4];
    d.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let mut buf8 = [0u8; 8];
        d.read_exact(&mut buf8)?;
        out.push(F1::from_u64(u64::from_le_bytes(buf8)));
    }
    Ok(out)
}
