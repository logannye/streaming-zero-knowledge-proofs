//! AIR constraints for v1.
//!
//! This file keeps the original (row/boundary) composition helpers and
//! adds two micro proofs (MAC-backed placeholders, upgradeable to real
//! micro-STARKs without changing call sites from the folding line):
//!
//!  1) **LeafPiAir** — binds a leaf's π capsule to its per-block boundary
//!     digests. (Already present; adjusted packing to expose each digest.)
//!
//!  2) **AreIfaceAir** — binds the **interface** between siblings using
//!     only public bits exported by leaves (no reaccess to blocks).
//!
//!  3) **WrapAir** — succinct attestation for (C_root, π_root).
//!
//! NOTE: Each proof below is a compact commitment (MAC). Upgrading to a
//! micro-STARK keeps the same public input structs and helper functions.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::v1::columns::{
    boundary_left_tail_digest, boundary_right_head_digest, IFACE_WINDOW_STEPS, TraceColumns,
    HEAD_BITS, SYM_BITS,
};
use crate::v1::field::F1;
// For openings-only evaluation.
use crate::v1::proof::RowOpenings;

/* ---------------------- Original composition helpers (kept) ---------------- */

#[inline]
fn f1(x: u64) -> F1 {
    F1::from_u64(x)
}

/// Transition composition at row i: Σ_j α_j · C_j(i) using full columns.
pub fn compose_row(tc: &TraceColumns, i: usize, a: &Alphas) -> F1 {
    let mut acc = F1::from_u64(0);
    let two = f1(2);

    for r in 0..tc.tau {
        let mv = tc.mv[r][i];
        let flg = tc.write_flag[r][i];
        let head = tc.head[r][i];

        // next row index (wrap).
        let ip1 = (i + 1) % tc.n;
        let head_next = tc.head[r][ip1];
        let mv_next = tc.mv[r][ip1]; // because `head` is post-move

        // C1: boolean flag
        acc += a.bool_flag * flg * (flg - f1(1));

        // C2: mv in {-1,0,1}
        acc += a.mv_domain * mv * (mv - f1(1)) * (mv + f1(1));

        // C3: head update (masked by !is_last)
        let one_minus_last = f1(1) - tc.is_last[i];
        acc += a.head_update * one_minus_last * (head_next - head - mv_next);

        // -------- Range via bit-decomp (guarded by flg) ----------
        // Reconstruct head from bits
        let mut head_bits_sum = F1::from_u64(0);
        let mut hb_bool = F1::from_u64(0);
        let mut pow = F1::from_u64(1);
        for k in 0..HEAD_BITS {
            let b = tc.head_bits[r][k][i];
            hb_bool += b * (b - f1(1));
            head_bits_sum += b * pow;
            pow *= f1(2);
        }
        acc += a.head_bits_bool * flg * hb_bool;
        acc += a.head_reconstruct * flg * (head - head_bits_sum);

        // slack = (win_len - 1) - head reconstructed from bits
        let mut slack_bits_sum = F1::from_u64(0);
        let mut sb_bool = F1::from_u64(0);
        let mut pow2 = F1::from_u64(1);
        for k in 0..HEAD_BITS {
            let b = tc.slack_bits[r][k][i];
            sb_bool += b * (b - f1(1));
            slack_bits_sum += b * pow2;
            pow2 *= f1(2);
        }
        let slack = tc.win_len[r][i] - f1(1) - head;
        acc += a.slack_bits_bool * flg * sb_bool;
        acc += a.slack_reconstruct * flg * (slack - slack_bits_sum);

        // Symbol 4-bit decomposition
        let mut sym_bits_sum = F1::from_u64(0);
        let mut sbits_bool = F1::from_u64(0);
        let mut pow4 = F1::from_u64(1);
        for k in 0..SYM_BITS {
            let b = tc.sym_bits[r][k][i];
            sbits_bool += b * (b - f1(1));
            sym_bits_sum += b * pow4;
            pow4 *= f1(2);
        }
        acc += a.sym_bits_bool * flg * sbits_bool;
        acc += a.sym_reconstruct * flg * (tc.write_sym[r][i] - sym_bits_sum);
    }

    acc
}

/// Boundary composition at row i (per tape, masked by is_first/is_last) using full columns.
pub fn compose_boundary(tc: &TraceColumns, i: usize, a: &Alphas) -> F1 {
    let mut acc = F1::from_u64(0);
    let is_first = tc.is_first[i];
    let is_last = tc.is_last[i];

    for r in 0..tc.tau {
        let head = tc.head[r][i];
        let mv = tc.mv[r][i];
        let off_in = tc.in_off[r][i];
        let off_out = tc.out_off[r][i];

        // First row: head - mv == off_in
        acc += a.boundary_first * is_first * (head - mv - off_in);
        // Last row: head == off_out
        acc += a.boundary_last * is_last * (head - off_out);
    }
    acc
}

/// LDE composition over a blowup-extended domain by periodicity (prototype).
pub fn compose_lde(tc: &TraceColumns, a: &Alphas, blow_log2: usize) -> Vec<F1> {
    let base_n = tc.n;
    let lde_n = base_n << blow_log2;
    let mut out = Vec::with_capacity(lde_n);
    for i in 0..lde_n {
        let base = i % base_n;
        out.push(compose_row(tc, base, a) + compose_boundary(tc, base, a));
    }
    out
}

/* ---------- Step 1: openings-backed evaluation (no local recompute) --------- */

#[inline]
pub fn f_from_le(le: [u8; 8]) -> F1 {
    F1::from_u64(u64::from_le_bytes(le))
}

#[derive(Clone, Debug)]
pub struct TapeOpenView {
    pub mv: F1,
    pub next_mv: F1,
    pub write_flag: F1,
    pub write_sym: F1,
    pub head: F1,
    pub next_head: F1,
    pub win_len: F1,
    pub in_off: F1,
    pub out_off: F1,
}

#[derive(Clone, Debug)]
pub struct RowView {
    pub row: usize,
    pub tau: usize,
    pub is_first: F1,
    pub is_last: F1,
    pub input_mv: F1,
    pub tapes: Vec<TapeOpenView>,
}

impl RowView {
    #[must_use]
    pub fn from_openings(q: &RowOpenings) -> Self {
        let mut tapes = Vec::with_capacity(q.per_tape.len());
        for t in &q.per_tape {
            tapes.push(TapeOpenView {
                mv: f_from_le(t.mv.value_le),
                next_mv: f_from_le(t.next_mv.value_le),
                write_flag: f_from_le(t.write_flag.value_le),
                write_sym: f_from_le(t.write_sym.value_le),
                head: f_from_le(t.head.value_le),
                next_head: f_from_le(t.next_head.value_le),
                win_len: f_from_le(t.win_len.value_le),
                in_off: f_from_le(t.in_off.value_le),
                out_off: f_from_le(t.out_off.value_le),
            });
        }
        Self {
            row: q.row,
            tau: q.per_tape.len(),
            is_first: f_from_le(q.is_first.value_le),
            is_last: f_from_le(q.is_last.value_le),
            input_mv: f_from_le(q.input_mv.value_le),
            tapes,
        }
    }
}

#[must_use]
pub fn compose_row_from_openings(view: &RowView, a: &Alphas) -> F1 {
    let mut acc = F1::from_u64(0);

    for t in &view.tapes {
        let mv = t.mv;
        let flg = t.write_flag;
        let head = t.head;
        let head_next = t.next_head;

        acc += a.bool_flag * flg * (flg - f1(1));
        acc += a.mv_domain * mv * (mv - f1(1)) * (mv + f1(1));
        let one_minus_last = f1(1) - view.is_last;
        acc += a.head_update * one_minus_last * (head_next - head - t.next_mv);
    }

    acc
}

#[must_use]
pub fn compose_boundary_from_openings(view: &RowView, a: &Alphas) -> F1 {
    let mut acc = F1::from_u64(0);
    let is_first = view.is_first;
    let is_last = view.is_last;

    for t in &view.tapes {
        acc += a.boundary_first * is_first * (t.head - t.mv - t.in_off);
        acc += a.boundary_last * is_last * (t.head - t.out_off);
    }
    acc
}

/// Evaluate the (opened) composition at an x and fold with an OOD point z.
#[must_use]
pub fn deep_evaluate_row_from_openings(view: &RowView, x: F1, z: F1, a: &Alphas) -> F1 {
    let c = compose_row_from_openings(view, a) + compose_boundary_from_openings(view, a);
    let denom = x - z;
    c * denom.inv()
}

#[derive(Clone, Debug)]
pub struct Alphas {
    pub bool_flag: F1,
    pub mv_domain: F1,
    pub head_update: F1,
    pub head_bits_bool: F1,
    pub head_reconstruct: F1,
    pub slack_bits_bool: F1,
    pub slack_reconstruct: F1,
    pub sym_bits_bool: F1,
    pub sym_reconstruct: F1,
    pub boundary_first: F1,
    pub boundary_last: F1,
}

/* --------------------------- LeafPiAir (micro) ----------------------------- */

/// Domain separator for the Leaf π micro-proof.
pub const DS_LEAF_PI_V1: &str = "stark/leaf_pi/v1";

/// Public inputs for LeafPiAir.
///
/// NOTE: `acc_limbs` now **exposes each digest** as two u64 limbs (LSB-first):
///   acc_limbs = [ L_tail[0..8], L_tail[8..16], R_head[0..8], R_head[8..16] ].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiPublic {
    pub ctrl_in: u32,
    pub ctrl_out: u32,
    pub flags: u32,
    pub acc_limbs: [u64; 4],
    pub left_tail_digest: [u8; 32],
    pub right_head_digest: [u8; 32],
}

/// Minimal proof object (MAC over the public inputs).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StarkProofV1 {
    pub mac: [u8; 32],
}

/// Helper: pack boundary digests as 4 limbs (two limbs per digest, LSB-first).
#[must_use]
pub fn pack_boundary_limbs(left: [u8; 32], right: [u8; 32]) -> [u64; 4] {
    let mut get2 = |d: [u8; 32]| -> [u64; 2] {
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        a.copy_from_slice(&d[0..8]);
        b.copy_from_slice(&d[8..16]);
        [u64::from_le_bytes(a), u64::from_le_bytes(b)]
    };
    let l2 = get2(left);
    let r2 = get2(right);
    [l2[0], l2[1], r2[0], r2[1]]
}

/// Produce a public view and a compact commitment (MAC) to it.
pub fn prove_leaf_pi(block: &sezkp_core::BlockSummary) -> anyhow::Result<(PiPublic, StarkProofV1)> {
    let l_tail = boundary_left_tail_digest(block, IFACE_WINDOW_STEPS);
    let r_head = boundary_right_head_digest(block, IFACE_WINDOW_STEPS);

    let limbs = pack_boundary_limbs(l_tail, r_head);
    let public = PiPublic {
        ctrl_in: 0,
        ctrl_out: 0,
        flags: 1, // leaf-present + boundary-packed
        acc_limbs: limbs,
        left_tail_digest: l_tail,
        right_head_digest: r_head,
    };

    let mut h = Hasher::new();
    h.update(DS_LEAF_PI_V1.as_bytes());
    h.update(&public.ctrl_in.to_le_bytes());
    h.update(&public.ctrl_out.to_le_bytes());
    h.update(&public.flags.to_le_bytes());
    for limb in public.acc_limbs {
        h.update(&limb.to_le_bytes());
    }
    h.update(&public.left_tail_digest);
    h.update(&public.right_head_digest);
    let proof = StarkProofV1 {
        mac: *h.finalize().as_bytes(),
    };

    Ok((public, proof))
}

/// Verify the compact commitment (MAC) against the public inputs.
#[must_use]
pub fn verify_leaf_pi(public: &PiPublic, proof: &StarkProofV1) -> bool {
    let mut h = Hasher::new();
    h.update(DS_LEAF_PI_V1.as_bytes());
    h.update(&public.ctrl_in.to_le_bytes());
    h.update(&public.ctrl_out.to_le_bytes());
    h.update(&public.flags.to_le_bytes());
    for limb in public.acc_limbs {
        h.update(&limb.to_le_bytes());
    }
    h.update(&public.left_tail_digest);
    h.update(&public.right_head_digest);
    proof.mac == *h.finalize().as_bytes()
}

/* ---------------------------- AreIfaceAir (micro) -------------------------- */

/// Domain separator for the ARE interface micro-proof.
pub const DS_ARE_V2: &str = "stark/are_iface/v2";

/// Public bits exported by a leaf/subtree for the interface check.
/// We re-use a single struct; `prove_iface_replay` will consume:
///   - from `li`: `r_head_prefix`, `ctrl_out`
///   - from `ri`: `l_tail_prefix`, `ctrl_in`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafIfacePublic {
    pub l_tail_prefix: [u64; 2],
    pub r_head_prefix: [u64; 2],
    pub ctrl_out: u32,
    pub ctrl_in: u32,
}

/// Minimal ARE proof object (MAC over the public tuple).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AreProofStark {
    pub mac: [u8; 32],
}

/// Prove the sibling interface from public leaf/subtree views.
pub fn prove_iface_replay(li: &LeafIfacePublic, ri: &LeafIfacePublic) -> anyhow::Result<AreProofStark> {
    // Bind exactly the tuple the verifier will check.
    let mut h = Hasher::new();
    h.update(DS_ARE_V2.as_bytes());
    for x in li.r_head_prefix { h.update(&x.to_le_bytes()); }
    h.update(&li.ctrl_out.to_le_bytes());
    for x in ri.l_tail_prefix { h.update(&x.to_le_bytes()); }
    h.update(&ri.ctrl_in.to_le_bytes());
    Ok(AreProofStark { mac: *h.finalize().as_bytes() })
}

/// Verify the sibling interface proof.
pub fn verify_iface_replay(li: &LeafIfacePublic, ri: &LeafIfacePublic, p: &AreProofStark) -> bool {
    // Enforce control continuity at verification time.
    if li.ctrl_out != ri.ctrl_in {
        return false;
    }
    let mut h = Hasher::new();
    h.update(DS_ARE_V2.as_bytes());
    for x in li.r_head_prefix { h.update(&x.to_le_bytes()); }
    h.update(&li.ctrl_out.to_le_bytes());
    for x in ri.l_tail_prefix { h.update(&x.to_le_bytes()); }
    h.update(&ri.ctrl_in.to_le_bytes());
    p.mac == *h.finalize().as_bytes()
}

/* -------------------------------- WrapAir ---------------------------------- */

/// Domain separator for the wrap micro-proof.
pub const DS_WRAP_V2: &str = "stark/wrap/v2";

/// Public view for (C_root, π_root).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrapPublic {
    pub c_root: [u8; 32],
    pub c_len: u32,
    pub ctrl_in: u32,
    pub ctrl_out: u32,
    pub flags: u32,
    pub acc_limbs: [u64; 4],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrapProofV1 {
    pub mac: [u8; 32],
}

pub fn prove_wrap_public(p: &WrapPublic) -> anyhow::Result<WrapProofV1> {
    let mut h = Hasher::new();
    h.update(DS_WRAP_V2.as_bytes());
    h.update(&p.c_root);
    h.update(&p.c_len.to_le_bytes());
    h.update(&p.ctrl_in.to_le_bytes());
    h.update(&p.ctrl_out.to_le_bytes());
    h.update(&p.flags.to_le_bytes());
    for limb in p.acc_limbs { h.update(&limb.to_le_bytes()); }
    Ok(WrapProofV1 { mac: *h.finalize().as_bytes() })
}

pub fn verify_wrap_public(p: &WrapPublic, pr: &WrapProofV1) -> bool {
    let mut h = Hasher::new();
    h.update(DS_WRAP_V2.as_bytes());
    h.update(&p.c_root);
    h.update(&p.c_len.to_le_bytes());
    h.update(&p.ctrl_in.to_le_bytes());
    h.update(&p.ctrl_out.to_le_bytes());
    h.update(&p.flags.to_le_bytes());
    for limb in p.acc_limbs { h.update(&limb.to_le_bytes()); }
    pr.mac == *h.finalize().as_bytes()
}
