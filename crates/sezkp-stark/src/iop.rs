//! Minimal IOP-style commitment over block interfaces (mock).
//!
//! This *mock* STARK IOP layer derives deterministic proof bytes from a
//! transcript over per-block interface data (sizes and head drifts).
//! It’s deliberately tiny so we can exercise the end-to-end plumbing and
//! serialization without depending on a full polynomial IOP stack.
//!
//! Implementation notes:
//! - We absorb a compact public tuple per block into a domain-separated
//!   transcript (Fiat–Shamir).
//! - The “proof” is simply three 32-byte challenges concatenated.
//! - Deterministic for identical inputs + domain strings.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(dead_code)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use sezkp_core::BlockSummary;
use sezkp_crypto::{Blake3Transcript, Transcript};

/// ZigZag encode an `i64` into a non-negative `u64`.
#[inline]
#[must_use]
fn zigzag_i64_to_u64(x: i64) -> u64 {
    // ZigZag: 0 → 0, -1 → 1, 1 → 2, -2 → 3, 2 → 4, ...
    ((x << 1) ^ (x >> 63)) as u64
}

/// Absorb interface data for a single block into the transcript.
///
/// We bind: IDs, step range, ctrl boundary, step count, input head drift,
/// and per-tape head drifts measured inside the declared windows.
fn absorb_block_iface(tr: &mut Blake3Transcript, b: &BlockSummary) {
    tr.absorb_u64("block_id", b.block_id as u64);
    tr.absorb_u64("step_lo", b.step_lo);
    tr.absorb_u64("step_hi", b.step_hi);
    tr.absorb_u64("ctrl_in", b.ctrl_in as u64);
    tr.absorb_u64("ctrl_out", b.ctrl_out as u64);

    // Step count (IOP would commit to execution trace; we only commit to length).
    tr.absorb_u64("steps_len", b.movement_log.steps.len() as u64);

    // Input head drift across the block.
    let input_drift = b.in_head_out - b.in_head_in;
    tr.absorb_u64("input_drift", zigzag_i64_to_u64(input_drift));

    // Per-tape head drifts across declared windows.
    tr.absorb_u64("tau", b.windows.len() as u64);
    for (r, (win, (&in_off, &out_off))) in b
        .windows
        .iter()
        .zip(b.head_in_offsets.iter().zip(b.head_out_offsets.iter()))
        .enumerate()
    {
        // Absolute head positions at in/out (within window), then drift.
        let in_abs = win.left + i64::from(in_off);
        let out_abs = win.left + i64::from(out_off);
        let drift = out_abs - in_abs;

        tr.absorb_u64("tape_idx", r as u64);
        tr.absorb_u64("tape_drift", zigzag_i64_to_u64(drift));
    }
}

/// Produce deterministic “proof bytes” by applying Fiat–Shamir to the absorbed interface.
///
/// This is a mock; it just squeezes three 32-byte challenges. Consumers can wrap
/// these bytes in higher-level envelopes as needed.
#[must_use]
pub fn commit_block_fiat_shamir(tr: &mut Blake3Transcript, blocks: &[BlockSummary]) -> Vec<u8> {
    tr.absorb_u64("n_blocks", blocks.len() as u64);
    for b in blocks {
        absorb_block_iface(tr, b);
    }

    // Derive a few challenge chunks to form our mock proof bytes.
    let mut proof = Vec::with_capacity(96);
    proof.extend(tr.challenge_bytes("alpha", 32));
    proof.extend(tr.challenge_bytes("beta", 32));
    proof.extend(tr.challenge_bytes("gamma", 32));
    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, TapeOp, Window};

    fn mk(len: usize) -> BlockSummary {
        let steps = vec![StepProjection { input_mv: 0, tapes: vec![TapeOp { write: None, mv: 0 }] }; len];
        BlockSummary {
            version: 1,
            block_id: 1,
            step_lo: 1,
            step_hi: len as u64,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 0 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![0],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        }
    }

    #[test]
    fn deterministic_for_same_input() {
        let mut t1 = Blake3Transcript::new("iop-test");
        let mut t2 = Blake3Transcript::new("iop-test");
        let blocks = vec![mk(4), mk(2)];
        let a = commit_block_fiat_shamir(&mut t1, &blocks);
        let b = commit_block_fiat_shamir(&mut t2, &blocks);
        assert_eq!(a, b);
    }

    #[test]
    fn different_domain_sep_changes_output() {
        let mut t1 = Blake3Transcript::new("iop-A");
        let mut t2 = Blake3Transcript::new("iop-B");
        let blocks = vec![mk(4)];
        let a = commit_block_fiat_shamir(&mut t1, &blocks);
        let b = commit_block_fiat_shamir(&mut t2, &blocks);
        assert_ne!(a, b);
    }
}
