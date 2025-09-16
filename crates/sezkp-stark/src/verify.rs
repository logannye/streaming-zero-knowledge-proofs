//! Verifier-side recomputation for v0.
//!
//! The v0 “proof” is just two 32-byte challenges derived from a transcript
//! that binds the manifest root and the streaming commit of the row witness.
//! To verify, we recompute the same transcript and check the bytes match.

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

use anyhow::{anyhow, Result};
use sezkp_core::{BlockSummary, ProofArtifact};
use sezkp_crypto::{Blake3Transcript, Transcript};

use crate::commit::commit_blocks;

/// Verify a v0 STARK artifact by recomputing the transcript challenges.
///
/// This performs the **same** streaming commitment over the blocks as the
/// prover, then re-derives the `alpha`/`beta` challenge bytes and compares
/// them with `artifact.proof_bytes`.
pub fn verify_artifact(
    art: &ProofArtifact,
    blocks: &[BlockSummary],
    manifest_root: [u8; 32],
) -> Result<()> {
    // 1) Recompute the streaming commit (includes minimal AIR checks).
    let com = commit_blocks(blocks)?;

    // 2) Rebuild the Fiat–Shamir transcript.
    let mut tr = Blake3Transcript::new("sezkp-stark-v0");
    tr.absorb("manifest_root", &manifest_root);
    tr.absorb("commit_root", &com.root);
    tr.absorb_u64("n_rows", com.n_rows);
    tr.absorb_u64("tau", com.tau as u64);

    // 3) Expected “proof bytes”.
    let mut expected = Vec::with_capacity(64);
    expected.extend(tr.challenge_bytes("alpha", 32));
    expected.extend(tr.challenge_bytes("beta", 32));

    if expected == art.proof_bytes {
        Ok(())
    } else {
        Err(anyhow!("stark-v0 challenge mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, TapeOp, Window};

    fn mk_block(block_id: u32, len: usize) -> BlockSummary {
        let steps = vec![
            StepProjection { input_mv: 0, tapes: vec![TapeOp { write: None, mv: 0 }] };
            len
        ];
        BlockSummary {
            version: 1,
            block_id,
            step_lo: 1 + (block_id as u64 - 1) * len as u64,
            step_hi: (block_id as u64) * len as u64,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: len as i64,
            windows: vec![Window { left: 0, right: len as i64 - 1 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![(len - 1) as u32],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        }
    }

    #[test]
    fn recompute_matches_proof_bytes() {
        let blocks = vec![mk_block(1, 4), mk_block(2, 2)];
        let manifest_root = [9u8; 32];

        // Synthesize expected proof payload the same way the prover would.
        let com = crate::commit::commit_blocks(&blocks).unwrap();
        let mut tr = Blake3Transcript::new("sezkp-stark-v0");
        tr.absorb("manifest_root", &manifest_root);
        tr.absorb("commit_root", &com.root);
        tr.absorb_u64("n_rows", com.n_rows);
        tr.absorb_u64("tau", com.tau as u64);
        let mut proof_bytes = Vec::new();
        proof_bytes.extend(tr.challenge_bytes("alpha", 32));
        proof_bytes.extend(tr.challenge_bytes("beta", 32));

        let art = ProofArtifact {
            backend: sezkp_core::BackendKind::Stark,
            manifest_root,
            proof_bytes,
            meta: serde_json::json!({}),
        };

        verify_artifact(&art, &blocks, manifest_root).unwrap();
    }
}
