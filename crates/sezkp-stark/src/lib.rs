//! SEZKP STARK backends
//!
//! - **v0**: Streaming row witness + transcript “proof” (scaffold).
//! - **v1**: Columnar PIOP with AIR constraints, Merkle column commitments,
//!           random queries, and a minimal FRI folding proof (WIP).

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

mod air;      // v0 scaffold checks
mod commit;   // v0 streaming commitment
mod iop;      // v0 mock IOP bits
mod verify;   // v0 verifier
mod witness;  // v0 row witness encoding

/// v1 modules
pub mod v1 {
    #![allow(missing_docs, dead_code)]
    pub mod air;
    pub mod columns;
    pub mod field;
    pub mod fri;
    pub mod merkle;
    pub mod params;
    pub mod proof;
    pub mod prover;
    pub mod verify;
    pub mod columns_stream;
    pub mod openings;
    pub mod lde;
    pub mod fri_stream;
    pub mod masking;
}

use anyhow::{ensure, Result};
pub use sezkp_core::{BackendKind, BlockSummary, ProofArtifact, ProvingBackend};
use sezkp_crypto::{Blake3Transcript, Transcript};

/// Re-export v1 parameters so downstream code can depend on them.
pub use v1::params;

/// v0 marker backend (streaming transcript scaffold).
#[derive(Debug, Clone, Copy, Default)]
pub struct StarkIOP;

impl ProvingBackend for StarkIOP {
    fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        let com = commit::commit_blocks(blocks)?;
        let mut tr = Blake3Transcript::new("sezkp-stark-v0");
        tr.absorb("manifest_root", &manifest_root);
        tr.absorb("commit_root", &com.root);
        tr.absorb_u64("n_rows", com.n_rows);
        tr.absorb_u64("tau", com.tau as u64);

        let mut proof = Vec::with_capacity(64);
        proof.extend(tr.challenge_bytes("alpha", 32));
        proof.extend(tr.challenge_bytes("beta", 32));

        Ok(ProofArtifact {
            backend: BackendKind::Stark,
            manifest_root,
            proof_bytes: proof,
            meta: serde_json::json!({
                "proto": "stark-v0",
                "n_rows": com.n_rows,
                "tau": com.tau
            }),
        })
    }

    fn verify(
        artifact: &ProofArtifact,
        blocks: &[BlockSummary],
        manifest_root: [u8; 32],
    ) -> Result<()> {
        ensure!(
            artifact.backend == BackendKind::Stark,
            "backend kind mismatch: expected STARK"
        );
        ensure!(
            artifact.manifest_root == manifest_root,
            "manifest root mismatch"
        );
        verify::verify_artifact(artifact, blocks, manifest_root)
    }
}

/// v1 backend (columnar PIOP).
#[derive(Debug, Clone, Copy, Default)]
pub struct StarkV1;

impl ProvingBackend for StarkV1 {
    fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        // Current default is the streaming prover entrypoint (A4+).
        let proof = v1::prover::prove_v1(blocks, manifest_root)?;
        let bytes = serde_json::to_vec(&proof)?;
        Ok(ProofArtifact {
            backend: BackendKind::Stark,
            manifest_root,
            proof_bytes: bytes,
            meta: serde_json::json!({
                "proto": "stark-v1",
                "domain_n": proof.domain_n,
                "tau": proof.tau
            }),
        })
    }

    fn verify(
        artifact: &ProofArtifact,
        blocks: &[BlockSummary],
        _manifest_root: [u8; 32],
    ) -> Result<()> {
        let proof: v1::proof::ProofV1 = bincode::deserialize(&artifact.proof_bytes)?;
        v1::verify::verify_v1(&proof, blocks)
    }
}

impl StarkV1 {
    /// Explicit streaming entrypoint for the CLI `--stream` flag.
    /// Currently identical to `prove`, but kept as a dedicated method
    /// so we can easily diverge implementations later.
    pub fn prove_streaming(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        let proof = v1::prover::prove_v1(blocks, manifest_root)?;
        let bytes = bincode::serialize(&proof)?;
        Ok(ProofArtifact {
            backend: BackendKind::Stark,
            manifest_root,
            proof_bytes: bytes,
            meta: serde_json::json!({
                "proto": "stark-v1",
                "mode": "streaming",
                "domain_n": proof.domain_n,
                "tau": proof.tau
            }),
        })
    }
}
