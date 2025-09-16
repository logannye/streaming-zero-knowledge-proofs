//! SEZKP STARK backends
//!
//! This crate currently exposes two families of proving backends:
//!
//! - **v0 (scaffold)** — a streaming row-witness commitment with a tiny
//!   transcript-based “proof”. It’s meant for plumbing and integration tests,
//!   not cryptographic security.
//! - **v1 (PIOP/FRI)** — a columnar interactive oracle proof with Merkle
//!   commitments, AIR constraints, sampled openings, and a small FRI folding
//!   proof. The v1 modules live under [`crate::v1`] and are designed to be
//!   *streaming friendly* via `columns_stream`, `openings`, and `fri_stream`.
//!
//! The top-level types implement the workspace’s [`sezkp_core::ProvingBackend`]
//! trait so they can be selected by the CLI or other hosts.

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

mod air;      // v0 scaffold checks (local, minimal)
mod commit;   // v0 streaming row-commit
mod iop;      // v0 mock IOP bits (Fiat–Shamir over interfaces)
mod verify;   // v0 verifier (recomputes transcript challenges)
mod witness;  // v0 row witness encoding / chunking

/// v1 modules (kept separate to avoid mixing concerns with the v0 scaffold).
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

/// Re-export v1 parameters so downstream code can depend on a single path:
/// `sezkp_stark::params::...`.
pub use v1::params;

/// v0 marker backend (streaming transcript scaffold).
///
/// This is intentionally tiny: it commits to the row stream with a transcript
/// and returns two squeezed challenge blocks as the “proof”. The verifier
/// recomputes the same transcript and checks equality.
#[derive(Debug, Clone, Copy, Default)]
pub struct StarkIOP;

impl ProvingBackend for StarkIOP {
    fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        // 1) Row-stream commitment with minimal AIR checks.
        let com = commit::commit_blocks(blocks)?;

        // 2) Fiat–Shamir transcript for the proof envelope.
        let mut tr = Blake3Transcript::new("sezkp-stark-v0");
        tr.absorb("manifest_root", &manifest_root);
        tr.absorb("commit_root", &com.root);
        tr.absorb_u64("n_rows", com.n_rows);
        tr.absorb_u64("tau", com.tau as u64);

        // 3) Squeeze a couple of challenge blocks (deterministic proof bytes).
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

/// v1 backend (columnar PIOP + FRI; streaming-friendly).
///
/// This uses the “real” prover/verifier stack living under `v1::*`. The proof
/// object is serialized into the artifact bytes. We use **bincode** for a small
/// byte footprint and fast (de)serialization; the metadata remains JSON for easy
/// inspection.
///
/// The `prove_streaming` entrypoint is documented to be compatible with the
/// streaming internals (`columns_stream`, `openings`, `fri_stream`). The exact
/// memory profile depends on parameter sizes, but both proving and verifying
/// avoid materializing Θ(T) state at once.
#[derive(Debug, Clone, Copy, Default)]
pub struct StarkV1;

impl ProvingBackend for StarkV1 {
    fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        let proof = v1::prover::prove_v1(blocks, manifest_root)?;
        let bytes = bincode::serialize(&proof)?;
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
        manifest_root: [u8; 32],
    ) -> Result<()> {
        // Defensive checks mirror v0 path so callers can mix backends safely.
        ensure!(
            artifact.backend == BackendKind::Stark,
            "backend kind mismatch: expected STARK"
        );
        ensure!(
            artifact.manifest_root == manifest_root,
            "manifest root mismatch"
        );

        let proof: v1::proof::ProofV1 = bincode::deserialize(&artifact.proof_bytes)?;
        v1::verify::verify_v1(&proof, blocks)
    }
}

impl StarkV1 {
    /// Explicit streaming entrypoint for the CLI `--stream` flag.
    ///
    /// Internally engages the streaming-friendly code paths (column roots,
    /// openings, and the FRI layer tree) while preserving the same
    /// wire format as [`Self::prove`].
    pub fn prove_streaming(
        blocks: &[BlockSummary],
        manifest_root: [u8; 32],
    ) -> Result<ProofArtifact> {
        // Current prover implementation already leverages streaming components.
        // Kept as a dedicated method so call sites can intentionally select
        // the streaming profile and we can diverge implementations later.
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
