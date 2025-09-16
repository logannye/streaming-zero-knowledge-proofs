//! Backend abstraction for proving and verification.
//!
//! Implementors provide a *stateless* API (associated functions) that take
//! block summaries and a `manifest_root` and either produce a [`ProofArtifact`]
//! or verify one. This keeps the call surface stable across CLI/FFI/Python.
//!
//! ## Contracts implementors should uphold
//! - `prove` must bind the proof to the given `manifest_root` and encode any
//!   necessary opening/consistency data in `proof_bytes`.
//! - `verify` must reject if:
//!   - `artifact.backend` does not correspond to the implementing backend,
//!   - `manifest_root` mismatches `artifact.manifest_root`,
//!   - or the proof bytes fail the backend’s validity checks.
//! - Neither function should panic for malformed inputs; return `Err` instead.
//!
//! Consider introducing a crate-local `Error` (via `thiserror`) when the API
//! stabilizes; we return `anyhow::Result` here to avoid churn during iteration.

use crate::{BlockSummary, ProofArtifact};
use anyhow::Result;

/// Minimal backend API the rest of the system depends on.
///
/// Backends are typically used as type parameters, e.g.:
/// `StreamingProver::<StarkIOP>::prove(...)`.
///
/// ```ignore
/// use sezkp_core::{ProvingBackend, ProofArtifact};
/// # struct StarkIOP;
/// # impl ProvingBackend for StarkIOP {
/// #     fn prove(_b: &[sezkp_core::BlockSummary], _r: [u8;32]) -> anyhow::Result<ProofArtifact> {
/// #         unimplemented!()
/// #     }
/// #     fn verify(_a: &ProofArtifact, _b: &[sezkp_core::BlockSummary], _r: [u8;32]) -> anyhow::Result<()> {
/// #         unimplemented!()
/// #     }
/// # }
/// // let artifact = StarkIOP::prove(blocks, manifest_root)?;
/// // StarkIOP::verify(&artifact, blocks, manifest_root)?;
/// ```
pub trait ProvingBackend {
    /// Produce a proof tied to `manifest_root` for the given block summaries.
    ///
    /// # Errors
    /// Returns an error if the backend cannot construct a proof (e.g., invalid
    /// block summaries, inconsistent parameters, internal constraint failure).
    #[must_use]
    fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<ProofArtifact>;

    /// Verify a previously generated proof against `blocks` and `manifest_root`.
    ///
    /// # Errors
    /// Returns an error if the proof is invalid for the provided inputs or the
    /// internal checks fail (e.g., root mismatch, malformed encoding).
    #[must_use]
    fn verify(
        artifact: &ProofArtifact,
        blocks: &[BlockSummary],
        manifest_root: [u8; 32],
    ) -> Result<()>;
}
