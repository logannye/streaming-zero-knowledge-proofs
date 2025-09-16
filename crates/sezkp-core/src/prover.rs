//! Streaming prover runtime (ARE + interface checks).
//!
//! Goals:
//! - Keep *space* sublinear by never materializing Θ(T) state.
//! - Validate σ_k locally (bounded-window write safety) and check adjacent
//!   interface equality (finite-state stitching) **as we stream**.
//! - Remain backend-agnostic for the classic slice API, while exposing a
//!   push-based streaming API backends can implement for true sublinear usage.

use crate::{BlockSummary, FiniteState, ProvingBackend};
use anyhow::{anyhow, Result};
use std::marker::PhantomData;

use crate::replay::{Replay, ReplayConfig};

/// Optional **push-based** interface a backend can implement to support
/// truly streaming proving without collecting all blocks.
pub trait ProvingBackendStream {
    /// Opaque backend streaming state.
    type StreamState;

    /// Initialize a streaming session bound to `manifest_root`.
    fn begin_stream(manifest_root: [u8; 32]) -> Result<Self::StreamState>;

    /// Ingest the next block (after the caller has validated it).
    fn ingest_block(state: &mut Self::StreamState, block: BlockSummary) -> Result<()>;

    /// Finalize and produce the proof artifact.
    fn finish_stream(state: Self::StreamState) -> Result<crate::ProofArtifact>;
}

/// A generic prover that can operate either in batch (slice) mode or in
/// streaming mode (when the backend implements [`ProvingBackendStream`]).
#[derive(Debug, Clone, Copy)]
pub struct StreamingProver<B: ProvingBackend> {
    backend: PhantomData<B>,
    replay: Replay,
}

impl<B: ProvingBackend> Default for StreamingProver<B> {
    fn default() -> Self {
        Self {
            backend: PhantomData,
            replay: Replay {
                cfg: ReplayConfig { check_writes: true },
            },
        }
    }
}

impl<B: ProvingBackend> StreamingProver<B> {
    /// Construct with a custom replay configuration (e.g., to relax checks in experiments).
    #[must_use]
    pub fn with_replay_config(cfg: ReplayConfig) -> Self {
        Self {
            backend: PhantomData,
            replay: Replay { cfg },
        }
    }

    /* ----------------------------- batch (slice) ---------------------------- */

    /// Validate per-block invariants + adjacent interfaces, then call the backend's `prove`.
    ///
    /// # Errors
    /// Returns an error if validation fails or the backend cannot produce a proof.
    #[must_use]
    pub fn prove(blocks: &[BlockSummary], manifest_root: [u8; 32]) -> Result<crate::ProofArtifact> {
        let sp = Self::default();
        sp.validate_blocks(blocks)?;
        B::prove(blocks, manifest_root)
    }

    /// Validate + delegate to backend verification.
    ///
    /// # Errors
    /// Returns an error if validation fails or the proof is invalid for the given inputs.
    #[must_use]
    pub fn verify(
        artifact: &crate::ProofArtifact,
        blocks: &[BlockSummary],
        manifest_root: [u8; 32],
    ) -> Result<()> {
        let sp = Self::default();
        sp.validate_blocks(blocks)?;
        B::verify(artifact, blocks, manifest_root)
    }

    /* ----------------------------- streaming -------------------------------- */

    /// **True streaming** prover:
    /// - Accepts an iterator of `Result<BlockSummary>`.
    /// - Validates each block with ARE on the fly.
    /// - Pushes blocks into a backend streaming state.
    ///
    /// Requires the backend to implement [`ProvingBackendStream`].
    ///
    /// # Errors
    /// Returns an error if validation fails or the backend cannot produce a proof.
    #[must_use]
    pub fn prove_stream_iter<I>(
        iter: I,
        manifest_root: [u8; 32],
    ) -> Result<crate::ProofArtifact>
    where
        B: ProvingBackendStream,
        I: IntoIterator<Item = Result<BlockSummary>>,
    {
        let mut state = <B as ProvingBackendStream>::begin_stream(manifest_root)?;
        let sp = Self::default();

        // Keep only the previous boundary for interface checks.
        let mut prev: Option<FiniteState> = None;

        for (idx, item) in iter.into_iter().enumerate() {
            let block = item?;

            // 1) Local bounded-window ARE check → returns FiniteState
            let fs = sp.replay.replay_block(&block).map_err(|e| {
                anyhow!(
                    "ARE validation failed for block index {} (block_id={}): {e}",
                    idx,
                    block.block_id
                )
            })?;

            // 2) Interface check vs previous boundary (ctrl + input-head continuity)
            if let Some(p) = &prev {
                if !sp.replay.interface_ok(p, &fs) {
                    return Err(anyhow!(
                        "interface mismatch at boundary {}→{}: (ctrl_out,in_head_out) != (ctrl_in,in_head_in)",
                        idx.saturating_sub(1),
                        idx
                    ));
                }
            }
            prev = Some(fs);

            // 3) Pass the (validated) block to the backend streaming driver.
            <B as ProvingBackendStream>::ingest_block(&mut state, block)?;
        }

        // 4) Finalize the proof.
        <B as ProvingBackendStream>::finish_stream(state)
    }

    /// Streaming verify: replay σ_k **without** materializing the vector,
    /// then call the backend's verifier (which may itself be streaming).
    ///
    /// The fold backend verifies against the manifest only, so we pass `&[]`.
    /// Backends that require blocks in their verifier can still use the batch API.
    ///
    /// # Errors
    /// Returns an error if validation fails or the proof fails to verify.
    #[must_use]
    pub fn verify_stream_iter<I>(
        artifact: &crate::ProofArtifact,
        iter: I,
        manifest_root: [u8; 32],
    ) -> Result<()>
    where
        I: IntoIterator<Item = Result<BlockSummary>>,
    {
        let sp = Self::default();

        // Validate per-block ARE + interfaces on the fly.
        let mut prev: Option<FiniteState> = None;
        for (idx, item) in iter.into_iter().enumerate() {
            let block = item?;

            let fs = sp.replay.replay_block(&block).map_err(|e| {
                anyhow!(
                    "ARE validation failed for block index {} (block_id={}): {e}",
                    idx,
                    block.block_id
                )
            })?;

            if let Some(p) = &prev {
                if !sp.replay.interface_ok(p, &fs) {
                    return Err(anyhow!(
                        "interface mismatch at boundary {}→{}: (ctrl_out,in_head_out) != (ctrl_in,in_head_in)",
                        idx.saturating_sub(1),
                        idx
                    ));
                }
            }
            prev = Some(fs);
        }

        // Delegate to backend verification using an empty slice (fold backend does not need blocks).
        B::verify(artifact, &[], manifest_root)
    }

    /* ------------------------------ helpers --------------------------------- */

    /// Local batch validation pass (used by the slice-based API).
    fn validate_blocks(&self, blocks: &[BlockSummary]) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }

        // Replay each block, collect FiniteState for interface stitching.
        let mut fstates: Vec<FiniteState> = Vec::with_capacity(blocks.len());
        for (idx, b) in blocks.iter().enumerate() {
            let fs = self.replay.replay_block(b).map_err(|e| {
                anyhow!(
                    "ARE validation failed for block index {} (block_id={}): {e}",
                    idx,
                    b.block_id
                )
            })?;
            fstates.push(fs);
        }

        // Check consecutive interface compatibility (minimal: ctrl + input head continuity).
        for i in 0..fstates.len().saturating_sub(1) {
            let a = &fstates[i];
            let c = &fstates[i + 1];
            if !self.replay.interface_ok(a, c) {
                return Err(anyhow!(
                    "interface mismatch at boundary {}→{}: (ctrl_out,in_head_out) != (ctrl_in,in_head_in)",
                    i,
                    i + 1
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Compile-time checks: generic struct is Send/Sync (PhantomData is).
    fn _assert_send_sync<B: ProvingBackend>() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StreamingProver<B>>();
    }
}
