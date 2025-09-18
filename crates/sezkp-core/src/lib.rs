//! sezkp-core — core types, replay/ARE, I/O, and the streaming prover runtime.
//!
//! This crate defines the **stable boundary** used across SEZKP crates:
//! - canonical data types (`BlockSummary`, `FiniteState`, …),
//! - the Algebraic Replay Engine (**ARE**) for per-block validation,
//! - JSON/CBOR I/O (with `.jsonl/.ndjson` streaming helpers), and
//! - the **backend-agnostic** proving façade (batch and streaming).
//!
//! ```no_run
//! use sezkp_core::{StreamingProver, ProvingBackend, BlockSummary};
//! # struct StarkIOP;
//! # impl ProvingBackend for StarkIOP {
//! #   fn prove(_b: &[BlockSummary], _r: [u8;32]) -> anyhow::Result<sezkp_core::ProofArtifact> { unimplemented!() }
//! #   fn verify(_a: &sezkp_core::ProofArtifact, _b: &[BlockSummary], _r: [u8;32]) -> anyhow::Result<()> { unimplemented!() }
//! # }
//! # let blocks: Vec<BlockSummary> = vec![];
//! # let root = [0u8; 32];
//! // Batch mode: validate blocks + delegate to backend
//! // let artifact = StreamingProver::<StarkIOP>::prove(&blocks, root)?;
//! // Streaming mode: feed an iterator of Result<BlockSummary>
//! // let artifact = StreamingProver::<StarkIOP>::prove_stream_iter(iter, root)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
// Small, explicit allowlist to keep docs readable and APIs ergonomic.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::doc_markdown
)]

/// Proof artifact types (opaque proof bytes, backend kind, manifest root, metadata).
pub mod artifact;
/// Minimal stateless backend trait used by the prover façade.
pub mod backend;
/// Constant-size finite-state combiner used by bottom-up evaluators.
pub mod combiner;
/// One-shot bottom-up evaluator (replay leaves + combine to root).
pub mod evaluator;
/// JSON/CBOR helpers and auto-detecting read/write APIs.
pub mod io;
/// Streaming JSONL/NDJSON helpers for large block sets.
pub mod io_jsonl;
/// Prover façade: batch validation + streaming driver.
pub mod prover;
/// Algebraic Replay Engine (ARE) and exact replayer wrapper.
pub mod replay;
/// Canonical core data types shared across the workspace.
pub mod types;

// ---- Re-exports for workspace compatibility ----
pub use artifact::*;
pub use backend::*;
pub use combiner::*;
pub use evaluator::*;
pub use io::*;
pub use prover::*;
pub use replay::*;
pub use types::*;

/// Explicitly re-export the streaming trait so backends can implement it.
pub use prover::ProvingBackendStream;

/// Commonly-used items for quick imports.
///
/// ```rust
/// use sezkp_core::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        artifact::ProofArtifact, backend::ProvingBackend, prover::StreamingProver, types::*,
    };
    pub use crate::prover::ProvingBackendStream;
}
