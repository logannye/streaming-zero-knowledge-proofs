//! VM-agnostic trace envelope used by the toy generator and partitioner.
//!
//! A `TraceFile` is intentionally minimal: it captures **only** head
//! movements and optional writes for an input head plus `τ` work tapes.
//!
//! - The structure is VM-neutral and suitable for tests, benches, or small
//!   demos. Production systems can embed this envelope inside richer formats.
//! - `TraceFile::version` is included for forward/parallel format evolution.
//!
//! ## Conventions
//! - Head moves live in `{-1, 0, +1}` (as `i8`).
//! - Tape writes (if any) are `SymbolId` values that match `sezkp_core`.
//! - The trace length is `steps.len()`; the tape count is `tau`.
//!
//! ## Compatibility
//! `TapeOp` converts losslessly into `sezkp_core::types::TapeOp`.

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

use serde::{Deserialize, Serialize};
use sezkp_core::types::{SymbolId, TapeOp as CoreTapeOp};

/// Per-tape operation in `{-1, 0, +1}` with an optional write.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TapeOp {
    /// Optional symbol to write at the *post-move* head position.
    pub write: Option<SymbolId>,
    /// Head movement in `{-1, 0, +1}`.
    pub mv: i8,
}

impl From<TapeOp> for CoreTapeOp {
    #[inline]
    fn from(x: TapeOp) -> CoreTapeOp {
        CoreTapeOp { write: x.write, mv: x.mv }
    }
}

/// A single step across all `τ` tapes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    /// Input head movement in `{-1, 0, +1}`.
    pub input_mv: i8,
    /// Per-tape operations, length = `τ`.
    pub tapes: Vec<TapeOp>,
}

/// Trace envelope (versioned).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceFile {
    /// Format/version tag for forward-compat (currently `1`).
    pub version: u16,
    /// Number of work tapes `τ` (≤ 255).
    pub tau: u8,
    /// Step sequence.
    pub steps: Vec<Step>,
    /// Optional metadata (program hash, VM id, input hash…).
    pub meta: Option<serde_json::Value>,
}

impl TraceFile {
    /// Number of steps.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the trace is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// `τ` as `usize`.
    #[inline]
    #[must_use]
    pub fn tau_usize(&self) -> usize {
        self.tau as usize
    }
}
