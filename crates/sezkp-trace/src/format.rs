// crates/sezkp-trace/src/format.rs

//! VM-agnostic trace envelope used by the generator and partitioner.

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

/// Per-tape op in `{-1, 0, +1}` with optional write.
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

/// Trace envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceFile {
    /// Format/version tag for forward-compat.
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
