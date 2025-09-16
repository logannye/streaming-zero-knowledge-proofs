//! Canonical core types used across the SEZKP workspace.
//!
//! These live in `sezkp-core` and are broadly re-exported at the crate root
//! so other crates can import via `sezkp_core::TapeOp`, `sezkp_core::Interval`, etc.
//!
//! The design aims to keep serialized forms conservative and portable (serde).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Absolute cell on a work tape (signed to allow moves left of origin).
pub type Cell = i64;

/// Relative offset within a window.
pub type Offset = u32;

/// Alphabet symbol identifier (mapping established by the trace).
pub type SymbolId = u16;

/// Inclusive contiguous window `[left, right]` of touched cells (per tape, per block).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    /// Left (minimum) absolute cell index.
    pub left: Cell,
    /// Right (maximum) absolute cell index (≥ `left` for valid windows).
    pub right: Cell,
}

impl Window {
    /// Create a new window (no validation).
    #[inline]
    #[must_use]
    pub const fn new(left: Cell, right: Cell) -> Self {
        Self { left, right }
    }

    /// Length of the window as a count of cells (0 if inverted).
    #[inline]
    #[must_use]
    pub fn len(&self) -> u64 {
        if self.right >= self.left {
            (self.right - self.left + 1) as u64
        } else {
            0
        }
    }

    /// Returns `true` if `pos` lies within `[left, right]`.
    #[inline]
    #[must_use]
    pub fn contains(&self, pos: Cell) -> bool {
        pos >= self.left && pos <= self.right
    }
}

/// Movement for a single tape in {-1, 0, +1}.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TapeOp {
    /// Optional write (`None` ⇒ no write).
    pub write: Option<SymbolId>,
    /// Head move in `{-1,0,+1}`.
    pub mv: i8,
}

impl TapeOp {
    /// Construct a new `TapeOp`. `mv` should be in `{-1,0,+1}`.
    #[inline]
    #[must_use]
    pub const fn new(write: Option<SymbolId>, mv: i8) -> Self {
        Self { write, mv }
    }
}

/// A single replay step projection (input move + τ per-tape ops).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepProjection {
    /// Input head move in `{-1,0,+1}`.
    pub input_mv: i8,
    /// Per-tape operations (length = τ).
    pub tapes: Vec<TapeOp>,
}

/// Compact per-block movement log (restricted to touched windows).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MovementLog {
    /// Replay steps (length ≤ block size).
    pub steps: Vec<StepProjection>,
}

/// Advisory fingerprint (not used for soundness).
pub type Tag = [u8; 16];

/// Per-block summary σ_k (enough to replay exactly with O(b) space).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSummary {
    /// Schema/wire version for forward-compat checks.
    pub version: u16,
    /// Block index `k` (1-based).
    pub block_id: u32,
    /// Global step lo/hi (1-based).
    pub step_lo: u64,
    /// Global step hi (inclusive).
    pub step_hi: u64,

    // Advisory finite control (engineer-facing, not required for soundness).
    /// Finite control at entry.
    pub ctrl_in: u16,
    /// Finite control at exit.
    pub ctrl_out: u16,

    /// Absolute input head positions at entry.
    pub in_head_in: i64,
    /// Absolute input head positions at exit.
    pub in_head_out: i64,

    /// Per-tape window geometry (length τ).
    pub windows: Vec<Window>,
    /// Head offsets within corresponding windows at entry.
    pub head_in_offsets: Vec<Offset>,
    /// Head offsets within corresponding windows at exit.
    pub head_out_offsets: Vec<Offset>,

    /// Exact bounded-window replay data for this block.
    pub movement_log: MovementLog,

    /// Advisory tags (quick reject only).
    pub pre_tags: Vec<Tag>,
    /// Advisory tags (quick reject only).
    pub post_tags: Vec<Tag>,
}

/// Closed interval of block indices `[i, j]` (1-based inclusive).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Interval {
    /// Start index (1-based).
    pub i: u32,
    /// End index (1-based, ≥ `i` for a valid interval).
    pub j: u32,
}

impl Interval {
    /// Construct a new interval `[i,j]` (no validation).
    #[inline]
    #[must_use]
    pub const fn new(i: u32, j: u32) -> Self {
        Self { i, j }
    }

    /// Length in blocks (0 if inverted).
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        if self.j >= self.i {
            self.j - self.i + 1
        } else {
            0
        }
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{},{}]", self.i, self.j)
    }
}

/// Constant-size interval finite-state projection.
/// (No large arrays; boundary contents are reconstructed by replay.)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FiniteState {
    /// Finite control at entry.
    pub ctrl_in: u16,
    /// Finite control at exit.
    pub ctrl_out: u16,
    /// Absolute input head at entry.
    pub in_head_in: i64,
    /// Absolute input head at exit.
    pub in_head_out: i64,
    /// Absolute work-tape heads at entry (length τ).
    pub work_head_in: Vec<i64>,
    /// Absolute work-tape heads at exit (length τ).
    pub work_head_out: Vec<i64>,
    /// Small reserved flags for inexpensive invariants.
    pub flags: u32,
    /// Advisory tag (e.g., a quick fingerprint).
    pub tag: Tag,
}

impl FiniteState {
    /// Returns τ (the number of work tapes) inferred from `work_head_in`.
    #[inline]
    #[must_use]
    pub fn arity(&self) -> usize {
        self.work_head_in.len()
    }
}

impl Default for FiniteState {
    fn default() -> Self {
        Self {
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            work_head_in: Vec::new(),
            work_head_out: Vec::new(),
            flags: 0,
            tag: [0u8; 16],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_len_and_contains() {
        let w = Window::new(-2, 2);
        assert_eq!(w.len(), 5);
        assert!(w.contains(0));
        assert!(!w.contains(3));
        let bad = Window::new(5, 1);
        assert_eq!(bad.len(), 0);
    }

    #[test]
    fn interval_len() {
        assert_eq!(Interval::new(3, 7).len(), 5);
        assert_eq!(Interval::new(7, 3).len(), 0);
    }
}
