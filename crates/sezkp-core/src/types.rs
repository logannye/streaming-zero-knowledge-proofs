// crates/sezkp-core/src/types.rs

//! Canonical core types used across the SEZKP workspace.
//!
//! These live in `sezkp-core` and are broadly re-exported at the crate root
//! so other crates can import via `sezkp_core::TapeOp`, `sezkp_core::Interval`, etc.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Absolute cell on a work tape (signed to allow moves left of origin).
pub type Cell = i64;

/// Relative offset within a window.
pub type Offset = u32;

/// Alphabet symbol identifier (mapping established by the trace).
pub type SymbolId = u16;

/// Inclusive contiguous window [left, right] of touched cells (per tape, per block).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    pub left: Cell,
    pub right: Cell,
}

impl Window {
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
    /// Optional write (None ⇒ no write)
    pub write: Option<SymbolId>,
    /// Head move in {-1,0,+1}
    pub mv: i8,
}

impl TapeOp {
    /// Construct a new `TapeOp`. `mv` should be in {-1,0,+1}.
    #[inline]
    #[must_use]
    pub const fn new(write: Option<SymbolId>, mv: i8) -> Self {
        Self { write, mv }
    }
}

/// A single replay step projection (input move + τ per-tape ops).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepProjection {
    pub input_mv: i8,
    pub tapes: Vec<TapeOp>, // len = tau
}

/// Compact per-block movement log (restricted to touched windows).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MovementLog {
    pub steps: Vec<StepProjection>, // length ≤ b
}

/// Advisory fingerprint (not used for soundness).
pub type Tag = [u8; 16];

/// Per-block summary σ_k (enough to replay exactly with O(b) space).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSummary {
    pub version: u16,
    pub block_id: u32, // k (1-based)
    pub step_lo: u64,  // global step index (1-based)
    pub step_hi: u64,

    // Advisory finite control (engineer-facing, not required for soundness)
    pub ctrl_in: u16,
    pub ctrl_out: u16,

    // Absolute input head positions at entry/exit.
    pub in_head_in: i64,
    pub in_head_out: i64,

    // Per-tape window geometry (len τ)
    pub windows: Vec<Window>,
    // Head offsets within corresponding windows
    pub head_in_offsets: Vec<Offset>,
    pub head_out_offsets: Vec<Offset>,

    // Exact bounded-window replay data for this block
    pub movement_log: MovementLog,

    // Advisory tags (quick reject only)
    pub pre_tags: Vec<Tag>,
    pub post_tags: Vec<Tag>,
}

/// Closed interval of block indices `[i, j]` (1-based inclusive).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Interval {
    pub i: u32,
    pub j: u32,
}
impl Interval {
    #[inline]
    #[must_use]
    pub fn new(i: u32, j: u32) -> Self {
        Self { i, j }
    }
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
    pub ctrl_in: u16,
    pub ctrl_out: u16,
    pub in_head_in: i64,
    pub in_head_out: i64,
    pub work_head_in: Vec<i64>,  // len τ
    pub work_head_out: Vec<i64>, // len τ
    pub flags: u32,              // reserved for small invariants
    pub tag: Tag,                // advisory only
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
