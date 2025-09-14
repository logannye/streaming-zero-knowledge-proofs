# Trace Format (Canonical Movement Log)

This document specifies the **VM-agnostic** trace format consumed by SEZKP. The trace captures a *time-ordered* sequence of micro-operations over a fixed number of **work tapes** (τ is constant) and a read-only **input tape**.

SEZKP uses **exact bounded-window replay**; therefore the trace must permit reconstructing all writes and head moves within each block.

## Design goals

- Deterministic, canonical serialization
- Supports exact replay over **O(b)** windows
- Constant-arity per step (bounded by τ)
- Stable versioning

## Terms

- `t`: total steps
- `b`: block size (steps per block)
- `T = ceil(t / b)`: number of blocks
- `τ`: number of work tapes (constant)
- `Γ`: finite alphabet (constant)

## Wire types (conceptual)

```rust
/// A tape symbol in Γ (encoded as u8 if |Γ|≤256; otherwise as varint id)
type SymbolId = u16;

/// Head movement in {-1, 0, +1}
#[repr(i8)]
enum Move1 { Neg1 = -1, Zero = 0, Pos1 = 1 }

/// Per-work-tape micro-op for a single step.
struct TapeOp {
  /// Optional write (None ⇒ no write)
  write: Option<SymbolId>,
  /// Head movement in {-1,0,+1}
  mv: Move1,
}

/// A single “step” across all τ work tapes.
struct Step {
  /// Control state id *before* the transition (for debugging / audit; optional)
  ctrl_in: u16,
  /// Control state id *after* the transition (optional)
  ctrl_out: u16,
  /// Read-only input head movement {-1,0,+1}
  input_mv: Move1,
  /// Per-tape ops (length = τ, fixed across the trace)
  tapes: [TapeOp; τ],
}
