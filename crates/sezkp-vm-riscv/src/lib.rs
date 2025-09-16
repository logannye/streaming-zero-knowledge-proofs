//! `sezkp-vm-riscv`: example VM adapter (stub).
//!
//! This is a placeholder showing where a real RISC-V adapter would live. It will
//! eventually translate VM traces into SEZKP’s movement logs and block summaries.
//!
//! For demos, we expose:
//! - `make_trace(steps)`: build a toy 2-tape trace using `sezkp-trace`’s generator.
//! - `RiscvAdapter::demo_block(...)`: synthesize a single block summary σ_k.
//!
//! Production note: this crate intentionally stays tiny and dependency-light so it
//! can be used in examples and tests without requiring a full VM toolchain.

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

use anyhow::Result;
use sezkp_core::{BlockSummary, MovementLog, StepProjection, TapeOp, Window};
use sezkp_trace::{format::TraceFile, generator::generate_trace};

/// Produce a toy trace with `τ = 2` tapes and `steps` rows.
///
/// This is just a stub that delegates to the shared trace generator.
/// A real adapter would record a RISC-V execution and emit the canonical trace.
#[must_use]
pub fn make_trace(steps: u64) -> TraceFile {
    // τ = 2 for the minimal demo
    generate_trace(steps, 2)
}

/// Stub adapter type for future expansion.
#[derive(Debug, Clone, Copy, Default)]
pub struct RiscvAdapter;

impl RiscvAdapter {
    /// Convert a hypothetical RISC-V execution segment into a single σ_k for demos.
    ///
    /// The block contains `len` steps, two tapes, and zero control changes.
    /// Values here are deterministic and simple so tests remain readable.
    pub fn demo_block(block_id: u32, len: usize) -> Result<BlockSummary> {
        let steps = vec![
            StepProjection {
                input_mv: 0,
                tapes: vec![
                    TapeOp { write: None, mv: 0 },
                    TapeOp { write: None, mv: 0 },
                ],
            };
            len
        ];

        Ok(BlockSummary {
            version: 1,
            block_id,
            step_lo: 1 + (block_id as u64 - 1) * len as u64,
            step_hi: (block_id as u64) * len as u64,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: len as i64,
            windows: vec![
                Window { left: 0, right: len as i64 - 1 },
                Window { left: -1, right: len as i64 - 2 },
            ],
            head_in_offsets: vec![0, 0],
            head_out_offsets: vec![(len - 1) as u32, (len - 2) as u32],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0u8; 16]; 2],
            post_tags: vec![[0u8; 16]; 2],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_make_trace() {
        let tf = make_trace(16);
        assert!(tf.len() > 0);
    }

    #[test]
    fn smoke_demo_block() {
        let b = RiscvAdapter::demo_block(1, 4).unwrap();
        assert_eq!(b.block_id, 1);
        assert_eq!(b.windows.len(), 2);
        assert_eq!(b.step_lo, 1);
        assert_eq!(b.step_hi, 4);
    }
}
