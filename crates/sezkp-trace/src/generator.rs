//! Tiny, deterministic trace generator used by the CLI `simulate` subcommand.
//!
//! The goal is to have *reproducible* inputs for tests/benches without pulling
//! in a full VM. The generator produces a `TraceFile` with `t` steps and `τ`
//! work tapes. Movements are uniform over `{-1,0,+1}` and writes are sampled
//! with a fixed probability.
//!
//! - RNG is `StdRng` seeded with a constant for reproducibility.
//! - Symbols are small (`0..=15`) to keep demo payloads compact.

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

use rand::{rngs::StdRng, Rng as _, SeedableRng};

use crate::format::{Step, TapeOp, TraceFile};

/// Generate a synthetic movement log.
///
/// - `input_mv` is a random step in `{-1, 0, +1}`.
/// - Each tape either writes (symbol in `[0..=15]`) with probability `0.4`
///   or no-ops, and then moves in `{-1,0,+1}`.
///
/// The output is deterministic for a given `(t, tau)` pair.
///
/// # Parameters
/// - `t`: number of steps
/// - `tau`: number of work tapes (`≤ 255`)
#[must_use]
pub fn generate_trace(t: u64, tau: u8) -> TraceFile {
    let mut rng = StdRng::seed_from_u64(42);
    let mut steps = Vec::with_capacity(t as usize);

    for _ in 0..t {
        let input_mv = match rng.random_range(0..=2) {
            0 => -1,
            1 => 0,
            _ => 1,
        };

        let mut tapes = Vec::with_capacity(tau as usize);
        for _ in 0..tau {
            let write = if rng.random_bool(0.4) {
                Some(rng.random_range(0u16..=15u16))
            } else {
                None
            };
            let mv = match rng.random_range(0..=2) {
                0 => -1,
                1 => 0,
                _ => 1,
            };
            tapes.push(TapeOp { write, mv });
        }

        steps.push(Step { input_mv, tapes });
    }

    TraceFile {
        version: 1,
        tau,        // ≤ 255
        steps,      // length t
        meta: None, // no extra metadata for the toy generator
    }
}
