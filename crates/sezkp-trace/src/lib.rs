// crates/sezkp-trace/src/lib.rs

//! VM-agnostic trace format + partitioning into `BlockSummary` (σ_k).

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

pub mod format;
pub mod generator;
pub mod io;
pub mod partition;

// (Intentionally no broad re-exports so downstream callers import
// stable module paths like `sezkp_trace::partition::partition_trace`.)
