//! VM-agnostic trace format + partitioning into `BlockSummary` (σ_k).
//!
//! This crate provides three small building blocks that are deliberately
//! independent of any specific VM:
//!
//! - `format`: a minimal, versioned trace envelope (`TraceFile`).
//! - `generator`: a deterministic toy trace generator for tests/benches.
//! - `partition`: a projector that slices a `TraceFile` into σ_k blocks
//!   (`BlockSummary`) used by downstream proof pipelines.
//! - `io`: JSON/CBOR read/write helpers for `TraceFile`.
//!
//! The intent is to keep the trace pipeline simple, testable, and easy to
//! replace with production sources later (a real VM or importer).
//!
//! We intentionally avoid broad re-exports so callers use stable paths like
//! `sezkp_trace::partition::partition_trace`.

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

/// Versioned, VM-neutral trace envelope.
pub mod format;
/// Deterministic toy trace generator (for sims/benches).
pub mod generator;
/// JSON/CBOR I/O helpers for `TraceFile`.
pub mod io;
/// Partition a `TraceFile` into σ_k (`BlockSummary`) windows/logs.
pub mod partition;

// (Intentionally no broad re-exports so downstream callers import
// stable module paths like `sezkp_trace::partition::partition_trace`.)
