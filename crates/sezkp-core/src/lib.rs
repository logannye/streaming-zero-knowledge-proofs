// crates/sezkp-core/src/lib.rs

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod artifact;
pub mod backend;
pub mod combiner;
pub mod evaluator;
pub mod io;
pub mod prover;
pub mod replay;
pub mod types;
pub mod io_jsonl;

// ---- Re-exports for workspace compatibility ----
pub use artifact::*;
pub use backend::*;
pub use combiner::*;
pub use evaluator::*;
pub use io::*;
pub use prover::*;
pub use replay::*;
pub use types::*;

// Explicitly re-export the streaming trait so backends can implement it.
pub use prover::ProvingBackendStream;
