//! Small CLI to run the VM stub and exercise the full pipeline end-to-end.
//!
//! Steps:
//! 1) Generate a toy trace (`--steps`, 2 tapes) and write it to `trace.cbor`.
//! 2) Partition into σ_k blocks of size `--b` and write `blocks.cbor`.
//! 3) Commit leaves → `manifest.cbor` (Merkle root).
//! 4) Prove with selected backend (`--proto v0|v1|fold`) → `proof.cbor`.
//! 5) Verify: checks blocks vs manifest, and verifies the proof.
//!
//! Folding backend knobs (forwarded via env to `sezkp-fold`):
//!   --fold-mode balanced|minram
//!   --wrap-cadence N
//!
//! Usage (example):
//!   cargo run -p sezkp-vm-riscv --release -- \
//!     --steps 64 --b 4 --proto fold --fold-mode balanced --wrap-cadence 0

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

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sezkp_core::ProvingBackend;
use sezkp_fold::FoldBackend;
use sezkp_merkle::{commit_block_file, verify_block_file_against_manifest};
use sezkp_stark::{StarkIOP, StarkV1};
use sezkp_trace::{format::TraceFile, io::write_trace_cbor, partition::partition_trace};

/// Parse a numeric flag like `--steps 32`, falling back to `default`.
fn parse_arg<T: std::str::FromStr>(name: &str, default: T) -> T {
    let mut it = env::args().skip(1);
    let mut last = None;
    while let Some(k) = it.next() {
        if k == format!("--{name}") {
            last = it.next();
            break;
        }
    }
    last.and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Parse a string flag like `--out-dir path`, falling back to `default`.
fn parse_str(name: &str, default: &str) -> String {
    let mut it = env::args().skip(1);
    let mut last = None;
    while let Some(k) = it.next() {
        if k == format!("--{name}") {
            last = it.next();
            break;
        }
    }
    last.unwrap_or_else(|| default.to_string())
}

fn main() -> Result<()> {
    let steps: u64 = parse_arg("steps", 32);
    let b: u32 = parse_arg("b", 4);
    let out_dir = PathBuf::from(parse_str("out-dir", "examples/minimal-riscv"));

    // Protocol choice: v0 (legacy IOP), v1 (STARK v1), fold (folding backend).
    let proto = parse_str("proto", "v0"); // v0 | v1 | fold

    // Streaming/Fri flags reserved for future expansion (kept to avoid churn).
    let _stream = parse_arg::<u32>("stream", 0) != 0;
    let _chunk_log2: usize = parse_arg("chunk-log2", 12);
    let _fri_out_chunk_log2: usize = parse_arg("fri-out-chunk-log2", 12);

    // Folding knobs (forwarded via env to sezkp-fold).
    let fold_mode = parse_str("fold-mode", "balanced"); // balanced | minram
    let wrap_cadence: u32 = parse_arg("wrap-cadence", 0);

    fs::create_dir_all(&out_dir).context("mkdir out-dir")?;

    let trace_path = out_dir.join("trace.cbor");
    let blocks_path = out_dir.join("blocks.cbor");
    let manifest_path = out_dir.join("manifest.cbor");
    let proof_path = out_dir.join("proof.cbor");

    // 1) Run the "VM" and write the trace.
    let tf: TraceFile = sezkp_vm_riscv::make_trace(steps);
    write_trace_cbor(&trace_path, &tf).context("write trace")?;
    println!(
        "VM → trace.cbor (t={steps}, tau=2) at {}",
        trace_path.display()
    );

    // 2) Partition into σ_k blocks of size b.
    let blocks = partition_trace(&tf, b);
    sezkp_core::io::write_block_summaries_cbor(&blocks_path, &blocks).context("write blocks")?;
    println!(
        "Partitioned → {} blocks → {}",
        blocks.len(),
        blocks_path.display()
    );

    // 3) Commit leaves → manifest root (used by all backends).
    let manifest = commit_block_file(&blocks_path, &manifest_path)?;
    println!(
        "Committed leaves, root={} → {}",
        hex::encode(manifest.root),
        manifest_path.display()
    );

    // 4) Prove per backend. For folding, forward CLI knobs via env so the
    //    backend can pick them up (`opts_from_env` inside sezkp-fold).
    if matches!(proto.as_str(), "fold" | "v2") {
        env::set_var("SEZKP_FOLD_MODE", fold_mode.clone());
        env::set_var("SEZKP_WRAP_CADENCE", wrap_cadence.to_string());
    }

    let artifact = match proto.as_str() {
        "v0" => {
            let art = StarkIOP::prove(&blocks, manifest.root)?;
            println!("Proved (stark-v0)");
            art
        }
        "v1" => {
            let art = StarkV1::prove(&blocks, manifest.root)?;
            println!("Proved (stark-v1)");
            art
        }
        "fold" | "v2" => {
            let art = FoldBackend::prove(&blocks, manifest.root)?;
            println!(
                "Proved (fold-v2) [mode={}, wrap-cadence={}]",
                fold_mode, wrap_cadence
            );
            art
        }
        other => bail!("unknown --proto '{other}'; use v0 | v1 | fold"),
    };

    sezkp_core::io::write_proof_artifact_cbor(&proof_path, &artifact).context("write proof")?;
    println!("Wrote proof → {}", proof_path.display());

    // 5) Verify: blocks vs manifest, then cryptographic verification.
    verify_block_file_against_manifest(&blocks_path, &manifest_path)
        .context("blocks/manifest mismatch")?;
    match proto.as_str() {
        "v0" => StarkIOP::verify(&artifact, &blocks, manifest.root)?,
        "v1" => StarkV1::verify(&artifact, &blocks, manifest.root)?,
        "fold" | "v2" => FoldBackend::verify(&artifact, &blocks, manifest.root)?,
        _ => unreachable!(),
    }
    println!("Verified OK.");

    Ok(())
}
