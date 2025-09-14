// crates/sezkp-cli/src/main.rs

#![forbid(unsafe_code)]
#![deny(
    rust_2018_idioms,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo
)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sezkp_core::{
    io::{
        read_block_summaries_auto, read_proof_auto, stream_block_summaries_auto, write_proof_auto,
    },
    BlockSummary,
    ProofArtifact,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "sezkp-cli",
    about = "SEZKP reference CLI",
    long_about = "SEZKP reference CLI.\n\nUse this tool to generate traces, commit block summaries, and produce/verify streaming proofs.",
    version = env!("CARGO_PKG_VERSION"),
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Simulate a synthetic trace and partition it into σ_k blocks.
    /// If --out-blocks ends with `.jsonl`, writes NDJSON for streaming.
    Simulate {
        /// Trace length T (>0)
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u32).range(1..))]
        t: u32,

        /// Number of blocks b (>0)
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..))]
        b: u32,

        /// Parameter τ (>0), e.g., branching/arity in the synthetic generator
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..))]
        tau: u8,

        /// Output path for σ_k block summaries (CBOR/JSON/JSONL)
        #[arg(long, default_value = "blocks.cbor")]
        out_blocks: PathBuf,
    },

    /// Commit blocks to a Merkle root and write a manifest
    Commit {
        /// Input path to σ_k block summaries (CBOR/JSON/JSONL)
        #[arg(long)]
        blocks: PathBuf,

        /// Output path for the manifest (CBOR/JSON)
        #[arg(long, default_value = "manifest.cbor")]
        out: PathBuf,
    },

    /// Check that a blocks file matches a manifest
    VerifyCommit {
        /// Input path to σ_k block summaries (CBOR/JSON/JSONL)
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON)
        #[arg(long)]
        manifest: PathBuf,
    },

    /// Convert blocks (CBOR/JSON/JSONL) -> JSON Lines (NDJSON) for streaming proofs
    ExportJsonl {
        /// Input blocks path (CBOR/JSON/JSONL)
        #[arg(long)]
        input: PathBuf,
        /// Output JSONL path
        #[arg(long)]
        output: PathBuf,
    },

    /// Produce a ZK (mock) proof with the chosen backend
    Prove {
        /// Proof backend
        #[arg(value_enum, long)]
        backend: BackendOpt,

        /// Input path to σ_k block summaries (CBOR/JSON/JSONL)
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON)
        #[arg(long)]
        manifest: PathBuf,

        /// Output path for proof artifact (CBOR/JSON)
        #[arg(long, default_value = "proof.cbor")]
        out: PathBuf,

        /* ---------- fold-specific flags (honored via environment) ---------- */
        /// Folding driver mode (balanced keeps O(T) endpoints; minram recomputes).
        #[arg(long, value_enum, default_value_t = FoldModeOpt::Balanced)]
        fold_mode: FoldModeOpt,

        /// Endpoint LRU capacity for minram mode (0 disables caching).
        #[arg(long, default_value_t = 64)]
        fold_cache: usize,

        /// Emit a wrap proof every k folds (0 = never).
        #[arg(long, default_value_t = 0)]
        wrap_cadence: u32,

        /// Stream blocks instead of loading all into memory.
        /// Effective with `.jsonl` inputs; `.json`/`.cbor` may degrade to in-memory iteration.
        #[arg(long, default_value_t = false)]
        stream: bool,
    },

    /// Verify a proof produced by the chosen backend
    Verify {
        /// Proof backend
        #[arg(value_enum, long)]
        backend: BackendOpt,

        /// Input path to σ_k block summaries (CBOR/JSON/JSONL)
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON)
        #[arg(long)]
        manifest: PathBuf,

        /// Input path to proof artifact (CBOR/JSON)
        #[arg(long)]
        proof: PathBuf,
    },
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum BackendOpt {
    /// Folding-based aggregation backend
    Fold,
    /// STARK IOP backend
    Stark,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum FoldModeOpt {
    Balanced,
    Minram,
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Simulate {
            t,
            b,
            tau,
            out_blocks,
        } => simulate(t, b, tau, out_blocks),

        Cmd::Commit { blocks, out } => commit_blocks(blocks, out),

        Cmd::VerifyCommit { blocks, manifest } => verify_commit(blocks, manifest),

        Cmd::ExportJsonl { input, output } => export_jsonl(input, output),

        Cmd::Prove {
            backend,
            blocks,
            manifest,
            out,
            fold_mode,
            fold_cache,
            wrap_cadence,
            stream,
        } => prove(
            backend,
            blocks,
            manifest,
            out,
            fold_mode,
            fold_cache,
            wrap_cadence,
            stream,
        ),

        Cmd::Verify {
            backend,
            blocks,
            manifest,
            proof,
        } => verify(backend, blocks, manifest, proof),
    }
}

/// Initialize tracing with an env-driven filter (default INFO).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer().with_target(false).with_level(true).compact();

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}

/// Ensure the parent directory for a file exists.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating parent directory {}", dir.display()))?;
        }
    }
    Ok(())
}

fn simulate(t: u32, b: u32, tau: u8, out_blocks: PathBuf) -> Result<()> {
    use sezkp_trace::{generator::generate_trace, partition::partition_trace};

    if b > t {
        bail!("number of blocks b ({b}) cannot exceed trace length T ({t})");
    }

    info!(t, b, tau, "generating synthetic trace");
    let trace = generate_trace(t as u64, tau);
    let blocks = partition_trace(&trace, b);

    ensure_parent_dir(&out_blocks)?;

    // If the extension is .jsonl, write NDJSON for streaming.
    let ext = out_blocks
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());

    if ext.as_deref() == Some("jsonl") {
        let f = File::create(&out_blocks)
            .with_context(|| format!("create {}", out_blocks.display()))?;
        let mut w = BufWriter::new(f);
        for b in &blocks {
            let line = serde_json::to_string(b).context("serialize block to JSON line")?;
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
    } else {
        sezkp_core::io::write_block_summaries_auto(&out_blocks, &blocks)
            .with_context(|| format!("writing σ_k blocks to {}", out_blocks.display()))?;
    }

    println!(
        "Simulated trace: T={}, b={}, τ={} → {} blocks → {}",
        t,
        b,
        tau,
        blocks.len(),
        out_blocks.display()
    );
    Ok(())
}

fn commit_blocks(blocks: PathBuf, out: PathBuf) -> Result<()> {
    use sezkp_merkle::commit_block_file;

    info!(blocks=%blocks.display(), out=%out.display(), "committing blocks");
    ensure_parent_dir(&out)?;

    commit_block_file(&blocks, &out).with_context(|| {
        format!(
            "committing {} to manifest {}",
            blocks.display(),
            out.display()
        )
    })?;

    println!("Committed {} → {}", blocks.display(), out.display());
    Ok(())
}

fn verify_commit(blocks: PathBuf, manifest: PathBuf) -> Result<()> {
    use sezkp_merkle::verify_block_file_against_manifest;

    info!(blocks=%blocks.display(), manifest=%manifest.display(), "verifying commit");
    verify_block_file_against_manifest(&blocks, &manifest).with_context(|| {
        format!(
            "verifying that {} matches manifest {}",
            blocks.display(),
            manifest.display()
        )
    })?;

    println!(
        "OK: {} matches manifest {}",
        blocks.display(),
        manifest.display()
    );
    Ok(())
}

/// Convert any blocks file (CBOR/JSON/JSONL) into JSON Lines for streaming proofs.
fn export_jsonl(input: PathBuf, output: PathBuf) -> Result<()> {
    info!(infile=%input.display(), outfile=%output.display(), "export to jsonl");
    let iter = stream_block_summaries_auto(&input).context("open input stream")?;

    ensure_parent_dir(&output)?;
    let f = File::create(&output).with_context(|| format!("create {}", output.display()))?;
    let mut w = BufWriter::new(f);

    let mut n = 0usize;
    for item in iter {
        let b = item?;
        let line = serde_json::to_string(&b).context("serialize block to JSON line")?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
        n += 1;
    }
    w.flush()?;

    println!("Exported {n} blocks → {}", output.display());
    Ok(())
}

fn prove(
    backend: BackendOpt,
    blocks: PathBuf,
    manifest: PathBuf,
    out: PathBuf,
    fold_mode: FoldModeOpt,
    fold_cache: usize,
    wrap_cadence: u32,
    stream: bool,
) -> Result<()> {
    use sezkp_core::prover::StreamingProver;
    use sezkp_merkle::{read_manifest_auto, verify_block_file_against_manifest};

    info!(?backend, blocks=%blocks.display(), manifest=%manifest.display(), out=%out.display(), stream, "proving");
    verify_block_file_against_manifest(&blocks, &manifest).context("blocks/manifest mismatch")?;

    let man = read_manifest_auto(&manifest).context("reading manifest")?;

    // Honor fold-driver flags via env vars the backend reads at prove-time.
    if matches!(backend, BackendOpt::Fold) {
        std::env::set_var(
            "SEZKP_FOLD_MODE",
            match fold_mode {
                FoldModeOpt::Balanced => "balanced",
                FoldModeOpt::Minram => "minram",
            },
        );
        std::env::set_var("SEZKP_FOLD_CACHE", fold_cache.to_string());
        std::env::set_var("SEZKP_WRAP_CADENCE", wrap_cadence.to_string());
    }

    // Choose streaming path iff requested (true streaming with .jsonl; other formats will
    // still iterate but may allocate the full Vec internally depending on the reader).
    let artifact: ProofArtifact = match (backend, stream) {
        (BackendOpt::Fold, true) => {
            use sezkp_fold::FoldAgg;
            let iter = stream_block_summaries_auto(&blocks).context("open stream")?;
            StreamingProver::<FoldAgg>::prove_stream_iter(iter, man.root)
                .context("fold backend streaming proof failed")?
        }
        (BackendOpt::Fold, false) => {
            use sezkp_fold::FoldAgg;
            let blocks_v = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StreamingProver::<FoldAgg>::prove(&blocks_v, man.root)
                .context("fold backend proof failed")?
        }
        (BackendOpt::Stark, _) => {
            use sezkp_stark::StarkIOP;
            let blocks_v = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StreamingProver::<StarkIOP>::prove(&blocks_v, man.root)
                .context("stark backend proof failed")?
        }
    };

    ensure_parent_dir(&out)?;
    write_proof_auto(&out, &artifact)
        .with_context(|| format!("writing proof to {}", out.display()))?;

    println!(
        "Proved with {:?}, wrote {} ({} bytes)",
        artifact.backend,
        out.display(),
        artifact.proof_bytes.len()
    );
    Ok(())
}

fn verify(backend: BackendOpt, blocks: PathBuf, manifest: PathBuf, proof: PathBuf) -> Result<()> {
    use sezkp_core::prover::StreamingProver;
    use sezkp_merkle::{read_manifest_auto, verify_block_file_against_manifest};

    info!(?backend, blocks=%blocks.display(), manifest=%manifest.display(), proof=%proof.display(), "verifying proof");
    verify_block_file_against_manifest(&blocks, &manifest).context("blocks/manifest mismatch")?;

    let man = read_manifest_auto(&manifest).context("reading manifest")?;
    // NEW: verify accepts `.jsonl` by streaming then collecting to Vec for the backend API.
    let blocks_v = read_blocks_for_verify(&blocks).context("reading/streaming blocks for verify")?;
    let artifact = read_proof_auto(&proof)
        .with_context(|| format!("reading proof artifact from {}", proof.display()))?;

    match backend {
        BackendOpt::Fold => {
            use sezkp_fold::FoldAgg;
            StreamingProver::<FoldAgg>::verify(&artifact, &blocks_v, man.root)
                .context("fold backend verification failed")?;
        }
        BackendOpt::Stark => {
            use sezkp_stark::StarkIOP;
            StreamingProver::<StarkIOP>::verify(&artifact, &blocks_v, man.root)
                .context("stark backend verification failed")?;
        }
    }

    println!("OK: proof verified");
    Ok(())
}

/// Helper: read blocks for verification, accepting `.jsonl` by streaming.
fn read_blocks_for_verify(path: &Path) -> Result<Vec<BlockSummary>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());

    if ext.as_deref() == Some("jsonl") {
        let mut out = Vec::new();
        let iter = stream_block_summaries_auto(path).context("open jsonl stream")?;
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    } else {
        read_block_summaries_auto(path)
    }
}
