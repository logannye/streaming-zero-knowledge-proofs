//! sezkp-cli — reference command-line interface for SEZKP
//!
//! This binary drives the end-to-end “streaming, sublinear-space ZKP” workflow:
//! 1) simulate a synthetic trace and partition into σ_k blocks,
//! 2) commit blocks to a Merkle root (manifest),
//! 3) produce a proof (folding or STARK backends; streaming or in-memory),
//! 4) verify a proof (prefer streaming to keep memory sublinear),
//! 5) convert block files to JSONL for streaming use.
//!
//! ### Examples
//! ```text
//! # 1) Simulate and write CBOR blocks
//! sezkp-cli simulate --t 32768 --b 512 --tau 8 --out-blocks blocks.cbor
//!
//! # 2) Commit blocks -> manifest
//! sezkp-cli commit --blocks blocks.cbor --out manifest.cbor
//!
//! # 3) Prove with folding backend (streaming input)
//! sezkp-cli prove --backend fold --blocks blocks.jsonl --manifest manifest.cbor \
//!   --out proof.cbor --fold-mode minram --fold-cache 64 --wrap-cadence 0 --stream
//!
//! # 4) Verify (streaming path preferred for sublinear memory)
//! sezkp-cli verify --backend fold --blocks blocks.jsonl --manifest manifest.cbor \
//!   --proof proof.cbor
//!
//! # 5) Convert blocks to JSONL (NDJSON) for streaming
//! sezkp-cli export-jsonl --input blocks.cbor --output blocks.jsonl
//! ```
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
use sezkp_core::ProvingBackend;
use sezkp_core::{
    io::{
        read_block_summaries_auto, read_proof_auto, stream_block_summaries_auto, write_proof_auto,
    },
    ProofArtifact,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::{info, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Top-level CLI.
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

/// CLI subcommands.
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Simulate a synthetic trace and partition it into σ_k blocks.
    ///
    /// If --out-blocks ends with `.jsonl` or `.ndjson`, writes NDJSON for streaming.
    Simulate {
        /// Trace length T (> 0).
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u32).range(1..))]
        t: u32,

        /// Number of blocks b (1..=T).
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..))]
        b: u32,

        /// Parameter τ (> 0), e.g., branching/arity in the synthetic generator.
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..))]
        tau: u8,

        /// Output path for σ_k block summaries (CBOR/JSON/JSONL/NDJSON).
        #[arg(long, default_value = "blocks.cbor")]
        out_blocks: PathBuf,
    },

    /// Commit blocks to a Merkle root and write a manifest.
    Commit {
        /// Input path to σ_k block summaries (CBOR/JSON/JSONL/NDJSON).
        #[arg(long)]
        blocks: PathBuf,

        /// Output path for the manifest (CBOR/JSON).
        #[arg(long, default_value = "manifest.cbor")]
        out: PathBuf,
    },

    /// Check that a blocks file matches a manifest.
    VerifyCommit {
        /// Input path to σ_k block summaries (CBOR/JSON/JSONL/NDJSON).
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON).
        #[arg(long)]
        manifest: PathBuf,
    },

    /// Convert blocks (CBOR/JSON/JSONL/NDJSON) → JSON Lines (NDJSON) for streaming proofs.
    ExportJsonl {
        /// Input blocks path (CBOR/JSON/JSONL/NDJSON).
        #[arg(long)]
        input: PathBuf,
        /// Output JSONL path.
        #[arg(long)]
        output: PathBuf,
    },

    /// Produce a ZK proof with the chosen backend.
    Prove {
        /// Proof backend.
        #[arg(value_enum, long)]
        backend: BackendOpt,

        /// Input path to σ_k block summaries (CBOR/JSON/JSONL/NDJSON).
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON).
        #[arg(long)]
        manifest: PathBuf,

        /// Output path for proof artifact (CBOR/JSON).
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
        ///
        /// Effective with `.jsonl`/`.ndjson` inputs; `.json`/`.cbor` may degrade to in-memory iteration.
        #[arg(long, default_value_t = false)]
        stream: bool,

        /// Assume the blocks file has already been verified against the manifest.
        ///
        /// Skips the extra pre-check inside `prove` to avoid redundant I/O/RSS.
        #[arg(long, default_value_t = false)]
        assume_committed: bool,
    },

    /// Verify a proof produced by the chosen backend.
    Verify {
        /// Proof backend.
        #[arg(value_enum, long)]
        backend: BackendOpt,

        /// Input path to σ_k block summaries (CBOR/JSON/JSONL/NDJSON).
        #[arg(long)]
        blocks: PathBuf,

        /// Input path to manifest (CBOR/JSON).
        #[arg(long)]
        manifest: PathBuf,

        /// Input path to proof artifact (CBOR/JSON).
        #[arg(long)]
        proof: PathBuf,

        /// Assume the blocks file has already been verified against the manifest.
        ///
        /// Skips the extra pre-check inside `verify` to avoid redundant I/O/RSS.
        #[arg(long, default_value_t = false)]
        assume_committed: bool,
    },
}

/// Available proving/verification backends.
#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum BackendOpt {
    /// Folding-based aggregation backend.
    Fold,
    /// STARK v1 backend (PIOP/FRI; streaming-friendly).
    Stark,
}

/// Folding driver modes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum FoldModeOpt {
    /// Balanced space/time (keeps O(T) endpoints).
    Balanced,
    /// Min-RAM mode (recompute endpoints; sublinear space).
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
            assume_committed,
        } => prove(
            backend,
            blocks,
            manifest,
            out,
            fold_mode,
            fold_cache,
            wrap_cadence,
            stream,
            assume_committed,
        ),

        Cmd::Verify {
            backend,
            blocks,
            manifest,
            proof,
            assume_committed,
        } => verify(backend, blocks, manifest, proof, assume_committed),
    }
}

/// Initialize tracing with an env-driven filter (default INFO).
///
/// Set `RUST_LOG=debug` (or `trace`) to increase verbosity, e.g.:
/// `RUST_LOG=sezkp_cli=debug,sezkp_core=info sezkp-cli prove ...`
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
///
/// # Errors
/// Returns an error if the directory cannot be created.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating parent directory {}", dir.display()))?;
        }
    }
    Ok(())
}

/// Return `true` if the path’s extension suggests JSON Lines (`.jsonl` or `.ndjson`).
fn is_jsonl_like(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .is_some_and(|ext| ext == "jsonl" || ext == "ndjson")
}

fn simulate(t: u32, b: u32, tau: u8, out_blocks: PathBuf) -> Result<()> {
    let _span = info_span!("simulate", t, b, tau, out = %out_blocks.display()).entered();
    use sezkp_trace::{generator::generate_trace, partition::partition_trace};

    if b > t {
        bail!("number of blocks b ({b}) cannot exceed trace length T ({t})");
    }

    info!("generating synthetic trace");
    let trace = generate_trace(t as u64, tau);
    let blocks = partition_trace(&trace, b);

    ensure_parent_dir(&out_blocks)?;

    // If the extension is .jsonl/.ndjson, write NDJSON for streaming.
    if is_jsonl_like(&out_blocks) {
        let f = File::create(&out_blocks)
            .with_context(|| format!("create {}", out_blocks.display()))?;
        let mut w = BufWriter::new(f);
        for blk in &blocks {
            serde_json::to_writer(&mut w, blk).context("serialize block as JSON line")?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
    } else {
        sezkp_core::io::write_block_summaries_auto(&out_blocks, &blocks).with_context(|| {
            format!("writing σ_k blocks (auto format) to {}", out_blocks.display())
        })?;
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
    let _span = info_span!("commit", blocks = %blocks.display(), out = %out.display()).entered();
    use sezkp_merkle::commit_block_file;

    info!("committing blocks");
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
    let _span =
        info_span!("verify_commit", blocks = %blocks.display(), manifest = %manifest.display())
            .entered();
    use sezkp_merkle::verify_block_file_against_manifest;

    info!("verifying commit");
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

/// Convert any blocks file (CBOR/JSON/JSONL/NDJSON) into JSON Lines for streaming proofs.
///
/// # Errors
/// Propagates I/O and serialization errors.
fn export_jsonl(input: PathBuf, output: PathBuf) -> Result<()> {
    let _span =
        info_span!("export_jsonl", infile = %input.display(), outfile = %output.display())
            .entered();
    info!("opening input stream");
    let iter = stream_block_summaries_auto(&input).context("open input stream")?;

    ensure_parent_dir(&output)?;
    let f = File::create(&output).with_context(|| format!("create {}", output.display()))?;
    let mut w = BufWriter::new(f);

    let mut n = 0usize;
    for item in iter {
        let blk = item?;
        serde_json::to_writer(&mut w, &blk).context("serialize block as JSON line")?;
        w.write_all(b"\n")?;
        n += 1;
    }
    w.flush()?;

    println!("Exported {n} blocks → {}", output.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove(
    backend: BackendOpt,
    blocks: PathBuf,
    manifest: PathBuf,
    out: PathBuf,
    fold_mode: FoldModeOpt,
    fold_cache: usize,
    wrap_cadence: u32,
    stream: bool,
    assume_committed: bool,
) -> Result<()> {
    let _span = info_span!(
        "prove",
        ?backend,
        blocks = %blocks.display(),
        manifest = %manifest.display(),
        out = %out.display(),
        stream
    )
    .entered();

    use sezkp_core::prover::StreamingProver;
    use sezkp_merkle::{read_manifest_auto, verify_block_file_against_manifest};

    // Skip redundant blocks/manifest pre-check if caller already verified it.
    if !assume_committed {
        verify_block_file_against_manifest(&blocks, &manifest)
            .context("blocks/manifest mismatch")?;
    }

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

    // Choose streaming path iff requested.
    let artifact: ProofArtifact = match (backend, stream) {
        (BackendOpt::Fold, true) => {
            use sezkp_fold::FoldAgg;

            // Decide on a proof stream path adjacent to the artifact.
            let mut stream_path = out.clone();
            stream_path.set_extension("cborseq");
            // Tell the backend where to write the streaming proof.
            std::env::set_var("SEZKP_PROOF_STREAM_PATH", &stream_path);

            let iter = stream_block_summaries_auto(&blocks).context("open blocks stream")?;
            let art = StreamingProver::<FoldAgg>::prove_stream_iter(iter, man.root)
                .context("fold backend streaming proof failed")?;

            println!(
                "Proved (streaming/fold) → artifact={} stream={}",
                out.display(),
                stream_path.display()
            );
            art
        }
        (BackendOpt::Fold, false) => {
            use sezkp_fold::FoldAgg;
            let blocks_vec = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StreamingProver::<FoldAgg>::prove(&blocks_vec, man.root)
                .context("fold backend proof failed")?
        }
        // --- STARK v1 path (always ZK). Prefer streaming entrypoint when asked.
        (BackendOpt::Stark, true) => {
            use sezkp_stark::StarkV1;
            let blocks_vec = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StarkV1::prove_streaming(&blocks_vec, man.root)
                .context("stark-v1 streaming proof failed")?
        }
        (BackendOpt::Stark, false) => {
            use sezkp_stark::StarkV1;
            let blocks_vec = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StarkV1::prove(&blocks_vec, man.root).context("stark-v1 proof failed")?
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

fn verify(
    backend: BackendOpt,
    blocks: PathBuf,
    manifest: PathBuf,
    proof: PathBuf,
    assume_committed: bool,
) -> Result<()> {
    let _span = info_span!(
        "verify",
        ?backend,
        blocks = %blocks.display(),
        manifest = %manifest.display(),
        proof = %proof.display()
    )
    .entered();

    use sezkp_core::prover::StreamingProver;
    use sezkp_merkle::{read_manifest_auto, verify_block_file_against_manifest};

    // Skip redundant blocks/manifest pre-check if caller already verified it.
    if !assume_committed {
        verify_block_file_against_manifest(&blocks, &manifest)
            .context("blocks/manifest mismatch")?;
    }

    let man = read_manifest_auto(&manifest).context("reading manifest")?;
    let artifact = read_proof_auto(&proof)
        .with_context(|| format!("reading proof artifact from {}", proof.display()))?;

    match backend {
        BackendOpt::Fold => {
            use sezkp_fold::FoldAgg;

            // Prefer streaming verify to keep memory sublinear.
            let iter = stream_block_summaries_auto(&blocks).context("open blocks stream")?;
            StreamingProver::<FoldAgg>::verify_stream_iter(&artifact, iter, man.root)
                .context("fold backend verification failed")?;
        }
        BackendOpt::Stark => {
            // v1 STARK verifier (manifest-root checked inside).
            use sezkp_stark::StarkV1;
            let blocks_vec = read_block_summaries_auto(&blocks).context("reading blocks")?;
            StarkV1::verify(&artifact, &blocks_vec, man.root)
                .context("stark-v1 verification failed")?;
        }
    }

    println!("OK: proof verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_commit_smoke() {
        // Ensure subcommand/args parse; do not run anything.
        let _ = Cli::parse_from([
            "sezkp-cli",
            "commit",
            "--blocks",
            "blocks.cbor",
            "--out",
            "manifest.cbor",
        ]);
    }
}
