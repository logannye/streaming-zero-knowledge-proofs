//! sezkp-bench-harness
//!
//! Run small end-to-end benchmarks (generate -> partition -> commit -> prove -> verify)
//! and append CSV rows into `benchmarks/reports/bench-<unix>.csv`.
//!
//! Usage examples:
//!   cargo run -p sezkp-bench-harness -- --profile configs/profiles/small.toml --backend stark
//!   cargo run -p sezkp-bench-harness -- --profile configs/profiles/medium.toml --backend fold

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Deserialize;

use sezkp_core::io::{write_block_summaries_cbor, write_proof_artifact_cbor};
use sezkp_core::ProvingBackend;
use sezkp_fold::FoldAgg;
use sezkp_merkle::{commit_block_file, verify_block_file_against_manifest};
use sezkp_stark::StarkIOP;
use sezkp_trace::{generator::generate_trace, partition::partition_trace};

#[derive(Debug, Deserialize)]
struct Profile {
    /// Total steps in the synthetic trace
    t: u64,
    /// Blocks per manifest leaf (σ_k size bound)
    b: u32,
    /// Number of work tapes
    tau: u8,
    /// Repetitions of the whole pipeline
    repeats: u32,
}

#[derive(Clone, Copy, Debug)]
enum BackendSel {
    Stark,
    Fold,
}

fn parse_flag(name: &str, default: &str) -> String {
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        if k == format!("--{name}") {
            return it.next().unwrap_or_else(|| default.to_string());
        }
    }
    default.to_string()
}

fn dur_ms(d: Duration) -> u128 {
    d.as_millis()
}

fn main() -> Result<()> {
    let profile_path = PathBuf::from(parse_flag("profile", "configs/profiles/small.toml"));
    let backend_str = parse_flag("backend", "stark");
    let backend = match backend_str.as_str() {
        "stark" => BackendSel::Stark,
        "fold" => BackendSel::Fold,
        other => anyhow::bail!("unknown --backend {other} (use stark|fold)"),
    };

    let profile_src = fs::read_to_string(&profile_path)
        .with_context(|| format!("read profile {:?}", profile_path))?;
    let profile: Profile = toml::from_str(&profile_src).context("parse profile toml")?;
    println!(
        "Profile: t={}, b={}, tau={}, repeats={}, backend={backend_str}",
        profile.t, profile.b, profile.tau, profile.repeats
    );

    fs::create_dir_all("benchmarks/reports").ok();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let csv_path = PathBuf::from(format!("benchmarks/reports/bench-{ts}.csv"));
    let mut csv = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&csv_path)?;
    writeln!(csv, "timestamp,backend,t,b,tau,repeat,stage,ms,extra")?;

    for rep in 0..profile.repeats {
        // temp paths per repeat
        let blocks_path = PathBuf::from(format!("benchmarks/tmp-blocks-{ts}-{rep}.cbor"));
        let manifest_path = PathBuf::from(format!("benchmarks/tmp-manifest-{ts}-{rep}.cbor"));
        let proof_path = PathBuf::from(format!("benchmarks/tmp-proof-{ts}-{rep}.cbor"));

        fs::create_dir_all("benchmarks").ok();

        // 1) generate trace
        let t0 = Instant::now();
        let tf = generate_trace(profile.t, profile.tau);
        let t_gen = t0.elapsed();

        writeln!(
            csv,
            "{ts},{backend_str},{},{},{},{},gen,{},",
            profile.t,
            profile.b,
            profile.tau,
            rep,
            dur_ms(t_gen)
        )?;

        // 2) partition
        let t0 = Instant::now();
        let blocks = partition_trace(&tf, profile.b);
        let t_part = t0.elapsed();
        writeln!(
            csv,
            "{ts},{backend_str},{},{},{},{},partition,{},n_blocks={}",
            profile.t,
            profile.b,
            profile.tau,
            rep,
            dur_ms(t_part),
            blocks.len()
        )?;

        // 3) commit leaves → manifest
        write_block_summaries_cbor(&blocks_path, &blocks)?;
        let t0 = Instant::now();
        let manifest = commit_block_file(&blocks_path, &manifest_path)?;
        let t_commit = t0.elapsed();
        writeln!(
            csv,
            "{ts},{backend_str},{},{},{},{},commit,{},root={}",
            profile.t,
            profile.b,
            profile.tau,
            rep,
            dur_ms(t_commit),
            hex::encode(manifest.root)
        )?;

        // 4) prove
        let t0 = Instant::now();
        let art = match backend {
            BackendSel::Stark => StarkIOP::prove(&blocks, manifest.root)?,
            BackendSel::Fold => FoldAgg::prove(&blocks, manifest.root)?,
        };
        let t_prove = t0.elapsed();
        write_proof_artifact_cbor(&proof_path, &art)?;
        writeln!(
            csv,
            "{ts},{backend_str},{},{},{},{},prove,{},proof_bytes={}",
            profile.t,
            profile.b,
            profile.tau,
            rep,
            dur_ms(t_prove),
            art.proof_bytes.len()
        )?;

        // 5) verify (manifest+proof)
        let t0 = Instant::now();
        verify_block_file_against_manifest(&blocks_path, &manifest_path)?;
        match backend {
            BackendSel::Stark => StarkIOP::verify(&art, &blocks, manifest.root)?,
            BackendSel::Fold => FoldAgg::verify(&art, &blocks, manifest.root)?,
        }
        let t_verify = t0.elapsed();
        writeln!(
            csv,
            "{ts},{backend_str},{},{},{},{},verify,{},",
            profile.t,
            profile.b,
            profile.tau,
            rep,
            dur_ms(t_verify)
        )?;

        // cleanup temp files to avoid disk bloat
        let _ = fs::remove_file(&blocks_path);
        let _ = fs::remove_file(&manifest_path);
        let _ = fs::remove_file(&proof_path);
    }

    println!("Wrote report → {}", csv_path.display());
    Ok(())
}
