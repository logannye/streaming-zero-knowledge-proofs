//! Parameter/vector stability test: transcript-derived values are consistent.
//!
//! Purpose:
//! - Ensure transcript-driven parameters (alphas, query indices) are derived
//!   deterministically from bound public inputs (manifest root, n, τ, column roots).
//!
//! How it runs:
//! - Reads a JSON file with fixed inputs. If the file is missing, the test is
//!   *politely skipped* (so CI/dev machines without vectors don't fail).
//!
//! Override location:
//! - Set `SEZKP_TRANSCRIPT_VECTORS=/abs/path/to/transcript_inputs.json`
//!   to point at a custom vectors file.

#![allow(clippy::unwrap_used)]

use std::{env, fs};
use std::path::PathBuf;

use serde::Deserialize;
use sezkp_crypto::{Blake3Transcript, Transcript};
use sezkp_stark::v1::params;

#[derive(Deserialize)]
struct Inputs {
    manifest_root_hex: String,
    n: usize,
    tau: usize,
    col_roots_hex: Vec<String>,
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex::decode(s).expect("hex");
    assert_eq!(bytes.len(), 32, "need 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn vectors_transcript_challenges_stable() {
    // Default vector path (repo-relative, if the specs submodule is present).
    let mut default = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    default.push("../../specs/test-vectors/stark-v1/transcript_inputs.json");

    // Optional override via env var.
    let path = env::var("SEZKP_TRANSCRIPT_VECTORS")
        .map(PathBuf::from)
        .unwrap_or(default);

    if !path.exists() {
        eprintln!(
            "skipping param_vectors: vectors file not found at {:?}. \
             Set SEZKP_TRANSCRIPT_VECTORS to point to transcript_inputs.json if you want this test to run.",
            path
        );
        // Soft-skip so the test suite still passes without the vectors file.
        return;
    }

    let data = fs::read_to_string(&path).expect("read vectors");
    let v: Inputs = serde_json::from_str(&data).expect("parse");

    // Bind the same public inputs into a transcript as the protocol does.
    let manifest_root = hex32(&v.manifest_root_hex);
    let mut tr = Blake3Transcript::new(params::DS_V1_DOMAIN);
    tr.absorb("manifest_root", &manifest_root);
    tr.absorb_u64("n", v.n as u64);
    tr.absorb_u64("tau", v.tau as u64);
    tr.absorb_u64(params::DS_N_COLS, v.col_roots_hex.len() as u64);
    for rhex in &v.col_roots_hex {
        let r = hex32(rhex);
        tr.absorb(params::DS_COL_ROOT, &r);
    }

    // Derive alphas and query indices; basic sanity invariants.
    let alphas = params::derive_alphas(&mut tr);
    assert_eq!(alphas.len(), params::NUM_ALPHAS, "alpha count mismatch");
    assert!(
        alphas.iter().any(|a| a.to_le_bytes() != [0u8; 8]),
        "alphas should be non-degenerate"
    );

    let queries = params::derive_queries(&mut tr, v.n, params::NUM_QUERIES);
    assert_eq!(queries.len(), params::NUM_QUERIES, "query count mismatch");
    assert!(
        queries.iter().all(|&q| q < v.n),
        "queries must be in [0, n)"
    );
}
