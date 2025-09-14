// crates/sezkp-fold/src/lib.rs

//! Folding/Accumulation line (height-compressed scheduler + ARE + driver).

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

/// Public API traits and small types.
pub mod api;
/// Algebraic Replay Engine types (Pi, InterfaceWitness, …).
pub mod are;
/// Micro-proof for interface replay (MAC today; micro-STARK later).
pub mod are_replay;
/// Scheduler driver glue + bundle format.
pub mod driver;
/// Concrete gadgets: Fold & Wrap.
pub mod fold;
/// Concrete gadget: Leaf.
pub mod leaf;
/// Bundle verifier (bottom-up).
pub mod verify;

pub use crate::driver::run_pipeline;
pub use crate::fold::{CryptoFold, CryptoWrap, CryptoWrapProof};
pub use crate::leaf::{CryptoLeaf, CryptoLeafProof};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sezkp_core::{BackendKind, BlockSummary, ProofArtifact, ProvingBackend, ProvingBackendStream};

use crate::api::{Commitment, DriverOptions, FoldMode};
use crate::are::Pi;

/* ------------------------- versioned payload envelope ---------------------- */

#[repr(u16)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum WireVersion {
    V1 = 1,
    V2 = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PayloadV1 {
    bundle_json: Vec<u8>,
    root_c: Commitment,
    root_pi: Pi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PayloadV2 {
    bundle_cbor: Vec<u8>,
    root_c: Commitment,
    root_pi: Pi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum WireEnvelope {
    V1(PayloadV1),
    V2(PayloadV2),
}

fn bundle_top<Lp, Fp, Wp>(b: &driver::FoldProofBundle<Lp, Fp, Wp>) -> (Commitment, Pi) {
    if let Some(((c, p), _, _, _)) = b.folds.last() {
        (*c, *p)
    } else if let Some((c, p, _)) = b.leaves.last() {
        (*c, *p)
    } else {
        (Commitment::new([0u8; 32], 0), Pi::default())
    }
}

/* ----------------------------- env -> options ------------------------------ */

fn opts_from_env(mut opts: DriverOptions) -> DriverOptions {
    if let Ok(mode) = std::env::var("SEZKP_FOLD_MODE") {
        match mode.to_ascii_lowercase().as_str() {
            "balanced" => opts.fold_mode = FoldMode::Balanced,
            "minram" => opts.fold_mode = FoldMode::MinRam,
            _ => {}
        }
    }
    if let Ok(k) = std::env::var("SEZKP_WRAP_CADENCE") {
        if let Ok(v) = k.parse::<u32>() {
            opts.wrap_cadence = v;
        }
    }
    // Parse as u32 to match DriverOptions::endpoint_cache
    if let Ok(c) = std::env::var("SEZKP_FOLD_CACHE") {
        if let Ok(v) = c.parse::<u32>() {
            opts.endpoint_cache = v;
        }
    }
    opts
}

/* --------------------------- ProvingBackend (batch) ------------------------ */

impl ProvingBackend for FoldBackend {
    fn prove(blocks: &[BlockSummary], _manifest_root: [u8; 32]) -> Result<ProofArtifact> {
        let opts = opts_from_env(api::DriverOptions::default());
        let bundle = run_pipeline::<leaf::CryptoLeaf, fold::CryptoFold, fold::CryptoWrap>(
            blocks, &opts,
        );
        let (root_c, root_pi) = bundle_top(&bundle);

        let bundle_cbor = serde_cbor::to_vec(&bundle).context("serializing bundle (CBOR)")?;
        let payload = WireEnvelope::V2(PayloadV2 {
            bundle_cbor,
            root_c,
            root_pi,
        });
        let proof_bytes =
            bincode::serialize(&(WireVersion::V2, &payload)).context("serializing fold envelope")?;

        Ok(ProofArtifact {
            backend: BackendKind::Stark, // reuse enum; payload carries version
            manifest_root: root_c.root,
            proof_bytes,
            meta: serde_json::json!({
                "proto": "fold-v2",
                "n_blocks": bundle.n_blocks,
                "wraps": bundle.wraps.len(),
                "mode": format!("{:?}", opts.fold_mode),
            }),
        })
    }

    fn verify(
        artifact: &ProofArtifact,
        _blocks: &[BlockSummary],
        manifest_root: [u8; 32],
    ) -> Result<()> {
        // Decode outer envelope.
        let (ver, env): (WireVersion, WireEnvelope) =
            bincode::deserialize(&artifact.proof_bytes).context("decoding fold envelope")?;

        // Decode bundle depending on version.
        let (bundle_root_c, bundle_root_pi, bundle_bytes, is_cbor) = match env {
            WireEnvelope::V1(p) => (p.root_c, p.root_pi, p.bundle_json, false),
            WireEnvelope::V2(p) => (p.root_c, p.root_pi, p.bundle_cbor, true),
        };

        // Decode inner bundle.
        let bundle: driver::FoldProofBundle<
            leaf::CryptoLeafProof,
            fold::CryptoFoldProof,
            fold::CryptoWrapProof,
        > = if is_cbor {
            serde_cbor::from_slice(&bundle_bytes).context("decoding CBOR bundle")?
        } else {
            serde_json::from_slice(&bundle_bytes).context("decoding JSON bundle")?
        };

        // Cryptographic verification.
        verify::verify_bundle::<leaf::CryptoLeaf, fold::CryptoFold, CryptoWrap>(&bundle)?;

        // Top consistency.
        let (top_c, top_pi) = bundle_top(&bundle);
        ensure!(
            top_c == bundle_root_c && top_pi == bundle_root_pi,
            "root mismatch in payload vs bundle"
        );

        // Bind artifact + CLI-provided manifest root to the bundle root.
        ensure!(
            artifact.manifest_root == top_c.root,
            "artifact.manifest_root does not match final fold root"
        );
        ensure!(
            manifest_root == top_c.root,
            "CLI manifest root does not match final fold root"
        );

        ensure!(
            matches!(ver, WireVersion::V1 | WireVersion::V2),
            "unsupported fold payload version"
        );
        Ok(())
    }
}

/* ---------------------- ProvingBackendStream (streaming) ------------------- */

/// Selectable folding backend (uses CryptoLeaf/CryptoFold/CryptoWrap).
#[derive(Debug, Clone, Copy, Default)]
pub struct FoldBackend;

/// Back-compat alias for older callers (CLI/bench harness).
pub use FoldBackend as FoldAgg;

/// Backend streaming state: defer to the driver’s streaming runner.
pub struct StreamState {
    drv: driver::StreamDriver<CryptoLeaf, CryptoFold, CryptoWrap>,
}

impl ProvingBackendStream for FoldBackend {
    type StreamState = StreamState;

    fn begin_stream(_manifest_root: [u8; 32]) -> Result<Self::StreamState> {
        let opts = opts_from_env(api::DriverOptions::default());
        let drv = driver::StreamDriver::new(opts);
        Ok(StreamState { drv })
    }

    fn ingest_block(state: &mut Self::StreamState, block: BlockSummary) -> Result<()> {
        state.drv.push_block(block)
    }

    fn finish_stream(state: Self::StreamState) -> Result<ProofArtifact> {
        // Capture anything we need from the driver BEFORE consuming it.
        let mode_str = format!("{:?}", state.drv.options().fold_mode);

        // This moves (consumes) the driver.
        let bundle = state.drv.finish_bundle();

        let (root_c, root_pi) = bundle_top(&bundle);
        let bundle_cbor = serde_cbor::to_vec(&bundle).context("serializing bundle (CBOR)")?;
        let payload = WireEnvelope::V2(PayloadV2 {
            bundle_cbor,
            root_c,
            root_pi,
        });
        let proof_bytes =
            bincode::serialize(&(WireVersion::V2, &payload)).context("serializing fold envelope")?;

        Ok(ProofArtifact {
            backend: BackendKind::Stark,
            manifest_root: root_c.root,
            proof_bytes,
            meta: serde_json::json!({
                "proto": "fold-v2",
                "n_blocks_streamed": bundle.n_blocks,
                "wraps": bundle.wraps.len(),
                "mode": mode_str,
                "streaming": true
            }),
        })
    }
}
