//! Serialization helpers for `BlockSummary` vectors and `ProofArtifact`s.
//!
//! JSON and CBOR read/write utilities with extension-based auto-detection.
//! Unknown/missing extensions are rejected for reads and default to JSON
//! for writes.
//!
//! Extras:
//! - In-memory CBOR helpers: [`to_cbor`] / [`from_cbor`]
//! - Tiny versioned payload wrapper: [`Versioned<T>`]
//! - Streaming helper: [`stream_block_summaries_auto`] returning a boxed iterator
//!   so callers can uniformly consume JSONL/NDJSON (true streaming) or JSON/CBOR
//!   (load-then-iterate) without caring about concrete iterator types.

use crate::{BlockSummary, ProofArtifact};
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor};
use std::path::Path;

/// Ensure the parent directory for a file exists (no-op if none).
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)
                .with_context(|| format!("creating parent directory {}", display(path)))?;
        }
    }
    Ok(())
}

/// ------------------------------
/// BlockSummary (Vec) I/O
/// ------------------------------

/// Read `Vec<BlockSummary>` from **JSON**.
pub fn read_block_summaries_json<P: AsRef<Path>>(path: P) -> Result<Vec<BlockSummary>> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let rdr = BufReader::new(f);
    let v: Vec<BlockSummary> =
        serde_json::from_reader(rdr).with_context(|| "deserialize JSON block summaries")?;
    Ok(v)
}

/// Write `Vec<BlockSummary>` to **JSON** (pretty).
pub fn write_block_summaries_json<P: AsRef<Path>>(path: P, v: &[BlockSummary]) -> Result<()> {
    let path_ref = path.as_ref();
    ensure_parent_dir(path_ref)?;
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let w = BufWriter::new(f);
    serde_json::to_writer_pretty(w, v).with_context(|| "serialize JSON block summaries")?;
    Ok(())
}

/// Read `Vec<BlockSummary>` from **CBOR**.
pub fn read_block_summaries_cbor<P: AsRef<Path>>(path: P) -> Result<Vec<BlockSummary>> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let mut rdr = BufReader::new(f);
    let v: Vec<BlockSummary> =
        ciborium::de::from_reader(&mut rdr).with_context(|| "deserialize CBOR block summaries")?;
    Ok(v)
}

/// Write `Vec<BlockSummary>` to **CBOR**.
pub fn write_block_summaries_cbor<P: AsRef<Path>>(path: P, v: &[BlockSummary]) -> Result<()> {
    let path_ref = path.as_ref();
    ensure_parent_dir(path_ref)?;
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    ciborium::ser::into_writer(v, &mut w).with_context(|| "serialize CBOR block summaries")?;
    Ok(())
}

/// Auto-detect read by extension `.json` / `.cbor` (case-insensitive).
pub fn read_block_summaries_auto<P: AsRef<Path>>(path: P) -> Result<Vec<BlockSummary>> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => read_block_summaries_json(path),
        Some("cbor") => read_block_summaries_cbor(path),
        Some(other) => Err(anyhow!(
            "unsupported blocks extension: {} (supported: .json, .cbor)",
            other
        )),
        None => Err(anyhow!("path has no extension (expected .json or .cbor)")),
    }
}

/// Auto-detect write (defaults to **JSON** if unknown or missing).
pub fn write_block_summaries_auto<P: AsRef<Path>>(path: P, v: &[BlockSummary]) -> Result<()> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => write_block_summaries_json(path, v),
        Some("cbor") => write_block_summaries_cbor(path, v),
        _ => write_block_summaries_json(path, v),
    }
}

/// ------------------------------
/// Streaming helper (boxed iterator)
/// ------------------------------

/// Return a boxed iterator over `BlockSummary`s for the given path.
///
/// - **`.jsonl` / `.ndjson`**: true streaming via `io_jsonl::stream_block_summaries_jsonl`
///   (no materialization; sublinear memory).
/// - **`.json` / `.cbor`**: load the vector, then iterate (compat fallback).
///
/// This uses a trait object so the concrete iterator type can differ by branch.
#[must_use]
pub fn stream_block_summaries_auto<P: AsRef<Path>>(
    path: P,
) -> Result<Box<dyn Iterator<Item = Result<BlockSummary>> + Send>> {
    // Own the path so the iterator type doesn't capture `P`.
    let pb = path.as_ref().to_owned();

    match ext_lower(&pb).as_deref() {
        Some("jsonl") | Some("ndjson") => {
            // True streaming path; iterator owns its resources.
            let it = crate::io_jsonl::stream_block_summaries_jsonl(pb)?;
            Ok(Box::new(it))
        }
        Some("json") => {
            let v = read_block_summaries_json(&pb)?;
            Ok(Box::new(v.into_iter().map(Ok)))
        }
        Some("cbor") => {
            let v = read_block_summaries_cbor(&pb)?;
            Ok(Box::new(v.into_iter().map(Ok)))
        }
        Some(other) => Err(anyhow!(
            "unsupported blocks extension: {} (supported: .json, .cbor, .jsonl, .ndjson)",
            other
        )),
        None => Err(anyhow!(
            "path has no extension (expected .json, .cbor, .jsonl, or .ndjson)"
        )),
    }
}

/// ------------------------------
/// ProofArtifact I/O
/// ------------------------------

/// Read `ProofArtifact` from **JSON**.
pub fn read_proof_artifact_json<P: AsRef<Path>>(path: P) -> Result<ProofArtifact> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let rdr = BufReader::new(f);
    let v: ProofArtifact =
        serde_json::from_reader(rdr).with_context(|| "deserialize JSON proof artifact")?;
    Ok(v)
}

/// Write `ProofArtifact` to **JSON** (pretty).
pub fn write_proof_artifact_json<P: AsRef<Path>>(path: P, v: &ProofArtifact) -> Result<()> {
    let path_ref = path.as_ref();
    ensure_parent_dir(path_ref)?;
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let w = BufWriter::new(f);
    serde_json::to_writer_pretty(w, v).with_context(|| "serialize JSON proof artifact")?;
    Ok(())
}

/// Read `ProofArtifact` from **CBOR**.
pub fn read_proof_artifact_cbor<P: AsRef<Path>>(path: P) -> Result<ProofArtifact> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let mut rdr = BufReader::new(f);
    let v: ProofArtifact =
        ciborium::de::from_reader(&mut rdr).with_context(|| "deserialize CBOR proof artifact")?;
    Ok(v)
}

/// Write `ProofArtifact` to **CBOR**.
pub fn write_proof_artifact_cbor<P: AsRef<Path>>(path: P, v: &ProofArtifact) -> Result<()> {
    let path_ref = path.as_ref();
    ensure_parent_dir(path_ref)?;
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    ciborium::ser::into_writer(v, &mut w).with_context(|| "serialize CBOR proof artifact")?;
    Ok(())
}

/// Auto-detect read for `ProofArtifact` by extension.
pub fn read_proof_artifact_auto<P: AsRef<Path>>(path: P) -> Result<ProofArtifact> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => read_proof_artifact_json(path),
        Some("cbor") => read_proof_artifact_cbor(path),
        Some(other) => Err(anyhow!(
            "unsupported proof extension: {} (supported: .json, .cbor)",
            other
        )),
        None => Err(anyhow!("path has no extension (expected .json or .cbor)")),
    }
}

/// Auto-detect write for `ProofArtifact` (defaults to **JSON** if unknown).
pub fn write_proof_artifact_auto<P: AsRef<Path>>(path: P, v: &ProofArtifact) -> Result<()> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => write_proof_artifact_json(path, v),
        Some("cbor") => write_proof_artifact_cbor(path, v),
        _ => write_proof_artifact_json(path, v),
    }
}

/// ------------------------------
/// In-memory CBOR helpers
/// ------------------------------

/// Serialize any `T: Serialize` to **CBOR bytes** using `ciborium`.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).with_context(|| "serialize CBOR (to_cbor)")?;
    Ok(buf)
}

/// Deserialize any `T: DeserializeOwned` from **CBOR bytes** using `ciborium`.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut cur = Cursor::new(bytes);
    let v = ciborium::de::from_reader(&mut cur).with_context(|| "deserialize CBOR (from_cbor)")?;
    Ok(v)
}

/// ------------------------------
/// Back-compat aliases expected by CLI
/// ------------------------------

/// Alias to [`read_proof_artifact_auto`].
pub fn read_proof_auto<P: AsRef<Path>>(path: P) -> Result<ProofArtifact> {
    read_proof_artifact_auto(path)
}

/// Alias to [`write_proof_artifact_auto`].
pub fn write_proof_auto<P: AsRef<Path>>(path: P, v: &ProofArtifact) -> Result<()> {
    write_proof_artifact_auto(path, v)
}

/// ------------------------------
/// Tiny versioned wrapper
/// ------------------------------

/// Small versioned wrapper to tag payloads.
///
/// This is deliberately “dumb”: it just pairs a `u16` tag with a payload so
/// callers can enforce wire versions at the boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Versioned<T> {
    /// Wire version tag.
    pub ver: u16,
    /// Wrapped payload.
    pub payload: T,
}

impl<T> Versioned<T> {
    /// Construct a new versioned wrapper.
    #[inline]
    pub fn new(ver: u16, payload: T) -> Self {
        Self { ver, payload }
    }
}

/// Return the lowercase extension (without dot) if present.
fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
}

/// Human-friendly path display for error messages.
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{BackendKind, ProofArtifact};

    fn tmp_path(name: &str, ext: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("sezkp_core_io_{}_{}.{}", name, nanos, ext));
        p
    }

    #[test]
    fn block_summaries_json_roundtrip() {
        let path = tmp_path("blocks", "json");
        let blocks: Vec<BlockSummary> = vec![]; // empty is fine
        write_block_summaries_auto(&path, &blocks).unwrap();
        let got = read_block_summaries_auto(&path).unwrap();
        assert_eq!(got.len(), blocks.len());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proof_cbor_roundtrip() {
        let path = tmp_path("proof", "cbor");
        let pa = ProofArtifact {
            backend: BackendKind::Fold,
            manifest_root: [42u8; 32],
            proof_bytes: vec![1, 2, 3, 4],
            meta: serde_json::json!({"bench": true}),
        };
        write_proof_artifact_auto(&path, &pa).unwrap();
        let got = read_proof_artifact_auto(&path).unwrap();
        assert_eq!(got.backend, pa.backend);
        assert_eq!(got.manifest_root, pa.manifest_root);
        assert_eq!(got.proof_bytes, pa.proof_bytes);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn in_memory_cbor_helpers_roundtrip() {
        let wrapped = Versioned::new(2u16, vec![1u32, 2, 3, 5, 8]);
        let bytes = to_cbor(&wrapped).unwrap();
        let back: Versioned<Vec<u32>> = from_cbor(&bytes).unwrap();
        assert_eq!(wrapped.ver, back.ver);
        assert_eq!(wrapped.payload, back.payload);
    }
}
