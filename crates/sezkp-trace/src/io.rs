//! I/O helpers for the `TraceFile` envelope (format-level).
//!
//! Supports JSON/CBOR and extension-based auto-detection. These routines do not
//! impose VM semantics; they only move the `TraceFile` struct across the wire.

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

use crate::format::TraceFile;
use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

/* ---------------- JSON ---------------- */

/// Read a `TraceFile` from **JSON**.
///
/// Errors include file open, decoding, or malformed structure.
pub fn read_trace_json<P: AsRef<Path>>(path: P) -> Result<TraceFile> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let rdr = BufReader::new(f);
    let v: TraceFile =
        serde_json::from_reader(rdr).with_context(|| "deserialize JSON trace file")?;
    Ok(v)
}

/// Write a `TraceFile` to **JSON** (pretty).
pub fn write_trace_json<P: AsRef<Path>>(path: P, v: &TraceFile) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, v).with_context(|| "serialize JSON trace file")?;
    w.flush().with_context(|| "flush JSON writer")?;
    Ok(())
}

/* ---------------- CBOR ---------------- */

/// Read a `TraceFile` from **CBOR**.
///
/// Uses `ciborium` for streaming-friendly decoding.
pub fn read_trace_cbor<P: AsRef<Path>>(path: P) -> Result<TraceFile> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let mut rdr = BufReader::new(f);
    let v: TraceFile =
        ciborium::de::from_reader(&mut rdr).with_context(|| "deserialize CBOR trace file")?;
    Ok(v)
}

/// Write a `TraceFile` to **CBOR**.
pub fn write_trace_cbor<P: AsRef<Path>>(path: P, v: &TraceFile) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    ciborium::ser::into_writer(v, &mut w).with_context(|| "serialize CBOR trace file")?;
    w.flush().with_context(|| "flush CBOR writer")?;
    Ok(())
}

/* --------------- Auto-detect by extension --------------- */

/// Auto-detect **read** by extension (`.json` / `.cbor`, case-insensitive).
///
/// Returns a helpful error if the extension is missing or unsupported.
pub fn read_trace_auto<P: AsRef<Path>>(path: P) -> Result<TraceFile> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => read_trace_json(path),
        Some("cbor") => read_trace_cbor(path),
        Some(other) => Err(anyhow!(
            "unsupported trace extension: {} (supported: .json, .cbor)",
            other
        )),
        None => Err(anyhow!("path has no extension (expected .json or .cbor)")),
    }
}

/// Auto-detect **write** (defaults to JSON if unknown/missing).
pub fn write_trace_auto<P: AsRef<Path>>(path: P, v: &TraceFile) -> Result<()> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => write_trace_json(path, v),
        Some("cbor") => write_trace_cbor(path, v),
        _ => write_trace_json(path, v),
    }
}

/* ---------------- Small helpers ---------------- */

#[inline]
fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
}

#[inline]
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
