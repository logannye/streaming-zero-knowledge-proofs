//! JSON Lines (NDJSON) helpers for streaming `BlockSummary` I/O.
//!
//! These functions provide memory-efficient line-by-line reading/writing
//! suitable for very large inputs. Each line is a single JSON object.
//!
//! - **Reader**: returns `Iterator<Item = Result<BlockSummary>>` so callers can
//!   surface per-line errors without losing the stream.
//! - **Writer**: uses `serde_json::to_writer` to avoid intermediate allocations.
//!
//! # Formats
//! We treat both `.jsonl` and `.ndjson` as equivalent line-delimited JSON.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::BlockSummary;

/// Stream read: one JSON object per line → yields `BlockSummary` items.
///
/// This is resilient to large inputs: we only materialize one block at a time.
/// Each line is parsed independently; the iterator yields `Err` with a line
/// number if parsing fails.
///
/// # Errors
/// Opening the file may fail. Individual iteration items may be `Err` if a
/// particular line is malformed.
pub fn stream_block_summaries_jsonl<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = Result<BlockSummary>>> {
    let f = File::open(path.as_ref())
        .with_context(|| format!("open {}", path.as_ref().display()))?;
    let rdr = BufReader::new(f);

    // We return an iterator of Result<BlockSummary> to surface per-line errors.
    Ok(rdr
        .lines()
        .enumerate()
        .map(|(i, line)| -> Result<BlockSummary> {
            let s = line.with_context(|| format!("read line {}", i + 1))?;
            let b: BlockSummary = serde_json::from_str(&s)
                .with_context(|| format!("parse jsonl line {}", i + 1))?;
            Ok(b)
        }))
}

/// Write blocks as JSON Lines (one object per line).
///
/// Uses `serde_json::to_writer` directly to avoid temporary `String`s.
pub fn write_block_summaries_jsonl<P: AsRef<Path>>(
    path: P,
    blocks: &[BlockSummary],
) -> Result<()> {
    let f = File::create(path.as_ref())
        .with_context(|| format!("create {}", path.as_ref().display()))?;
    let mut w = BufWriter::new(f);
    for b in blocks {
        serde_json::to_writer(&mut w, b).context("serialize block to json")?;
        w.write_all(b"\n").context("write newline")?;
    }
    w.flush().context("flush writer")?;
    Ok(())
}

/// Generic JSONL writer (handy if you want to dump other streams later).
pub fn write_jsonl<P: AsRef<Path>, T: Serialize>(path: P, items: &[T]) -> Result<()> {
    let f = File::create(path.as_ref())
        .with_context(|| format!("create {}", path.as_ref().display()))?;
    let mut w = BufWriter::new(f);
    for it in items {
        serde_json::to_writer(&mut w, it).context("serialize jsonl item")?;
        w.write_all(b"\n").context("write newline")?;
    }
    w.flush().context("flush writer")?;
    Ok(())
}
