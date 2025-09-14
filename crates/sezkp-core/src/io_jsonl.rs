#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::BlockSummary;

/// Stream read: one JSON object per line → yields `BlockSummary` items.
///
/// This is resilient to large inputs: we only materialize one block at a time.
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
pub fn write_block_summaries_jsonl<P: AsRef<Path>>(
    path: P,
    blocks: &[BlockSummary],
) -> Result<()> {
    let f = File::create(path.as_ref())
        .with_context(|| format!("create {}", path.as_ref().display()))?;
    let mut w = BufWriter::new(f);
    for b in blocks {
        let line = serde_json::to_string(b).context("serialize block to json")?;
        w.write_all(line.as_bytes()).context("write jsonl line")?;
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
        let line = serde_json::to_string(it).context("serialize jsonl item")?;
        w.write_all(line.as_bytes()).context("write jsonl line")?;
        w.write_all(b"\n").context("write newline")?;
    }
    w.flush().context("flush writer")?;
    Ok(())
}
