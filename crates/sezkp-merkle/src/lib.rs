// crates/sezkp-merkle/src/lib.rs

//! Simple Merkle commitment over `BlockSummary` leaves.
//!
//! - Canonical leaf hash: BLAKE3 over a compact encoding of σ_k fields that
//!   must be bound by the commitment.
//! - Manifest contains: root, leaf count, and a schema version.
//! - Helpers to commit blocks from disk, verify that a blocks file matches a
//!   manifest, and read/write manifests (JSON/CBOR).

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

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_core::{io as core_io, BlockSummary};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use sezkp_core::io_jsonl::stream_block_summaries_jsonl;

/// Format version for `CommitManifest`.
pub const MANIFEST_VERSION: u32 = 1;

/// Compact commitment over `Vec<BlockSummary>`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitManifest {
    /// Schema/encoding version.
    pub version: u32,
    /// Merkle root over canonical leaf hashes.
    pub root: [u8; 32],
    /// Number of leaves (blocks).
    pub n_leaves: u32,
}

#[inline]
fn leaf_hash(b: &BlockSummary) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(&b.version.to_le_bytes());
    h.update(&b.block_id.to_le_bytes());
    h.update(&b.step_lo.to_le_bytes());
    h.update(&b.step_hi.to_le_bytes());
    h.update(&b.ctrl_in.to_le_bytes());
    h.update(&b.ctrl_out.to_le_bytes());
    h.update(&b.in_head_in.to_le_bytes());
    h.update(&b.in_head_out.to_le_bytes());

    // windows + head offsets (bind geometry)
    h.update(&(b.windows.len() as u64).to_le_bytes());
    for w in &b.windows {
        h.update(&w.left.to_le_bytes());
        h.update(&w.right.to_le_bytes());
    }
    for &x in &b.head_in_offsets {
        h.update(&x.to_le_bytes());
    }
    for &x in &b.head_out_offsets {
        h.update(&x.to_le_bytes());
    }

    // Movement log: bind only length in v0 (full σ_k schema carries the data).
    h.update(&(b.movement_log.steps.len() as u64).to_le_bytes());

    *h.finalize().as_bytes()
}

#[inline]
fn merkle_parent(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(&a);
    h.update(&b);
    *h.finalize().as_bytes()
}

fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for i in (0..leaves.len()).step_by(2) {
            if i + 1 < leaves.len() {
                next.push(merkle_parent(leaves[i], leaves[i + 1]));
            } else {
                // Promote odd leaf (left-balanced).
                next.push(leaves[i]);
            }
        }
        leaves = next;
    }
    leaves[0]
}

/// Compute a manifest (root + count) from in-memory blocks.
#[must_use]
pub fn commit_blocks(blocks: &[BlockSummary]) -> CommitManifest {
    let leaves: Vec<[u8; 32]> = blocks.iter().map(leaf_hash).collect();
    let root = merkle_root(leaves);
    CommitManifest {
        version: MANIFEST_VERSION,
        root,
        n_leaves: blocks.len() as u32,
    }
}

/// Read blocks (JSON/CBOR), compute manifest, write it to output path, and return it.
pub fn commit_block_file<P: AsRef<Path>, Q: AsRef<Path>>(
    blocks_path: P,
    out_manifest_path: Q,
) -> Result<CommitManifest> {
    let path = blocks_path.as_ref();
    let manifest = if ext_lower(path).as_deref() == Some("jsonl") {
        // Stream blocks → collect leaf hashes only
        let mut leaves = Vec::new();
        for blk in stream_block_summaries_jsonl(path)? {
            let b = blk?;
            leaves.push(leaf_hash(&b));
        }
        let root = merkle_root(leaves);
        let man = CommitManifest {
            version: MANIFEST_VERSION,
            root,
            n_leaves: 0, // will set below
        };
        // We don't know n a priori; recompute by re-streaming count or track in loop
        let mut n = 0u32;
        for _ in stream_block_summaries_jsonl(path)? {
            n += 1;
        }
        CommitManifest { n_leaves: n, ..man }
    } else {
        // existing path
        let blocks = core_io::read_block_summaries_auto(&blocks_path)
            .with_context(|| format!("read blocks {}", display(path)))?;
        commit_blocks(&blocks)
    };

    write_manifest_auto(&out_manifest_path, &manifest)?;
    println!(
        "Committed {} leaves, root={}, wrote manifest {}",
        manifest.n_leaves,
        hex::encode(manifest.root),
        out_manifest_path.as_ref().display()
    );
    Ok(manifest)
}


/// Verify that a blocks file matches a manifest file (by recomputing the root).
pub fn verify_block_file_against_manifest<P: AsRef<Path>, Q: AsRef<Path>>(
    blocks_path: P,
    manifest_path: Q,
) -> Result<()> {
    let path = blocks_path.as_ref();
    let man = read_manifest_auto(&manifest_path)?;
    if ext_lower(path).as_deref() == Some("jsonl") {
        // Recompute root + count by streaming
        let mut leaves = Vec::new();
        let mut n = 0u32;
        for blk in stream_block_summaries_jsonl(path)? {
            let b = blk?;
            leaves.push(leaf_hash(&b));
            n += 1;
        }
        let root = merkle_root(leaves);
        if root != man.root {
            anyhow::bail!(
                "root mismatch: manifest={}, recomputed={}",
                hex::encode(man.root),
                hex::encode(root)
            );
        }
        if n != man.n_leaves {
            anyhow::bail!(
                "leaf count mismatch: manifest={}, recomputed={}",
                man.n_leaves,
                n
            );
        }
        Ok(())
    } else {
        let blocks = core_io::read_block_summaries_auto(&blocks_path)
            .with_context(|| format!("read blocks {}", display(path)))?;
        validate_blocks_against_manifest(&blocks, &man)
    }
}


/// In-memory validator: recompute and compare root and leaf count.
pub fn validate_blocks_against_manifest(
    blocks: &[BlockSummary],
    man: &CommitManifest,
) -> Result<()> {
    let recomputed = commit_blocks(blocks);
    if recomputed.root != man.root {
        return Err(anyhow!(
            "root mismatch: manifest={}, recomputed={}",
            hex::encode(man.root),
            hex::encode(recomputed.root)
        ));
    }
    if recomputed.n_leaves != man.n_leaves {
        return Err(anyhow!(
            "leaf count mismatch: manifest={}, recomputed={}",
            man.n_leaves,
            recomputed.n_leaves
        ));
    }
    Ok(())
}

/* -------------------- Manifest IO (JSON/CBOR) -------------------- */

/// Read manifest from **JSON**.
pub fn read_manifest_json<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let rdr = BufReader::new(f);
    let v: CommitManifest =
        serde_json::from_reader(rdr).with_context(|| "deserialize JSON manifest")?;
    Ok(v)
}

/// Write manifest to **JSON** (pretty).
pub fn write_manifest_json<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, v).with_context(|| "serialize JSON manifest")?;
    w.flush().with_context(|| "flush JSON writer")?;
    Ok(())
}

/// Read manifest from **CBOR**.
pub fn read_manifest_cbor<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    let path_ref = path.as_ref();
    let f = File::open(path_ref).with_context(|| format!("open {}", display(path_ref)))?;
    let mut rdr = BufReader::new(f);
    let v: CommitManifest =
        ciborium::de::from_reader(&mut rdr).with_context(|| "deserialize CBOR manifest")?;
    Ok(v)
}

/// Write manifest to **CBOR**.
pub fn write_manifest_cbor<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    let path_ref = path.as_ref();
    let f = File::create(path_ref).with_context(|| format!("create {}", display(path_ref)))?;
    let mut w = BufWriter::new(f);
    ciborium::ser::into_writer(v, &mut w).with_context(|| "serialize CBOR manifest")?;
    w.flush().with_context(|| "flush CBOR writer")?;
    Ok(())
}

/// Auto-detect read by extension `.json` / `.cbor` (case-insensitive).
pub fn read_manifest_auto<P: AsRef<Path>>(path: P) -> Result<CommitManifest> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => read_manifest_json(path),
        Some("cbor") => read_manifest_cbor(path),
        Some(other) => anyhow::bail!("unsupported manifest extension: {}", other),
        None => anyhow::bail!("path has no extension (expected .json or .cbor)"),
    }
}

/// Auto-detect write (defaults to JSON if unknown).
pub fn write_manifest_auto<P: AsRef<Path>>(path: P, v: &CommitManifest) -> Result<()> {
    match ext_lower(path.as_ref()).as_deref() {
        Some("json") => write_manifest_json(path, v),
        Some("cbor") => write_manifest_cbor(path, v),
        _ => write_manifest_json(path, v),
    }
}

/* -------------------- Small helpers -------------------- */

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

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, TapeOp, Window};

    fn mk_block(block_id: u32, len: usize) -> BlockSummary {
        let steps = vec![
            StepProjection {
                input_mv: 0,
                tapes: vec![TapeOp { write: None, mv: 0 }],
            };
            len
        ];
        BlockSummary {
            version: 1,
            block_id,
            step_lo: 1 + (block_id as u64 - 1) * len as u64,
            step_hi: (block_id as u64) * len as u64,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: len as i64,
            windows: vec![Window { left: 0, right: len as i64 - 1 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![(len - 1) as u32],
            movement_log: MovementLog { steps },
            pre_tags: vec![[0u8; 16]; 1],
            post_tags: vec![[0u8; 16]; 1],
        }
    }

    #[test]
    fn merkle_root_empty_and_odd() {
        assert_eq!(merkle_root(vec![]), [0u8; 32]);

        // Three leaves → odd promotion path defined behavior.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let r1 = merkle_parent(a, b);
        let r2 = merkle_parent(r1, c); // (a,b) then promote c
        let root = merkle_root(vec![a, b, c]);
        assert_eq!(root, r2);
    }

    #[test]
    fn commit_and_validate_roundtrip() {
        let blocks = vec![mk_block(1, 4), mk_block(2, 4), mk_block(3, 2)];
        let man = commit_blocks(&blocks);
        validate_blocks_against_manifest(&blocks, &man).unwrap();
    }
}
