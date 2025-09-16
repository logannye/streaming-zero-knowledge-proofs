//! On-demand column openings and streamed column roots.
//!
//! A2: no full columns in RAM. We commit to columns by streaming rows and
//! answering openings by recomputing only the required chunk plus the outer
//! Merkle path over chunk-roots.
//!
//! Memory profile
//! - Building roots: O(chunk) per label (pending leaves) and O(1) otherwise.
//! - Opening one (label, row): O(chunk) to rebuild that chunk; we cache all
//!   chunk-roots per label for reuse across multiple opens.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::collections::HashMap;

use sezkp_core::BlockSummary;

use crate::v1::{
    field::F1,
    merkle::{hash_field_leaves_labeled, MerkleTree},
    proof::{ColumnRoot, Opening},
};

/// Number of rows across all blocks.
fn total_rows(blocks: &[BlockSummary]) -> usize {
    blocks
        .iter()
        .map(|b| (b.step_hi - b.step_lo + 1) as usize)
        .sum()
}

/* --------------------------- Column label plumbing ------------------------- */

/// Column label grammar and dispatch.
#[derive(Clone, Debug)]
enum TapeColKind {
    Mv,
    WFlag,
    WSym,
    Head,
    WinLen,
    InOff,
    OutOff,
}

#[derive(Clone, Debug)]
enum LabelKind {
    InputMv,
    IsFirst,
    IsLast,
    Tape { kind: TapeColKind, r: usize },
}

fn parse_label(label: &str, tau: usize) -> LabelKind {
    match label {
        "input_mv" => LabelKind::InputMv,
        "is_first" => LabelKind::IsFirst,
        "is_last" => LabelKind::IsLast,
        _ => {
            let (name, idx_str) = label
                .rsplit_once('_')
                .expect("column label must end with _{r}");
            let r: usize = idx_str.parse().expect("column index must be usize");
            assert!(r < tau, "column index out of range: {r} >= tau={tau}");
            let kind = match name {
                "mv" => TapeColKind::Mv,
                "wflag" => TapeColKind::WFlag,
                "wsym" => TapeColKind::WSym,
                "head" => TapeColKind::Head,
                "winlen" => TapeColKind::WinLen,
                "in_off" => TapeColKind::InOff,
                "out_off" => TapeColKind::OutOff,
                _ => panic!("unknown column prefix: {name}"),
            };
            LabelKind::Tape { kind, r }
        }
    }
}

/// Public label order (must match the verifier / transcript binding).
fn all_labels(tau: usize) -> Vec<String> {
    let mut out = Vec::<String>::new();
    out.push("input_mv".into());
    out.push("is_first".into());
    out.push("is_last".into());
    for r in 0..tau {
        out.push(format!("mv_{r}"));
    }
    for r in 0..tau {
        out.push(format!("wflag_{r}"));
    }
    for r in 0..tau {
        out.push(format!("wsym_{r}"));
    }
    for r in 0..tau {
        out.push(format!("head_{r}"));
    }
    for r in 0..tau {
        out.push(format!("winlen_{r}"));
    }
    for r in 0..tau {
        out.push(format!("in_off_{r}"));
    }
    for r in 0..tau {
        out.push(format!("out_off_{r}"));
    }
    out
}

/* ----------------------------- Small helpers ------------------------------- */

#[inline]
fn f_le_u64(x: u64) -> [u8; 8] {
    F1::from_u64(x).to_le_bytes()
}
#[inline]
fn f_le_i64(x: i64) -> [u8; 8] {
    F1::from_i64(x).to_le_bytes()
}

/* -------------------------- Reconstruct row values -------------------------- */

/// One row of committed columns (values already encoded as 8-byte LE).
#[derive(Clone, Debug)]
struct RowSnapshot {
    input_mv: [u8; 8],
    is_first: [u8; 8],
    is_last: [u8; 8],
    mv: Vec<[u8; 8]>,
    wflag: Vec<[u8; 8]>,
    wsym: Vec<[u8; 8]>,
    head: Vec<[u8; 8]>,
    winlen: Vec<[u8; 8]>,
    in_off: Vec<[u8; 8]>,
    out_off: Vec<[u8; 8]>,
}

impl RowSnapshot {
    fn with_tau(tau: usize) -> Self {
        Self {
            input_mv: [0; 8],
            is_first: [0; 8],
            is_last: [0; 8],
            mv: vec![[0; 8]; tau],
            wflag: vec![[0; 8]; tau],
            wsym: vec![[0; 8]; tau],
            head: vec![[0; 8]; tau],
            winlen: vec![[0; 8]; tau],
            in_off: vec![[0; 8]; tau],
            out_off: vec![[0; 8]; tau],
        }
    }

    fn get_for_label(&self, label: &LabelKind) -> [u8; 8] {
        match label {
            LabelKind::InputMv => self.input_mv,
            LabelKind::IsFirst => self.is_first,
            LabelKind::IsLast => self.is_last,
            LabelKind::Tape { kind, r } => match kind {
                TapeColKind::Mv => self.mv[*r],
                TapeColKind::WFlag => self.wflag[*r],
                TapeColKind::WSym => self.wsym[*r],
                TapeColKind::Head => self.head[*r],
                TapeColKind::WinLen => self.winlen[*r],
                TapeColKind::InOff => self.in_off[*r],
                TapeColKind::OutOff => self.out_off[*r],
            },
        }
    }
}

/// Row-wise iterator that reconstructs the committed columns exactly.
/// (Semantics match `columns_stream.rs` and `columns.rs`.)
struct RowIter<'a> {
    blocks: &'a [BlockSummary],
    tau: usize,
    blk_idx: usize,
    row_in_blk: usize,
    blk_len: usize,
    // per-block caches
    wlen: Vec<u64>,
    cur_heads: Vec<i64>,
}

impl<'a> RowIter<'a> {
    fn new(blocks: &'a [BlockSummary]) -> Self {
        let tau = blocks.first().map(|b| b.windows.len()).unwrap_or(0);
        let mut it = Self {
            blocks,
            tau,
            blk_idx: 0,
            row_in_blk: 0,
            blk_len: 0,
            wlen: vec![0; tau],
            cur_heads: vec![0; tau],
        };
        it.enter_block();
        it
    }

    fn enter_block(&mut self) {
        if let Some(b) = self.blocks.get(self.blk_idx) {
            self.blk_len = (b.step_hi - b.step_lo + 1) as usize;

            // window lengths are constant within a block
            for r in 0..self.tau {
                let left = b.windows[r].left;
                let right = b.windows[r].right;
                let wl = (right - left).abs() as u64 + 1;
                self.wlen[r] = wl;
                self.cur_heads[r] = 0;
            }
        } else {
            self.blk_len = 0;
        }
    }
}

impl<'a> Iterator for RowIter<'a> {
    type Item = RowSnapshot;

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.blocks.get(self.blk_idx)?;
        if self.row_in_blk >= self.blk_len {
            // next block
            self.blk_idx += 1;
            self.row_in_blk = 0;
            self.enter_block();
            return self.next();
        }

        let mut row = RowSnapshot::with_tau(self.tau);

        // flags
        row.is_first = f_le_u64((self.row_in_blk == 0) as u64);
        row.is_last = f_le_u64((self.row_in_blk + 1 == self.blk_len) as u64);

        // step
        let step = &b.movement_log.steps[self.row_in_blk];
        row.input_mv = f_le_i64(step.input_mv as i64);

        for r in 0..self.tau {
            let op = &step.tapes[r];

            // movement and write
            row.mv[r] = f_le_i64(op.mv as i64);
            let flg = u64::from(op.write.is_some());
            let sym = op.write.unwrap_or(0) as u64;
            row.wflag[r] = f_le_u64(flg);
            row.wsym[r] = f_le_u64(sym);

            // move-then-write: head is post-move, relative to the left bound
            self.cur_heads[r] += op.mv as i64;
            row.head[r] = f_le_i64(self.cur_heads[r]);

            // block constants
            row.winlen[r] = f_le_u64(self.wlen[r]);
            row.in_off[r] = f_le_u64(b.head_in_offsets[r] as u64);
            row.out_off[r] = f_le_u64(b.head_out_offsets[r] as u64);
        }

        self.row_in_blk += 1;
        Some(row)
    }
}

/* --------------------------- On-demand openings ---------------------------- */

/// On-demand openings over streamed column commitments.
pub struct OnDemandOpenings<'a> {
    blocks: &'a [BlockSummary],
    tau: usize,
    n_rows: usize,
    chunk_log2: usize,
    chunk_size: usize,
    // Cache per column label: (chunk_roots, outer_tree)
    outer_cache: HashMap<String, (Vec<[u8; 32]>, MerkleTree)>,
}

impl<'a> OnDemandOpenings<'a> {
    /// Create for a given `chunk_log2` (shared across columns).
    #[must_use]
    pub fn new(blocks: &'a [BlockSummary], chunk_log2: usize) -> Self {
        let tau = blocks.first().map(|b| b.windows.len()).unwrap_or(0);
        let n_rows = total_rows(blocks);
        Self {
            blocks,
            tau,
            n_rows,
            chunk_log2,
            chunk_size: 1usize << chunk_log2,
            outer_cache: HashMap::new(),
        }
    }

    /// Build public column roots in canonical order using O(chunk) memory.
    #[must_use]
    pub fn build_roots(&self) -> Vec<ColumnRoot> {
        let labels = all_labels(self.tau);

        // One pending chunk per label.
        let mut pending: Vec<Vec<[u8; 32]>> = labels
            .iter()
            .map(|_| Vec::with_capacity(self.chunk_size))
            .collect();
        let mut chunk_roots_per_label: Vec<Vec<[u8; 32]>> =
            labels.iter().map(|_| Vec::new()).collect();

        for row in RowIter::new(self.blocks) {
            // Scalars
            pending[0].push(hash_field_leaves_labeled(&[row.input_mv], "input_mv")[0]);
            pending[1].push(hash_field_leaves_labeled(&[row.is_first], "is_first")[0]);
            pending[2].push(hash_field_leaves_labeled(&[row.is_last], "is_last")[0]);

            let mut idx = 3usize;

            // mv_r
            for r in 0..self.tau {
                pending[idx + r].push(hash_field_leaves_labeled(&[row.mv[r]], &format!("mv_{r}"))[0]);
            }
            idx += self.tau;

            // wflag_r
            for r in 0..self.tau {
                pending[idx + r].push(
                    hash_field_leaves_labeled(&[row.wflag[r]], &format!("wflag_{r}"))[0],
                );
            }
            idx += self.tau;

            // wsym_r
            for r in 0..self.tau {
                pending[idx + r]
                    .push(hash_field_leaves_labeled(&[row.wsym[r]], &format!("wsym_{r}"))[0]);
            }
            idx += self.tau;

            // head_r
            for r in 0..self.tau {
                pending[idx + r]
                    .push(hash_field_leaves_labeled(&[row.head[r]], &format!("head_{r}"))[0]);
            }
            idx += self.tau;

            // winlen_r
            for r in 0..self.tau {
                pending[idx + r].push(
                    hash_field_leaves_labeled(&[row.winlen[r]], &format!("winlen_{r}"))[0],
                );
            }
            idx += self.tau;

            // in_off_r
            for r in 0..self.tau {
                pending[idx + r]
                    .push(hash_field_leaves_labeled(&[row.in_off[r]], &format!("in_off_{r}"))[0]);
            }
            idx += self.tau;

            // out_off_r
            for r in 0..self.tau {
                pending[idx + r]
                    .push(hash_field_leaves_labeled(&[row.out_off[r]], &format!("out_off_{r}"))[0]);
            }

            // Close full chunks.
            for (lix, buf) in pending.iter_mut().enumerate() {
                if buf.len() == self.chunk_size {
                    let mt = MerkleTree::from_leaves(buf);
                    chunk_roots_per_label[lix].push(mt.root());
                    buf.clear();
                }
            }
        }

        // Flush partials and build outer roots.
        let mut out = Vec::<ColumnRoot>::with_capacity(labels.len());
        for (lix, label) in labels.into_iter().enumerate() {
            if !pending[lix].is_empty() {
                let mt = MerkleTree::from_leaves(&pending[lix]);
                chunk_roots_per_label[lix].push(mt.root());
            }
            let outer = MerkleTree::from_leaves(&chunk_roots_per_label[lix]);
            out.push(ColumnRoot {
                label,
                root: outer.root(),
            });
        }
        out
    }

    /// Open (`label`, `row_idx`) by recomputing the target chunk and using a
    /// cached outer tree (per label).
    #[must_use]
    pub fn open(&mut self, label: &str, row_idx: usize) -> Opening {
        assert!(row_idx < self.n_rows, "row index out of range");
        let kind = parse_label(label, self.tau);

        let chunk_idx = row_idx / self.chunk_size;
        let idx_in_chunk = row_idx - chunk_idx * self.chunk_size;

        // Inner chunk data (recomputed).
        let (value_le, chunk_root, path_in_chunk) =
            self.open_within_chunk(&kind, label, chunk_idx, idx_in_chunk);

        // Ensure we have cached outer tree for this label (avoid E0502).
        if !self.outer_cache.contains_key(label) {
            let (roots, tree) = self.compute_all_chunk_roots_for_label(&kind, label);
            self.outer_cache.insert(label.to_string(), (roots, tree));
        }
        let (_roots, outer_tree) = self.outer_cache.get(label).expect("cached");

        let path_to_chunk = outer_tree.open(chunk_idx).sibs.clone();

        Opening {
            value_le,
            index: row_idx,
            chunk_index: chunk_idx,
            index_in_chunk: idx_in_chunk,
            chunk_root,
            path_in_chunk,
            path_to_chunk,
        }
    }

    /// Recompute **all** chunk-roots for a column (cached per label), and the
    /// outer Merkle tree.
    fn compute_all_chunk_roots_for_label(
        &self,
        kind: &LabelKind,
        label: &str,
    ) -> (Vec<[u8; 32]>, MerkleTree) {
        let mut chunk_roots = Vec::<[u8; 32]>::new();
        let mut cur = Vec::<[u8; 32]>::with_capacity(self.chunk_size);

        for row in RowIter::new(self.blocks) {
            let v = row.get_for_label(kind);
            cur.push(hash_field_leaves_labeled(&[v], label)[0]);
            if cur.len() == self.chunk_size {
                let mt = MerkleTree::from_leaves(&cur);
                chunk_roots.push(mt.root());
                cur.clear();
            }
        }
        if !cur.is_empty() {
            let mt = MerkleTree::from_leaves(&cur);
            chunk_roots.push(mt.root());
        }

        let outer = MerkleTree::from_leaves(&chunk_roots);
        (chunk_roots, outer)
    }

    /// Build the **inner** chunk tree for (`label`, `chunk_idx`) and return
    /// the opening data for `idx_in_chunk` (including the raw value bytes).
    fn open_within_chunk(
        &self,
        kind: &LabelKind,
        label: &str,
        chunk_idx: usize,
        idx_in_chunk: usize,
    ) -> ([u8; 8], [u8; 32], Vec<[u8; 32]>) {
        let start = chunk_idx * self.chunk_size;
        let end = (start + self.chunk_size).min(self.n_rows);

        let mut cur_leaves = Vec::<[u8; 32]>::with_capacity(end - start);
        let mut value_le = [0u8; 8];

        // Advance an iterator to `start`.
        let mut it = RowIter::new(self.blocks);
        for _ in 0..start {
            let _ = it.next();
        }

        for i in start..end {
            let row = it.next().expect("row exists");
            let v = row.get_for_label(kind);
            if i == start + idx_in_chunk {
                value_le = v;
            }
            cur_leaves.push(hash_field_leaves_labeled(&[v], label)[0]);
        }

        let chunk_tree = MerkleTree::from_leaves(&cur_leaves);
        let chunk_root = chunk_tree.root();
        let path_in_chunk = chunk_tree.open(idx_in_chunk).sibs;

        (value_le, chunk_root, path_in_chunk)
    }
}
