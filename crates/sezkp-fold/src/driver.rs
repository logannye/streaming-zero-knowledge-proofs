//! Glue driver: run the height-compressed scheduler with Leaf / Fold / Wrap
//! callbacks, building a folding proof artifact.
//!
//! # Modes
//!
//! - **Balanced**: pointerless DFS with an `O(T)` endpoint ledger.
//! - **MinRam**: recompute endpoints on demand; keep a tiny LRU cache
//!   bounded by [`DriverOptions::endpoint_cache`] (default 64).
//! - **Streaming**: push-based builder that keeps only `O(log T)` live
//!   subtrees while consuming blocks left→right. Produces the *same* balanced
//!   tree shape by greedily merging sibling spans where the midpoint equals
//!   the boundary between adjacent subtrees.
//!
//! # Streaming format
//!
//! The streaming variants in this module can *emit* or *consume* a compact
//! CBOR sequence (see [`StreamHeader`]/[`StreamItem`]/[`StreamFooter`])
//! that represents the same information as the in-memory bundle. Each CBOR
//! value is self-delimiting, so writing them back-to-back yields a valid
//! byte stream that can be incrementally decoded.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_mut)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_assignments)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::Result;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_core::BlockSummary;
use sezkp_scheduler as hct;
use sezkp_stark::v1::columns::interface_boundary_digest;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::Write;

use crate::api::{commit_pi, Commitment, DriverOptions, Fold, Leaf, PiCommitment, Wrap};
use crate::are::{InterfaceWitness, Pi};

/// Serializable folding artifact (compact and human-inspectable).
///
/// See the module docs for ordering guarantees on `leaves`, `folds`, and `wraps`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldProofBundle<Lp, Fp, Wp> {
    /// Number of input blocks.
    pub n_blocks: usize,
    /// Root interval spanned by the balanced tree. Half-open `[lo, hi)`.
    pub tree_span: (u32, u32),
    /// Per-leaf records: `(C, π, leaf_proof)` (left→right).
    pub leaves: Vec<(Commitment, Pi, Lp)>,
    /// Per-fold records (bottom-up): `(parent(C,π), left(C,π), right(C,π), fold_proof)`.
    pub folds: Vec<((Commitment, Pi), (Commitment, Pi), (Commitment, Pi), Fp)>,
    /// Optional wrap attestations of intermediate or final roots.
    pub wraps: Vec<((Commitment, Pi), Wp)>,
}

impl<Lp, Fp, Wp> FoldProofBundle<Lp, Fp, Wp> {
    /// Create an empty bundle placeholder that will be filled by the driver.
    ///
    /// - `n`   — number of leaves
    /// - `lo`  — root span start (usually `0`)
    /// - `hi`  — root span end   (usually `n`)
    #[inline]
    #[must_use]
    pub fn empty(n: usize, lo: u32, hi: u32) -> Self {
        Self {
            n_blocks: n,
            tree_span: (lo, hi),
            leaves: Vec::new(),
            folds: Vec::new(),
            wraps: Vec::new(),
        }
    }

    /// Convenience: number of leaves recorded.
    #[inline]
    #[allow(dead_code)]
    pub fn n_leaves(&self) -> usize {
        self.leaves.len()
    }
}

/// Derive a tiny commitment for a subtree from `(C, π)`.
///
/// **Not** the cryptographic root—just a compact digest, helpful for debugging.
#[allow(dead_code)]
pub(crate) fn digest_pair(c: &Commitment, pi: &Pi) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(&c.root);
    h.update(&c.len.to_le_bytes());
    h.update(&pi.ctrl_in.to_le_bytes());
    h.update(&pi.ctrl_out.to_le_bytes());
    h.update(&pi.flags.to_le_bytes());
    for a in &pi.acc {
        h.update(&a.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/* ---------------------------- tiny LRU for endpoints ----------------------- */

/// Key for the endpoint cache corresponding to a half-open interval `[lo, hi)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SpanKey(u32, u32);

/// Extremely small LRU used by the *MinRam* driver to avoid retaining an
/// `O(T)` ledger. When capacity is zero, the cache is effectively disabled.
///
/// The cache stores *endpoints* `(Commitment, Pi)` for previously-computed
/// subtrees keyed by their span.
#[derive(Default)]
struct EndpointCache {
    cap: usize,
    map: HashMap<SpanKey, (Commitment, Pi)>,
    /// Ordering deque: front = LRU, back = MRU.
    order: VecDeque<SpanKey>,
}

impl EndpointCache {
    #[inline]
    fn new(cap: usize) -> Self {
        Self {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    #[inline]
    fn touch_back(&mut self, k: SpanKey) {
        if let Some(pos) = self.order.iter().position(|x| *x == k) {
            self.order.remove(pos);
        }
        self.order.push_back(k);
    }
    #[inline]
    fn get(&mut self, k: SpanKey) -> Option<(Commitment, Pi)> {
        if let Some(v) = self.map.get(&k).cloned() {
            self.touch_back(k);
            Some(v)
        } else {
            None
        }
    }
    #[inline]
    fn put(&mut self, k: SpanKey, v: (Commitment, Pi)) {
        if self.cap == 0 {
            return; // effectively disabled
        }
        if !self.map.contains_key(&k) && self.map.len() == self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
        self.map.insert(k, v);
        self.touch_back(k);
    }
}

/* ------------------------------ batch driver ------------------------------- */

/// Run the folding pipeline with generic `Leaf` / `Fold` / `Wrap` gadgets.
///
/// Returns an in-memory [`FoldProofBundle`] containing all emitted leaves,
/// folds, and optional wraps in a stable order.
pub fn run_pipeline<L, F, W>(
    blocks: &[BlockSummary],
    opts: &DriverOptions,
) -> FoldProofBundle<L::Proof, F::Proof, W::Proof>
where
    L: Leaf,
    F: Fold,
    W: Wrap,
{
    let t = blocks.len();
    if t == 0 {
        // Trivial bundle for empty input; avoids scheduler edge-cases.
        return FoldProofBundle::empty(0, 0, 0);
    }

    let root = hct::balanced_tree(t);

    // Shared output buffers.
    let leaves: RefCell<Vec<(Commitment, Pi, L::Proof)>> = RefCell::new(Vec::new());
    let folds: RefCell<Vec<((Commitment, Pi), (Commitment, Pi), (Commitment, Pi), F::Proof)>> =
        RefCell::new(Vec::new());
    let wraps: RefCell<Vec<((Commitment, Pi), W::Proof)>> = RefCell::new(Vec::new());

    match opts.fold_mode {
        crate::api::FoldMode::Balanced => {
            // Keep a tiny ledger of endpoints at leaf .lo positions.
            let ledger: RefCell<Vec<Option<(Commitment, Pi)>>> = RefCell::new(vec![None; t]);

            hct::dfs(
                t,
                |leaf_span| {
                    let i = leaf_span.lo as usize;
                    let (pi, c, pr) = L::prove_leaf(&blocks[i]);
                    ledger.borrow_mut()[i] = Some((c, pi));
                    leaves.borrow_mut().push((c, pi, pr));
                },
                |merge_span| {
                    let (l, r) = merge_span.split_mid();

                    // Recover endpoints for left+right subtrees from ledger at child.lo.
                    let (ci, pi_i) = {
                        let ldg = ledger.borrow();
                        ldg[l.lo as usize]
                            .as_ref()
                            .expect("left endpoint present in ledger")
                            .clone()
                    };
                    let (cj, pj) = {
                        let ldg = ledger.borrow();
                        ldg[r.lo as usize]
                            .as_ref()
                            .expect("right endpoint present in ledger")
                            .clone()
                    };

                    // Canonical boundary digest between the last left leaf and the first right leaf.
                    let left_blk = &blocks[(l.hi - 1) as usize];
                    let right_blk = &blocks[r.lo as usize];
                    let digest = interface_boundary_digest(left_blk, right_blk);
                    let iface = InterfaceWitness {
                        left_ctrl_out: pi_i.ctrl_out,
                        right_ctrl_in: pj.ctrl_in,
                        boundary_writes_digest: digest,
                    };

                    let (c_par, pi_par, pf) = F::fold((&ci, &pi_i), (&cj, &pj), &iface);

                    folds
                        .borrow_mut()
                        .push(((c_par, pi_par), (ci, pi_i), (cj, pj), pf));

                    if opts.wrap_cadence != 0 {
                        let k = opts.wrap_cadence as usize;
                        if folds.borrow().len() % k == 0 {
                            let w = W::wrap((&c_par, &pi_par));
                            wraps.borrow_mut().push(((c_par, pi_par), w));
                        }
                    }

                    // Collapse into left endpoint; clear right.
                    {
                        let mut ldg = ledger.borrow_mut();
                        ldg[l.lo as usize] = Some((c_par, pi_par));
                        ldg[r.lo as usize] = None;
                    }
                },
            );
        }
        crate::api::FoldMode::MinRam => {
            // Recursively build endpoints; keep only a tiny LRU.
            let mut cache = EndpointCache::new(opts.endpoint_cache as usize);

            fn build_endpoint<L, F, W>(
                blocks: &[BlockSummary],
                span: hct::Interval,
                cache: &mut EndpointCache,
                leaves: &RefCell<Vec<(Commitment, Pi, L::Proof)>>,
                folds: &RefCell<
                    Vec<((Commitment, Pi), (Commitment, Pi), (Commitment, Pi), F::Proof)>,
                >,
                wraps: &RefCell<Vec<((Commitment, Pi), W::Proof)>>,
                wrap_cadence: u32,
            ) -> (Commitment, Pi)
            where
                L: Leaf,
                F: Fold,
                W: Wrap,
            {
                let key = SpanKey(span.lo, span.hi);
                if let Some(ep) = cache.get(key) {
                    return ep;
                }

                if span.is_leaf() {
                    let i = span.lo as usize;
                    let (pi, c, pr) = L::prove_leaf(&blocks[i]);
                    leaves.borrow_mut().push((c, pi, pr));
                    cache.put(key, (c, pi));
                    return (c, pi);
                }

                let (l, r) = span.split_mid();
                let (ci, pi_i) = build_endpoint::<L, F, W>(
                    blocks, l, cache, leaves, folds, wraps, wrap_cadence,
                );
                let (cj, pj) = build_endpoint::<L, F, W>(
                    blocks, r, cache, leaves, folds, wraps, wrap_cadence,
                );

                // Boundary between last left leaf and first right leaf.
                let left_blk = &blocks[(l.hi - 1) as usize];
                let right_blk = &blocks[r.lo as usize];
                let digest = interface_boundary_digest(left_blk, right_blk);
                let iface = InterfaceWitness {
                    left_ctrl_out: pi_i.ctrl_out,
                    right_ctrl_in: pj.ctrl_in,
                    boundary_writes_digest: digest,
                };

                let (c_par, pi_par, pf) = F::fold((&ci, &pi_i), (&cj, &pj), &iface);
                folds
                    .borrow_mut()
                    .push(((c_par, pi_par), (ci, pi_i), (cj, pj), pf));

                if wrap_cadence != 0 {
                    let k = wrap_cadence as usize;
                    if folds.borrow().len() % k == 0 {
                        let w = W::wrap((&c_par, &pi_par));
                        wraps.borrow_mut().push(((c_par, pi_par), w));
                    }
                }

                cache.put(key, (c_par, pi_par));
                (c_par, pi_par)
            }

            // Kick off recursion at root.
            let _root_ep = build_endpoint::<L, F, W>(
                blocks,
                root,
                &mut cache,
                &leaves,
                &folds,
                &wraps,
                opts.wrap_cadence,
            );
        }
    }

    // Assemble the final bundle.
    let mut out = FoldProofBundle::empty(t, root.lo, root.hi);
    out.leaves = leaves.into_inner();
    out.folds = folds.into_inner();
    out.wraps = wraps.into_inner();
    out
}

/* ------------------------------ streaming sink I/O ------------------------- */

/// Stream header (first CBOR value in the sequence).
///
/// Stream layout: `Header, Item*, Footer` — each is a single CBOR value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHeader {
    /// Protocol identifier (e.g. `"sezkp-fold-seq"`).
    pub magic: String,
    /// Version of this CBOR-seq stream format (currently `1`).
    pub ver: u16,
    /// Driver options captured at start.
    pub wrap_cadence: u32,
    /// Folding mode used by the driver (balanced/minram).
    pub mode: crate::api::FoldMode,
    /// Reserved for future use (may be `0`).
    pub reserved: u32,
}

/// Stream footer (last CBOR value in the sequence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamFooter {
    /// Number of leaves observed (equals number of pushed blocks).
    pub n_blocks: u64,
    /// Final root commitment.
    pub root_c: Commitment,
    /// Commitment to the final root projection `π`.
    pub root_pi_cmt: PiCommitment,
}

/// Stream item (middle CBOR values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamItem<Lp, Fp, Wp> {
    /// Leaf proof `(C, π_commitment, proof)`.
    Leaf {
        /// Commitment of the leaf subtree (one input block).
        c: Commitment,
        /// Commitment to the public projection `π` (opaque on the wire).
        pi_cmt: PiCommitment,
        /// Gadget-specific proof payload produced by the leaf prover.
        proof: Lp,
    },
    /// Internal-node fold `(parent, left, right, proof)`.
    Fold {
        /// Commitment pair of the parent node produced by folding.
        parent: (Commitment, PiCommitment),
        /// Commitment pair of the left child.
        left: (Commitment, PiCommitment),
        /// Commitment pair of the right child.
        right: (Commitment, PiCommitment),
        /// Gadget-specific proof payload for the fold step.
        proof: Fp,
    },
    /// Optional wrap proof over a subtree root.
    Wrap {
        /// Commitment pair of the (sub)tree root being wrapped.
        root: (Commitment, PiCommitment),
        /// Gadget-specific proof payload for the wrap attestations.
        proof: Wp,
    },
}

/// A sink that receives bundle events as they occur.
///
/// Implementors should be *append-only*: each callback corresponds to one
/// event in the canonical emission order.
pub trait BundleSink<Lp, Fp, Wp> {
    /// Called once at the beginning of the stream.
    fn start(&mut self, header: &StreamHeader) -> Result<()>;
    /// Called for each leaf (left→right).
    fn on_leaf(&mut self, c: Commitment, pi_cmt: PiCommitment, proof: Lp) -> Result<()>;
    /// Called for each internal fold (bottom-up order).
    fn on_fold(
        &mut self,
        parent: (Commitment, PiCommitment),
        left: (Commitment, PiCommitment),
        right: (Commitment, PiCommitment),
        proof: Fp,
    ) -> Result<()>;
    /// Called whenever a wrap is emitted (if enabled by cadence).
    fn on_wrap(&mut self, root: (Commitment, PiCommitment), proof: Wp) -> Result<()>;
    /// Called once at the end of the stream.
    fn finish(&mut self, footer: &StreamFooter) -> Result<()>;
}

/// A concrete sink that writes a CBOR sequence to any [`Write`] impl.
///
/// Each call serializes exactly one CBOR value to `w`, in this order:
/// `Header`, then many `Item`s, then the final `Footer`.
pub struct CborSeqSink<W: Write> {
    w: W,
    started: bool,
}

impl<W: Write> CborSeqSink<W> {
    /// Construct a CBOR-seq sink from the given writer.
    #[inline]
    #[must_use]
    pub fn new(w: W) -> Self {
        Self { w, started: false }
    }
}

impl<Lp, Fp, Wp, Wt> BundleSink<Lp, Fp, Wp> for CborSeqSink<Wt>
where
    Lp: serde::Serialize,
    Fp: serde::Serialize,
    Wp: serde::Serialize,
    Wt: Write,
{
    fn start(&mut self, header: &StreamHeader) -> Result<()> {
        if !self.started {
            ciborium::ser::into_writer(header, &mut self.w)?;
            self.started = true;
        }
        Ok(())
    }

    fn on_leaf(&mut self, c: Commitment, pi_cmt: PiCommitment, proof: Lp) -> Result<()> {
        let item = StreamItem::<Lp, Fp, Wp>::Leaf { c, pi_cmt, proof };
        ciborium::ser::into_writer(&item, &mut self.w)?;
        Ok(())
    }

    fn on_fold(
        &mut self,
        parent: (Commitment, PiCommitment),
        left: (Commitment, PiCommitment),
        right: (Commitment, PiCommitment),
        proof: Fp,
    ) -> Result<()> {
        let item = StreamItem::<Lp, Fp, Wp>::Fold {
            parent,
            left,
            right,
            proof,
        };
        ciborium::ser::into_writer(&item, &mut self.w)?;
        Ok(())
    }

    fn on_wrap(&mut self, root: (Commitment, PiCommitment), proof: Wp) -> Result<()> {
        let item = StreamItem::<Lp, Fp, Wp>::Wrap { root, proof };
        ciborium::ser::into_writer(&item, &mut self.w)?;
        Ok(())
    }

    fn finish(&mut self, footer: &StreamFooter) -> Result<()> {
        ciborium::ser::into_writer(footer, &mut self.w)?;
        Ok(())
    }
}

/* ------------------------------ streaming driver --------------------------- */

/// Internal node carried on the streaming stack.
struct Subtree {
    /// Half-open span `[lo, hi)`.
    lo: u32,
    /// Half-open span `[lo, hi)`.
    hi: u32,
    /// Subtree commitment endpoint.
    c: Commitment,
    /// Subtree projection endpoint (internal only; never streamed).
    p: Pi,
    /// First (leftmost) block in the subtree—needed to compute boundary digests.
    first: BlockSummary,
    /// Last (rightmost) block in the subtree—needed to compute boundary digests.
    last: BlockSummary,
}

/// Push-based streaming builder that consumes blocks left→right and emits the
/// same balanced-tree fold structure as the batch driver, while keeping only
/// `O(log T)` live subtrees.
pub struct StreamDriver<L, F, W>
where
    L: Leaf,
    F: Fold,
    W: Wrap,
{
    opts: DriverOptions,
    next_idx: u32, // index of the next leaf to be pushed
    stack: Vec<Subtree>,

    // Output bundle buffers
    leaves: Vec<(Commitment, Pi, L::Proof)>,
    folds: Vec<((Commitment, Pi), (Commitment, Pi), (Commitment, Pi), F::Proof)>,
    wraps: Vec<((Commitment, Pi), W::Proof)>,
}

impl<L, F, W> StreamDriver<L, F, W>
where
    L: Leaf,
    F: Fold,
    W: Wrap,
{
    /// Create a new streaming driver with the given options.
    #[inline]
    #[must_use]
    pub fn new(opts: DriverOptions) -> Self {
        Self {
            opts,
            next_idx: 0,
            stack: Vec::new(),
            leaves: Vec::new(),
            folds: Vec::new(),
            wraps: Vec::new(),
        }
    }

    /// Return the effective driver options.
    #[inline]
    #[must_use]
    pub fn options(&self) -> &DriverOptions {
        &self.opts
    }

    /// Number of leaves pushed so far.
    #[inline]
    #[must_use]
    pub fn n_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Push the next validated block and update the streaming state.
    pub fn push_block(&mut self, mut block: BlockSummary) -> anyhow::Result<()> {
        // 1) Leaf proof
        let (pi, c, pr) = L::prove_leaf(&block);
        self.leaves.push((c, pi, pr));

        // 2) New leaf subtree
        let i = self.next_idx;
        self.next_idx = self.next_idx.saturating_add(1);

        // For a leaf, first == last. Move `block` into `last`, clone once for `first`.
        let first = block.clone();
        let last = block;

        self.stack.push(Subtree {
            lo: i,
            hi: i + 1,
            c,
            p: pi,
            first,
            last,
        });

        // 3) Greedily collapse siblings where midpoint equals boundary
        self.try_collapses::<L, F, W>();

        Ok(())
    }

    /// Finish: collapse any remaining siblings and return the bundle.
    #[must_use]
    pub fn finish_bundle(mut self) -> FoldProofBundle<L::Proof, F::Proof, W::Proof> {
        self.try_collapses::<L, F, W>();

        let mut out = FoldProofBundle::empty(self.leaves.len(), 0, self.next_idx);
        out.leaves = self.leaves;
        out.folds = self.folds;
        out.wraps = self.wraps;
        out
    }

    /// Merge top-of-stack sibling spans until no more merges are possible.
    fn try_collapses<Lx, Fx, Wx>(&mut self)
    where
        Lx: Leaf,
        Fx: Fold,
        Wx: Wrap,
        L: Leaf<Proof = Lx::Proof>,
        F: Fold<Proof = Fx::Proof>,
        W: Wrap<Proof = Wx::Proof>,
    {
        loop {
            if self.stack.len() < 2 {
                break;
            }
            let (l_span_lo, l_span_hi, r_span_lo, r_span_hi) = {
                let l = &self.stack[self.stack.len() - 2];
                let r = &self.stack[self.stack.len() - 1];
                // Must be adjacent
                if l.hi != r.lo {
                    break;
                }
                (l.lo, l.hi, r.lo, r.hi)
            };
            // Balanced-tree sibling test: midpoint equals boundary.
            let mid = (l_span_lo + r_span_hi) / 2;
            if mid != l_span_hi {
                break;
            }

            // Pop siblings
            let right = self.stack.pop().expect("right subtree present");
            let left = self.stack.pop().expect("left subtree present");

            // Boundary digest between last(left) and first(right)
            let digest = interface_boundary_digest(&left.last, &right.first);
            let iface = InterfaceWitness {
                left_ctrl_out: left.p.ctrl_out,
                right_ctrl_in: right.p.ctrl_in,
                boundary_writes_digest: digest,
            };

            let (c_par, p_par, pf) = F::fold((&left.c, &left.p), (&right.c, &right.p), &iface);

            // Record fold + optional wrap
            self.folds
                .push(((c_par, p_par), (left.c, left.p), (right.c, right.p), pf));

            if self.opts.wrap_cadence != 0 {
                let k = self.opts.wrap_cadence as usize;
                if self.folds.len() % k == 0 {
                    let w = W::wrap((&c_par, &p_par));
                    self.wraps.push(((c_par, p_par), w));
                }
            }

            // Parent subtree: span [left.lo, right.hi), first=left.first, last=right.last
            self.stack.push(Subtree {
                lo: left.lo,
                hi: right.hi,
                c: c_par,
                p: p_par,
                first: left.first,
                last: right.last,
            });
        }
    }
}

/* ------------ streaming driver variant that EMITS into a sink --------------- */

/// Streaming driver that emits CBOR-seq (or any [`BundleSink`]) *as it runs*.
///
/// This variant never collects the entire bundle: each leaf/fold/wrap event is
/// sent to the provided `sink` immediately, so memory stays `O(log T)`.
pub struct StreamDriverSink<L, F, W, S>
where
    L: Leaf,
    F: Fold,
    W: Wrap,
    S: BundleSink<L::Proof, F::Proof, W::Proof>,
{
    opts: DriverOptions,
    next_idx: u32,
    stack: Vec<Subtree>,
    sink: S,
    leaves_seen: u64,
    started: bool,
    // track folds to decide wrap cadence
    folds_emitted: usize,
    _phantom: std::marker::PhantomData<(L, F, W)>,
}

impl<L, F, W, S> StreamDriverSink<L, F, W, S>
where
    L: Leaf,
    F: Fold,
    W: Wrap,
    S: BundleSink<L::Proof, F::Proof, W::Proof>,
{
    /// Construct a streaming driver bound to a sink and emit the header.
    pub fn new(mut sink: S, opts: DriverOptions) -> Result<Self> {
        // Emit header immediately
        let header = StreamHeader {
            magic: "sezkp-fold-seq".to_owned(),
            ver: 1,
            wrap_cadence: opts.wrap_cadence,
            mode: opts.fold_mode,
            reserved: 0,
        };
        sink.start(&header)?;
        Ok(Self {
            opts,
            next_idx: 0,
            stack: Vec::new(),
            sink,
            leaves_seen: 0,
            started: true,
            folds_emitted: 0,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Push the next block; emit `Leaf` + subsequent `Fold`/`Wrap` items.
    pub fn push_block(&mut self, mut block: BlockSummary) -> Result<()> {
        // 1) Leaf proof
        let (pi, c, pr) = L::prove_leaf(&block);
        let pi_cmt = commit_pi(&pi);
        self.sink.on_leaf(c, pi_cmt, pr)?;
        self.leaves_seen = self.leaves_seen.saturating_add(1);

        // 2) New leaf subtree on stack
        let i = self.next_idx;
        self.next_idx = self.next_idx.saturating_add(1);
        let first = block.clone();
        let last = block;
        self.stack.push(Subtree {
            lo: i,
            hi: i + 1,
            c,
            p: pi,
            first,
            last,
        });

        // 3) Greedily collapse siblings
        self.try_collapses::<L, F, W>()?;
        Ok(())
    }

    /// Finish: fully collapse, emit the footer, and return the final `(C, π)`.
    pub fn finish(mut self) -> Result<(Commitment, Pi)> {
        self.try_collapses::<L, F, W>()?;
        // Top of stack should be the root (or empty input → zeroed root).
        let (root_c, root_pi) = if let Some(top) = self.stack.last() {
            (top.c, top.p)
        } else {
            (Commitment::new([0u8; 32], 0), Pi::default())
        };
        let footer = StreamFooter {
            n_blocks: self.leaves_seen,
            root_c,
            root_pi_cmt: commit_pi(&root_pi),
        };
        self.sink.finish(&footer)?;
        Ok((root_c, root_pi))
    }

    /// Internal helper: perform zero or more collapses and emit folds/wraps.
    fn try_collapses<Lx, Fx, Wx>(&mut self) -> Result<()>
    where
        Lx: Leaf,
        Fx: Fold,
        Wx: Wrap,
        L: Leaf<Proof = Lx::Proof>,
        F: Fold<Proof = Fx::Proof>,
        W: Wrap<Proof = Wx::Proof>,
    {
        loop {
            if self.stack.len() < 2 {
                break;
            }
            let (l_span_lo, l_span_hi, r_span_lo, r_span_hi) = {
                let l = &self.stack[self.stack.len() - 2];
                let r = &self.stack[self.stack.len() - 1];
                if l.hi != r.lo {
                    break;
                }
                (l.lo, l.hi, r.lo, r.hi)
            };
            let mid = (l_span_lo + r_span_hi) / 2;
            if mid != l_span_hi {
                break;
            }

            // Pop siblings
            let right = self.stack.pop().expect("right subtree present");
            let left = self.stack.pop().expect("left subtree present");

            // Boundary digest
            let digest = interface_boundary_digest(&left.last, &right.first);
            let iface = InterfaceWitness {
                left_ctrl_out: left.p.ctrl_out,
                right_ctrl_in: right.p.ctrl_in,
                boundary_writes_digest: digest,
            };

            let (c_par, p_par, pf) = F::fold((&left.c, &left.p), (&right.c, &right.p), &iface);

            // Emit fold (commit to πs on the wire)
            self.sink.on_fold(
                (c_par, commit_pi(&p_par)),
                (left.c, commit_pi(&left.p)),
                (right.c, commit_pi(&right.p)),
                pf,
            )?;
            self.folds_emitted += 1;

            // Maybe emit wrap
            if self.opts.wrap_cadence != 0 {
                let k = self.opts.wrap_cadence as usize;
                if self.folds_emitted % k == 0 {
                    let w = W::wrap((&c_par, &p_par));
                    self.sink.on_wrap((c_par, commit_pi(&p_par)), w)?;
                }
            }

            // Push parent
            self.stack.push(Subtree {
                lo: left.lo,
                hi: right.hi,
                c: c_par,
                p: p_par,
                first: left.first,
                last: right.last,
            });
        }
        Ok(())
    }
}
