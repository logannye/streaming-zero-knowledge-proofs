// crates/sezkp-fold/src/driver.rs

//! Glue driver: run the height-compressed scheduler with Leaf / Fold / Wrap
//! callbacks, building a folding proof artifact.
//!
//! Modes:
//! - **Balanced**: pointerless DFS with an O(T) endpoint ledger.
//! - **MinRam**: recompute endpoints on demand; keep a tiny LRU cache
//!   bounded by `DriverOptions::endpoint_cache` (default 64).
//! - **Streaming**: push-based builder that keeps only O(log T) live
//!   subtrees while consuming blocks left→right. Produces the *same* balanced
//!   tree shape by greedily merging sibling spans where the midpoint equals
//!   the boundary between adjacent subtrees.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sezkp_core::BlockSummary;
use sezkp_scheduler as hct;
use sezkp_stark::v1::columns::interface_boundary_digest;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::api::{Commitment, DriverOptions, Fold, Leaf, Wrap};
use crate::are::{InterfaceWitness, Pi};

/// Serializable folding artifact (compact and human-inspectable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldProofBundle<Lp, Fp, Wp> {
    /// Number of input blocks.
    pub n_blocks: usize,
    /// Root interval spanned by the balanced tree. Half-open [lo, hi).
    pub tree_span: (u32, u32),
    /// Per-leaf records: `(C, π, leaf_proof)`.
    pub leaves: Vec<(Commitment, Pi, Lp)>,
    /// Per-fold records: `(parent(C,π), left(C,π), right(C,π), fold_proof)`.
    pub folds: Vec<((Commitment, Pi), (Commitment, Pi), (Commitment, Pi), Fp)>,
    /// Optional wrap attestations of intermediate or final roots.
    pub wraps: Vec<((Commitment, Pi), Wp)>,
}

impl<Lp, Fp, Wp> FoldProofBundle<Lp, Fp, Wp> {
    /// Create an empty bundle that will be filled by the driver.
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
    #[allow(dead_code)]
    pub fn n_leaves(&self) -> usize {
        self.leaves.len()
    }
}

/// Derive a tiny commitment for a subtree from `(C, π)`.
#[allow(dead_code)] // used by some gadget variants; keep for convenience
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SpanKey(u32, u32);

#[derive(Default)]
struct EndpointCache {
    cap: usize,
    map: HashMap<SpanKey, (Commitment, Pi)>,
    order: VecDeque<SpanKey>, // front = LRU, back = MRU
}

impl EndpointCache {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    fn touch_back(&mut self, k: SpanKey) {
        if let Some(pos) = self.order.iter().position(|x| *x == k) {
            self.order.remove(pos);
        }
        self.order.push_back(k);
    }
    fn get(&mut self, k: SpanKey) -> Option<(Commitment, Pi)> {
        if let Some(v) = self.map.get(&k).cloned() {
            self.touch_back(k);
            Some(v)
        } else {
            None
        }
    }
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

/// Run the fold pipeline with generic Leaf/Fold/Wrap gadgets.
///
/// - **Balanced**: pointerless DFS with O(T) ledger of endpoints.
/// - **MinRam**: post-order recursion with O(log T) live endpoints and a small LRU.
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

    // Assemble the final bundle
    let mut out = FoldProofBundle::empty(t, root.lo, root.hi);
    out.leaves = leaves.into_inner();
    out.folds = folds.into_inner();
    out.wraps = wraps.into_inner();
    out
}

/* ------------------------------ streaming driver --------------------------- */

/// Internal node carried on the streaming stack.
struct Subtree {
    /// Half-open span [lo, hi)
    lo: u32,
    hi: u32,
    /// Endpoints commitment/projection for the subtree.
    c: Commitment,
    p: Pi,
    /// Boundary blocks needed for future merges.
    first: BlockSummary,
    last: BlockSummary,
}

/// Push-based streaming builder that consumes blocks left→right and emits the
/// same balanced-tree fold structure as the batch driver, while keeping only
/// O(log T) live subtrees.
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

    #[inline]
    /// Get the driver options.
    pub fn options(&self) -> &DriverOptions {
        &self.opts
    }

    #[inline]
    /// Get the number of leaves pushed.
    pub fn n_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Push the next block (index increases monotonically).
    pub fn push_block(&mut self, mut block: BlockSummary) -> anyhow::Result<()> {
        // 1) Leaf proof
        let (pi, c, pr) = L::prove_leaf(&block);
        self.leaves.push((c, pi, pr));

        // 2) New leaf subtree
        let i = self.next_idx;
        self.next_idx += 1;

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
    pub fn finish_bundle(mut self) -> FoldProofBundle<L::Proof, F::Proof, W::Proof> {
        // In case the last push didn't fully collapse (it should have),
        // try again until no more sibling pairs exist.
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
            let (l_span_lo, l_span_hi);
            let (r_span_lo, r_span_hi);
            {
                let l = &self.stack[self.stack.len() - 2];
                let r = &self.stack[self.stack.len() - 1];
                // Must be adjacent
                if l.hi != r.lo {
                    break;
                }
                l_span_lo = l.lo;
                l_span_hi = l.hi;
                r_span_lo = r.lo;
                r_span_hi = r.hi;
            }
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
