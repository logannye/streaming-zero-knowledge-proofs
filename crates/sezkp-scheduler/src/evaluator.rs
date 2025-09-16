//! One-shot evaluator that **drives** a DFS schedule end-to-end.
//!
//! It does three things for each subtree in a balanced recursion over `[1, T]`:
//! 1) **Replays** each leaf block into a `FiniteState`.
//! 2) **Checks** the left/right **interface** before merging.
//! 3) **Combines** child states with a constant-size combiner.
//!
//! This is a simple, single-machine “oracle” useful for testing and
//! regression checks. Production systems usually replace the inner pieces (e.g.,
//! replay or combine) with proving/verification gadgets—but the control flow
//! stays the same.

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

use crate::{DfsScheduler, Event};
use anyhow::{anyhow, Context, Result};
use sezkp_core::{
    BlockSummary, BoundedReplay, Combiner, ConstantCombiner, ExactReplayer, FiniteState,
};
use std::collections::HashMap;

/// One-shot evaluator over a DFS schedule.
///
/// Owns the replay engine and a constant-size combiner.
#[derive(Debug, Clone)]
pub struct Evaluator {
    replayer: ExactReplayer,
    combiner: ConstantCombiner,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            replayer: ExactReplayer::new(Default::default()),
            combiner: ConstantCombiner::new(),
        }
    }
}

impl Evaluator {
    /// Construct a new evaluator from an explicit replayer and combiner.
    #[must_use]
    pub fn new(replayer: ExactReplayer, combiner: ConstantCombiner) -> Self {
        Self { replayer, combiner }
    }

    /// Evaluate the root Σ([1,T]) from block summaries.
    ///
    /// # Panics
    /// Panics if the schedule is internally inconsistent. Prefer
    /// [`Self::evaluate_root_checked`] to avoid panics.
    #[must_use]
    pub fn evaluate_root(&self, blocks: &[BlockSummary]) -> FiniteState {
        self.evaluate_root_checked(blocks)
            .expect("evaluation failed")
    }

    /// Evaluate the root Σ([1,T]) from block summaries, returning an error on inconsistency.
    ///
    /// The evaluator memoizes intermediate Σ([i,j]) states in a hash map keyed
    /// by `(i,j)` pairs from the DFS events, then looks up and merges during
    /// `Event::Combine(left,right)`. Interfaces are validated via the
    /// `ExactReplayer::interface_ok` policy.
    pub fn evaluate_root_checked(&self, blocks: &[BlockSummary]) -> Result<FiniteState> {
        let t_blocks = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
        if t_blocks == 0 {
            return Ok(FiniteState::default());
        }

        #[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
        struct Key(u32, u32);

        let mut map: HashMap<Key, FiniteState> =
            HashMap::with_capacity(blocks.len().saturating_mul(2));
        let mut dfs = DfsScheduler::new(t_blocks);

        while let Some(ev) = dfs.next() {
            match ev {
                Event::DescendLeaf(k) => {
                    let blk = &blocks[(k - 1) as usize];
                    let fs = self.replayer.replay_block(blk);
                    map.insert(Key(k, k), fs);
                }
                Event::Combine(l, r) => {
                    let left = map
                        .get(&Key(l.i, l.j))
                        .with_context(|| format!("missing Σ([{},{}])", l.i, l.j))?;
                    let right = map
                        .get(&Key(r.i, r.j))
                        .with_context(|| format!("missing Σ([{},{}])", r.i, r.j))?;

                    if !self.replayer.interface_ok(left, right) {
                        return Err(anyhow!(
                            "interface mismatch at Σ([{},{}]) + Σ([{},{}])",
                            l.i,
                            l.j,
                            r.i,
                            r.j
                        ));
                    }

                    let parent = Key(l.i, r.j);
                    let fs = self.combiner.combine(left, right);
                    map.insert(parent, fs);
                }
                Event::Done => break,
            }
        }

        map.remove(&Key(1, t_blocks))
            .ok_or_else(|| anyhow!("root Σ([1,T]) missing after DFS"))
    }
}
