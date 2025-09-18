//! One-shot evaluator with an internal bottom-up scheduler.
//!
//! Replays leaf blocks to finite-state summaries, checks interfaces via the
//! exact replayer, and combines them up to the root using a [`Combiner`].
//!
//! This evaluator is intentionally single-shot and self-contained: callers pass
//! a slice of [`BlockSummary`] and receive the root [`FiniteState`]. There is no
//! external scheduler dependency.
//!
//! ## Algorithm sketch
//! 1. Replay each leaf block `k` into Σ([k,k]) using [`ExactReplayer`].
//! 2. For spans `1,2,4,...`, combine adjacent intervals bottom-up:
//!    Σ([i,mid]) ⊕ Σ([mid+1,j]) → Σ([i,j]).
//! 3. Enforce interface equality with the *authoritative* replayer check before
//!    combining. (The combiner only sees constant-size summaries.)
//!
//! ## Complexity
//! - Time: `O(n)` replays + `O(n)` combines = `O(n)`.
//! - Space: `O(n)` transient map of intermediate Σ([i,j]) states.
//!
//! Prefer [`Evaluator::evaluate_root_checked`] in library code; it returns a rich
//! error instead of panicking on internal inconsistencies.

use crate::replay::BoundedReplay; // bring trait into scope for method calls
use crate::{BlockSummary, Combiner, ConstantCombiner, ExactReplayer, FiniteState};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;

/// Simple one-shot evaluator over a bottom-up schedule.
///
/// Owns the replay engine and a constant-size combiner.
#[derive(Debug)]
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
    /// # Errors
    /// - Returns an error if `blocks.len()` exceeds `u32::MAX`.
    /// - Returns an error if any interface check fails or an internal interval is missing.
    pub fn evaluate_root_checked(&self, blocks: &[BlockSummary]) -> Result<FiniteState> {
        let n = blocks.len();
        if n == 0 {
            return Ok(FiniteState::default());
        }
        if n > u32::MAX as usize {
            bail!("too many blocks: {} (max supported: {})", n, u32::MAX);
        }
        let t_blocks = n as u32;

        #[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
        struct Key(u32, u32);

        // 1) Replay leaves.
        let mut map: HashMap<Key, FiniteState> =
            HashMap::with_capacity(blocks.len().saturating_mul(2));
        for k in 1..=t_blocks {
            let blk = &blocks[(k - 1) as usize];
            let fs = self.replayer.replay_block(blk);
            map.insert(Key(k, k), fs);
        }

        // 2) Combine bottom-up with doubling span (handles non powers of two).
        let mut span: u32 = 1;
        while span < t_blocks {
            let mut start: u32 = 1;
            while start <= t_blocks {
                let mid = start.saturating_add(span).saturating_sub(1);
                if mid >= t_blocks {
                    break; // no right interval available
                }
                let end = (start + 2 * span - 1).min(t_blocks);

                let left_key = Key(start, mid);
                let right_key = Key(mid + 1, end);

                let left = map
                    .get(&left_key)
                    .with_context(|| format!("missing Σ({:?}) during combine", left_key))?;
                let right = map
                    .get(&right_key)
                    .with_context(|| format!("missing Σ({:?}) during combine", right_key))?;

                // Exact interface check (authoritative).
                if !self.replayer.interface_ok(left, right) {
                    return Err(anyhow!(
                        "interface mismatch at {:?} + {:?} (exact replay check failed)",
                        left_key,
                        right_key
                    ));
                }

                let parent_key = Key(start, end);
                // Combine constant-size summaries. Precondition already checked above.
                let fs = self.combiner.combine(left, right);
                map.insert(parent_key, fs);

                start = start.saturating_add(2 * span);
            }
            // Ensure forward progress even if doubling would overflow u32.
            span = span.checked_mul(2).unwrap_or(t_blocks);
        }

        map.remove(&Key(1, t_blocks))
            .ok_or_else(|| anyhow!("root Σ([1,T]) missing after evaluation"))
    }
}
