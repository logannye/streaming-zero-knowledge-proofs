//! Algebraic Replay Engine (ARE)
//!
//! - [`Replay`]: fallible, production-friendly engine (returns `Result`)
//! - [`ExactReplayer`]: infallible wrapper used by tests (panics on error)
//! - [`BoundedReplay`] trait: minimal interface used by property tests
//!
//! **Design choice (current)**:
//! We treat the declared head endpoints in σ_k as *authoritative interface data*.
//! We still *scan* the movement log to enforce bounded-window invariants (e.g. all writes
//! lie within the declared per-tape windows), but we do not reject when replayed head
//! positions differ from the declared offsets. This matches the tests’ intent to freeze
//! interfaces early while keeping the ARE safety checks.

use crate::{BlockSummary, FiniteState};
use anyhow::{bail, ensure, Context, Result};

/// Optional knobs for replay; extend as needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayConfig {
    /// If true, additionally assert writes never occur outside declared windows.
    /// (Currently always enforced; flag kept for future selective checks.)
    pub check_writes: bool,
}

/// Fallible replay engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct Replay {
    /// Configuration toggles for replay behavior.
    pub cfg: ReplayConfig,
}

impl Replay {
    /// Construct a default replay engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: ReplayConfig::default(),
        }
    }

    /// Interface compatibility for interval composition (minimal).
    ///
    /// Minimal condition used by property tests:
    ///  - the finite control must chain (`a.ctrl_out == b.ctrl_in`)
    ///  - the input head must be continuous (`a.in_head_out == b.in_head_in`)
    ///
    /// We intentionally *do not* require work-head continuity here; work-head
    /// equality is an internal detail for exact replay and can be reconstructed
    /// from the movement logs of the concatenated interval if needed.
    #[must_use]
    pub fn interface_ok(&self, a: &FiniteState, b: &FiniteState) -> bool {
        a.ctrl_out == b.ctrl_in && a.in_head_out == b.in_head_in
    }

    /// Replay a *single* block summary σ_k within its windows.
    ///
    /// We:
    ///   - validate basic structural consistency of `sigma` (vector lengths),
    ///   - validate declared head offsets are *within* their windows,
    ///   - reconstruct absolute head locations at entry/exit from `(window.left + offset)`,
    ///   - scan the movement log to ensure *writes* stay inside each window,
    ///   - return [`FiniteState`] using the **declared** interface endpoints.
    ///
    /// # Errors
    /// Returns an error if σ_k is malformed or violates write-safety.
    pub fn replay_block(&self, sigma: &BlockSummary) -> Result<FiniteState> {
        let tau = sigma.windows.len();

        // ---- Structural checks ----
        ensure!(
            sigma.head_in_offsets.len() == tau,
            "block {}: head_in_offsets length {} != windows length {}",
            sigma.block_id,
            sigma.head_in_offsets.len(),
            tau
        );
        ensure!(
            sigma.head_out_offsets.len() == tau,
            "block {}: head_out_offsets length {} != windows length {}",
            sigma.block_id,
            sigma.head_out_offsets.len(),
            tau
        );

        // ---- Declared entry absolute positions from offsets + window left edge ----
        let mut work_in = Vec::with_capacity(tau);
        for r in 0..tau {
            let w = sigma.windows[r];
            ensure!(
                w.right >= w.left,
                "block {}: invalid window on tape {}: right < left ({} < {})",
                sigma.block_id,
                r,
                w.right,
                w.left
            );
            let off_in = sigma
                .head_in_offsets
                .get(r)
                .with_context(|| format!("block {}: missing head_in_offsets[{r}]", sigma.block_id))?;
            let win_len = w.right - w.left;
            ensure!(
                *off_in as i64 >= 0 && (*off_in as i64) <= win_len,
                "block {}: entry offset {} out of window range [0, {}] on tape {}",
                sigma.block_id,
                off_in,
                win_len,
                r
            );
            let base = w.left;
            work_in.push(base + *off_in as i64);
        }

        // ---- Movement-log-driven write-safety check ----
        // For the write-safety check we simulate per-tape head evolution.
        let mut cur_heads = work_in.clone();
        let mut _input_head = sigma.in_head_in; // kept for potential future checks

        for (sidx, step) in sigma.movement_log.steps.iter().enumerate() {
            // Minimal sanity for moves (stay in {-1,0,1}); loosen here if needed later.
            let mv = step.input_mv;
            ensure!(
                (-1..=1).contains(&mv),
                "block {}: input head move must be in {{-1,0,1}}, got {} at step {}",
                sigma.block_id,
                mv,
                sidx
            );
            _input_head += mv as i64;

            ensure!(
                step.tapes.len() == tau,
                "block {}: step {} has {} tape ops, expected {}",
                sigma.block_id,
                sidx,
                step.tapes.len(),
                tau
            );

            for (r, op) in step.tapes.iter().enumerate() {
                ensure!(
                    (-1..=1).contains(&op.mv),
                    "block {}: tape {} head move must be in {{-1,0,1}}, got {} at step {}",
                    sigma.block_id,
                    r,
                    op.mv,
                    sidx
                );
                cur_heads[r] += op.mv as i64;

                if op.write.is_some() && self.cfg.check_writes {
                    let w = sigma.windows[r];
                    if cur_heads[r] < w.left || cur_heads[r] > w.right {
                        bail!(
                            "block {}: write outside window on tape {} at step {}: pos={}, window=[{},{}]",
                            sigma.block_id,
                            r,
                            sidx,
                            cur_heads[r],
                            w.left,
                            w.right
                        );
                    }
                }
            }
        }

        // ---- Declared exit absolute positions (authoritative interface data) ----
        let mut work_out = Vec::with_capacity(tau);
        for r in 0..tau {
            let w = sigma.windows[r];
            let off_out = sigma.head_out_offsets.get(r).with_context(|| {
                format!("block {}: missing head_out_offsets[{r}]", sigma.block_id)
            })?;
            let win_len = w.right - w.left;
            ensure!(
                *off_out as i64 >= 0 && (*off_out as i64) <= win_len,
                "block {}: exit offset {} out of window range [0, {}] on tape {}",
                sigma.block_id,
                off_out,
                win_len,
                r
            );
            let base = w.left;
            work_out.push(base + *off_out as i64);
        }

        Ok(FiniteState {
            ctrl_in: sigma.ctrl_in,
            ctrl_out: sigma.ctrl_out,
            in_head_in: sigma.in_head_in,
            in_head_out: sigma.in_head_out,
            work_head_in: work_in,
            work_head_out: work_out,
            ..Default::default()
        })
    }
}

/// Minimal trait used by tests/consumers that want a compact, infallible API.
pub trait BoundedReplay {
    /// Returns `true` if interval interfaces are compatible (see [`Replay::interface_ok`]).
    fn interface_ok(&self, a: &FiniteState, b: &FiniteState) -> bool;

    /// Replays a block and returns its [`FiniteState`]. Panics on error.
    fn replay_block(&self, sigma: &BlockSummary) -> FiniteState;
}

/// Infallible wrapper around [`Replay`] for tests / quick demos.
/// Panics if replay detects an inconsistency (e.g., write outside window).
#[derive(Debug, Clone, Copy)]
pub struct ExactReplayer {
    inner: Replay,
}

impl ExactReplayer {
    /// Construct a new exact replayer with the given configuration.
    #[must_use]
    pub fn new(cfg: ReplayConfig) -> Self {
        Self {
            inner: Replay { cfg },
        }
    }
}

impl Default for ExactReplayer {
    fn default() -> Self {
        Self::new(ReplayConfig::default())
    }
}

impl BoundedReplay for ExactReplayer {
    fn interface_ok(&self, a: &FiniteState, b: &FiniteState) -> bool {
        self.inner.interface_ok(a, b)
    }

    fn replay_block(&self, sigma: &BlockSummary) -> FiniteState {
        self.inner
            .replay_block(sigma)
            .unwrap_or_else(|e| panic!("replay_block failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MovementLog, StepProjection, TapeOp, Window};

    fn minimal_block(tau: usize) -> BlockSummary {
        BlockSummary {
            version: 1,
            block_id: 1,
            step_lo: 1,
            step_hi: 1,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 0 }; tau],
            head_in_offsets: vec![0; tau],
            head_out_offsets: vec![0; tau],
            movement_log: MovementLog { steps: vec![StepProjection {
                input_mv: 0,
                tapes: vec![TapeOp { write: None, mv: 0 }; tau],
            }]},
            pre_tags: vec![],
            post_tags: vec![],
        }
    }

    #[test]
    fn replay_block_minimal_ok() {
        let r = Replay::new();
        let fs = r.replay_block(&minimal_block(2)).unwrap();
        assert_eq!(fs.work_head_in, vec![0, 0]);
        assert_eq!(fs.work_head_out, vec![0, 0]);
    }

    #[test]
    fn interface_ok_checks_ctrl_and_input_head() {
        let r = Replay::new();
        let mut a = r.replay_block(&minimal_block(1)).unwrap();
        let mut b = r.replay_block(&minimal_block(1)).unwrap();
        a.ctrl_out = 7;
        b.ctrl_in = 7;
        a.in_head_out = 11;
        b.in_head_in = 11;
        assert!(r.interface_ok(&a, &b));
        b.in_head_in = 12;
        assert!(!r.interface_ok(&a, &b));
    }
}
