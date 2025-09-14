// crates/sezkp-core/src/combiner.rs

//! Constant-size finite-state combiner and interface checks.
//!
//! A [`Combiner`] reduces two adjacent interval finite-states into their parent’s
//! finite-state. The combiner operates only on the *constant-size* projection;
//! any block-size (`b`) dependent content is validated via exact replay at
//! interfaces (see `ExactReplayer`).
//!
//! ## Invariants
//! - The interface between the left (prefix) and right (suffix) states must be
//!   valid: control must chain, input head position must match, and each work-
//!   tape head must match (`left.out == right.in`).
//! - Callers are responsible for checking interface validity before `combine`.

use crate::types::FiniteState;

/// A combiner operates on the constant-size finite-state projection.
///
/// Implementations must *not* assume anything about block size; they should only
/// read/compose fields present in the finite-state summary.
pub trait Combiner {
    /// Merge two adjacent interval finite-states into the parent's finite-state.
    ///
    /// # Preconditions
    /// The interface between `left` and `right` has been validated.
    #[must_use]
    fn combine(&self, left: &FiniteState, right: &FiniteState) -> FiniteState;

    /// Check that the interface between `left` (as a prefix) and `right` (as a suffix) is valid.
    ///
    /// Semantically: the *exit* boundary of `left` must equal the *entry* boundary of `right`
    /// for input head and each work-tape head; control state must chain.
    #[must_use]
    fn interface_ok(&self, left: &FiniteState, right: &FiniteState) -> bool;
}

/// A trivial combiner that preserves entry state from the left and exit state from the right,
/// carrying small flags/tags by a fixed rule (XOR flags, keep right tag).
#[derive(Clone, Copy, Debug, Default)]
pub struct ConstantCombiner;

impl ConstantCombiner {
    /// Construct a new [`ConstantCombiner`].
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Combiner for ConstantCombiner {
    #[inline]
    fn combine(&self, left: &FiniteState, right: &FiniteState) -> FiniteState {
        // Precondition (enforced separately by interface_ok): left.out matches right.in

        // Determine target arity for work-tape head vectors; pad defensively.
        let tau = left.work_head_in.len().max(right.work_head_out.len());

        let mut fs = FiniteState::default();

        // Entry comes from the left.
        fs.ctrl_in = left.ctrl_in;
        fs.in_head_in = left.in_head_in;
        fs.work_head_in = left.work_head_in.clone();

        // Exit comes from the right.
        fs.ctrl_out = right.ctrl_out;
        fs.in_head_out = right.in_head_out;
        fs.work_head_out = right.work_head_out.clone();

        // Advisory tags/flags: XOR flags, keep right tag.
        fs.flags = left.flags ^ right.flags;
        fs.tag = right.tag;

        // Ensure vector lengths are consistent (pad with zeros if needed; defensive).
        if fs.work_head_in.len() != tau {
            fs.work_head_in.resize(tau, 0);
        }
        if fs.work_head_out.len() != tau {
            fs.work_head_out.resize(tau, 0);
        }

        fs
    }

    #[inline]
    fn interface_ok(&self, left: &FiniteState, right: &FiniteState) -> bool {
        // Control and input head continuity at the single interface.
        if left.ctrl_out != right.ctrl_in {
            return false;
        }
        if left.in_head_out != right.in_head_in {
            return false;
        }
        // Per-tape head continuity (exact).
        if left.work_head_out != right.work_head_in {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn associativity_holds_on_chaining_interfaces() {
        // Minimal smoke: compose three segments when interfaces chain.
        let mut a = FiniteState::default();
        let mut b = FiniteState::default();
        let mut c = FiniteState::default();

        a.ctrl_in = 1;
        a.ctrl_out = 2;
        a.in_head_in = 0;
        a.in_head_out = 10;
        a.work_head_in = vec![0, 0];
        a.work_head_out = vec![5, 6];

        b.ctrl_in = 2;
        b.ctrl_out = 3;
        b.in_head_in = 10;
        b.in_head_out = 20;
        b.work_head_in = vec![5, 6];
        b.work_head_out = vec![7, 9];

        c.ctrl_in = 3;
        c.ctrl_out = 4;
        c.in_head_in = 20;
        c.in_head_out = 25;
        c.work_head_in = vec![7, 9];
        c.work_head_out = vec![8, 11];

        let comb = ConstantCombiner::new();
        assert!(comb.interface_ok(&a, &b));
        assert!(comb.interface_ok(&b, &c));

        let ab = comb.combine(&a, &b);
        let bc = comb.combine(&b, &c);

        // (a ⊕ b) ⊕ c  vs  a ⊕ (b ⊕ c)
        let lhs = comb.combine(&ab, &c);
        let rhs = comb.combine(&a, &bc);

        assert_eq!(lhs.ctrl_in, rhs.ctrl_in);
        assert_eq!(lhs.ctrl_out, rhs.ctrl_out);
        assert_eq!(lhs.in_head_in, rhs.in_head_in);
        assert_eq!(lhs.in_head_out, rhs.in_head_out);
        assert_eq!(lhs.work_head_in, rhs.work_head_in);
        assert_eq!(lhs.work_head_out, rhs.work_head_out);

        // Flags/tag aggregation law for this combiner.
        assert_eq!(lhs.flags, (a.flags ^ b.flags) ^ c.flags);
        assert_eq!(lhs.tag, c.tag);
    }

    #[test]
    fn interface_mismatch_is_rejected() {
        let mut l = FiniteState::default();
        let mut r = FiniteState::default();
        l.ctrl_out = 1;
        r.ctrl_in = 2; // mismatch
        l.in_head_out = 3;
        r.in_head_in = 3;
        l.work_head_out = vec![1, 2];
        r.work_head_in = vec![1, 2];
        let comb = ConstantCombiner::new();
        assert!(!comb.interface_ok(&l, &r));
    }
}
