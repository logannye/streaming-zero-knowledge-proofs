// crates/sezkp-scheduler/src/lib.rs

//! Height-compressed scheduler (HCT) with pointerless DFS.
//!
//! - Balanced splits on `[lo, hi)` intervals (midpoint).
//! - Pointerless, post-order DFS using O(1) tokens per level (O(log T) live).
//! - No index arrays; callbacks fire in left-to-right order for leaves,
//!   and in post-order for merges.

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

/// Half-open interval `[lo, hi)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// inclusive lower bound
    pub lo: u32,
    /// exclusive upper bound
    pub hi: u32,
}

impl Interval {
    /// Create an interval `[lo, hi)`.
    #[inline]
    #[must_use]
    pub const fn new(lo: u32, hi: u32) -> Self {
        Self { lo, hi }
    }

    /// Length of the interval.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.hi.saturating_sub(self.lo)
    }

    /// Whether the span is a leaf (length 1).
    #[inline]
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.len() <= 1
    }

    /// Balanced split at midpoint. Returns `(left, right)`; if `len()==1`,
    /// returns `(self, self)`.
    #[inline]
    #[must_use]
    pub fn split_mid(&self) -> (Self, Self) {
        let len = self.len();
        if len <= 1 {
            return (*self, *self);
        }
        let mid = self.lo + len / 2;
        (Self::new(self.lo, mid), Self::new(mid, self.hi))
    }
}

/// Root interval for `T` leaves.
#[inline]
#[must_use]
pub fn balanced_tree(t: usize) -> Interval {
    Interval::new(0, t as u32)
}

/// Pointerless post-order DFS with balanced splits.
///
/// - `t`: number of leaves
/// - `on_leaf(span)`: called for each unit interval `[i, i+1)` in order
/// - `on_merge(span)`: called after both children of `span` were processed
///
/// Memory: ≤ `O(log t)` frames; no node allocations.
pub fn dfs<FL, FM>(t: usize, mut on_leaf: FL, mut on_merge: FM)
where
    FL: FnMut(Interval),
    FM: FnMut(Interval),
{
    if t == 0 {
        return;
    }
    // Frame states: 0 = enter, 1 = left done (go right next)
    #[derive(Clone, Copy)]
    struct Frame {
        span: Interval,
        state: u8,
    }

    let mut st = Vec::<Frame>::new();
    st.push(Frame {
        span: balanced_tree(t),
        state: 0,
    });

    while let Some(top) = st.last_mut() {
        if top.span.is_leaf() {
            let leaf = top.span;
            st.pop();
            on_leaf(leaf);
            // Bubble up: either go to right child or merge and continue bubbling.
            while let Some(parent) = st.last_mut() {
                match parent.state {
                    0 => {
                        parent.state = 1;
                        let (_l, r) = parent.span.split_mid();
                        st.push(Frame { span: r, state: 0 });
                        break; // descend right
                    }
                    1 => {
                        let span = parent.span;
                        st.pop();
                        on_merge(span);
                        // keep bubbling
                    }
                    _ => unreachable!("invalid frame state"),
                }
            }
            continue;
        }

        // Non-leaf first visit: descend left
        if top.state == 0 {
            let (l, _r) = top.span.split_mid();
            st.push(Frame { span: l, state: 0 });
        } else {
            // Other states are handled by bubbling after child returns.
            unreachable!("unexpected state during descent");
        }
    }
}

/// Compute maximum live frames during DFS (upper bound on live interfaces).
///
/// Uses the same pointerless traversal but avoids holding a mutable borrow
/// while reading `st.len()` (fixes borrow-checker complaint).
#[must_use]
pub fn max_live_frames(t: usize) -> usize {
    if t == 0 {
        return 0;
    }

    #[derive(Clone, Copy)]
    struct Frame {
        span: Interval,
        state: u8,
    }

    let mut st = Vec::<Frame>::new();
    st.push(Frame {
        span: balanced_tree(t),
        state: 0,
    });

    let mut max_depth = st.len();

    while !st.is_empty() {
        // Snapshot the current top to avoid aliasing issues with borrows.
        let top = *st.last().expect("stack not empty");
        let cur_len = st.len();
        if cur_len > max_depth {
            max_depth = cur_len;
        }

        if top.span.is_leaf() {
            st.pop();
            // Bubble up through parents.
            loop {
                // Refresh len each loop to keep max up to date.
                let cur_len = st.len();
                if cur_len > max_depth {
                    max_depth = cur_len;
                }
                let Some(parent) = st.last_mut() else { break };
                match parent.state {
                    0 => {
                        parent.state = 1;
                        let (_l, r) = parent.span.split_mid();
                        st.push(Frame { span: r, state: 0 });
                        break; // descend right
                    }
                    1 => {
                        st.pop(); // emit merge (counted by caller if needed)
                                  // continue bubbling
                    }
                    _ => unreachable!(),
                }
            }
            continue;
        }

        // Non-leaf first visit: descend left
        if top.state == 0 {
            let (l, _r) = top.span.split_mid();
            st.push(Frame { span: l, state: 0 });
            let cur_len = st.len();
            if cur_len > max_depth {
                max_depth = cur_len;
            }
        }
    }

    max_depth
}

/// Ceil log2 helper for small values.
#[inline]
#[must_use]
pub fn ceil_log2(mut x: usize) -> usize {
    if x <= 1 {
        return 0;
    }
    x -= 1;
    let mut lg = 0usize;
    while x > 0 {
        x >>= 1;
        lg += 1;
    }
    lg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_in_order_and_postorder_merges() {
        for &t in &[1usize, 2, 3, 4, 5, 7, 8, 9, 17, 32, 1024] {
            let mut leaves = Vec::new();
            let mut merges = Vec::new();
            dfs(t, |s| leaves.push((s.lo, s.hi)), |s| merges.push((s.lo, s.hi)));
            // Leaves are in order 0..t
            assert_eq!(leaves.len(), t);
            for (i, (lo, hi)) in leaves.iter().enumerate() {
                assert_eq!((*lo, *hi), (i as u32, i as u32 + 1));
            }
            // Root merge is last and spans whole interval.
            if t > 1 {
                let (lo, hi) = *merges.last().unwrap();
                assert_eq!((lo, hi), (0, t as u32));
            } else {
                assert!(merges.is_empty());
            }
        }
    }

    #[test]
    fn live_frames_is_logarithmic() {
        for &t in &[1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33, 1000] {
            let depth = max_live_frames(t);
            let bound = ceil_log2(t) + 2; // small slack for odd sizes
            assert!(
                depth <= bound,
                "depth {} exceeded O(log T) bound {} for T={}",
                depth,
                bound,
                t
            );
        }
    }
}
