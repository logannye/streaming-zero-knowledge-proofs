//! Balanced (midpoint) recursion utilities over inclusive intervals `[1, T]`.
//!
//! This helper mirrors the “height-compressed tree” used throughout the codebase.
//! It provides:
//! - `ceil_log2_u32`: tiny ceil-log helper
//! - `children`: split an inclusive `[i, j]` into `( [i, m], [m+1, j] )`
//! - `depth_bound`: theoretical recursion depth bound for `T` leaves
//!
//! Used by `dfs.rs` to compute balanced splits during pointerless DFS.

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

use sezkp_core::Interval;

/// Compute `ceil(log2(x))` for `u32` with the convention `ceil_log2(0) = 0`.
#[inline]
#[must_use]
pub fn ceil_log2_u32(x: u32) -> u32 {
    if x <= 1 {
        0
    } else {
        32 - (x - 1).leading_zeros()
    }
}

/// Midpoint split of an inclusive interval `[i, j]` with `i ≤ j`.
#[inline]
#[must_use]
pub fn children(iv: Interval) -> (Interval, Interval) {
    assert!(iv.i <= iv.j, "invalid interval");
    let m = (iv.i + iv.j) / 2;
    (Interval::new(iv.i, m), Interval::new(m + 1, iv.j))
}

/// Depth bound of a balanced recursion over `t_leaves`.
#[inline]
#[must_use]
pub fn depth_bound(t_leaves: u32) -> u32 {
    ceil_log2_u32(t_leaves.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_bound_ok() {
        assert_eq!(depth_bound(0), 0);
        assert_eq!(depth_bound(1), 0);
        assert_eq!(depth_bound(2), 1);
        assert_eq!(depth_bound(3), 2);
        assert_eq!(depth_bound(4), 2);
        assert_eq!(depth_bound(5), 3);
    }

    #[test]
    fn children_ok() {
        let (l, r) = children(Interval::new(1, 8));
        assert_eq!(l, Interval::new(1, 4));
        assert_eq!(r, Interval::new(5, 8));
    }
}
