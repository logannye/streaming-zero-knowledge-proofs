// crates/sezkp-scheduler/src/dfs.rs

//! Pointerless DFS scheduler over a balanced recursion tree.

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

use crate::hct::children;
use sezkp_core::Interval;

/// DFS events over the balanced recursion tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Visit leaf `k` (interval `[k, k]`).
    DescendLeaf(u32),
    /// Combine adjacent children `(left, right)` into their parent.
    Combine(Interval, Interval),
    /// All work completed.
    Done,
}

#[derive(Clone, Debug)]
struct Frame {
    /// Interval held by this stack frame.
    iv: Interval,
    /// 0 = not visited, 1 = left done, 2 = right done (emit combine)
    state: u8,
    left: Option<Interval>,
    right: Option<Interval>,
}

/// Pointerless DFS scheduler over `[1, T]`.
#[derive(Clone, Debug)]
pub struct DfsScheduler {
    stack: Vec<Frame>,
    done_emitted: bool,
}

impl DfsScheduler {
    /// Create a new DFS scheduler for `t_leaves` leaves.
    #[must_use]
    pub fn new(t_leaves: u32) -> Self {
        let mut s = Self {
            stack: Vec::new(),
            done_emitted: false,
        };
        if t_leaves >= 1 {
            s.stack.push(Frame {
                iv: Interval::new(1, t_leaves),
                state: 0,
                left: None,
                right: None,
            });
        } else {
            // Empty schedule: immediately emit Done once.
            s.done_emitted = true;
        }
        s
    }
}

impl Iterator for DfsScheduler {
    type Item = Event;

    #[inline]
    fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(top) = self.stack.last_mut() {
                if top.iv.i == top.iv.j {
                    // Leaf
                    let k = top.iv.i;
                    self.stack.pop();
                    return Some(Event::DescendLeaf(k));
                }

                match top.state {
                    0 => {
                        // First visit: compute children, go left.
                        let (l, r) = children(top.iv);
                        top.left = Some(l);
                        top.right = Some(r);
                        top.state = 1;
                        self.stack.push(Frame {
                            iv: l,
                            state: 0,
                            left: None,
                            right: None,
                        });
                        continue;
                    }
                    1 => {
                        // Left done, go right.
                        let r = top.right.expect("right child missing");
                        top.state = 2;
                        self.stack.push(Frame {
                            iv: r,
                            state: 0,
                            left: None,
                            right: None,
                        });
                        continue;
                    }
                    2 => {
                        // Both children done: emit combine for this parent.
                        let l = top.left.expect("left child missing");
                        let r = top.right.expect("right child missing");
                        self.stack.pop();
                        return Some(Event::Combine(l, r));
                    }
                    _ => unreachable!("invalid frame state"),
                }
            } else if self.done_emitted {
                return None;
            } else {
                self.done_emitted = true;
                return Some(Event::Done);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_leaves_and_combines_then_done() {
        let mut ev = DfsScheduler::new(3);
        // Order is DFS-specific; we only assert totals and presence of Done.
        let mut saw_leaf = 0u32;
        let mut saw_combine = 0u32;
        let mut saw_done = false;

        while let Some(e) = ev.next() {
            match e {
                Event::DescendLeaf(_) => saw_leaf += 1,
                Event::Combine(_, _) => saw_combine += 1,
                Event::Done => {
                    saw_done = true;
                    break;
                }
            }
        }
        assert!(saw_done, "must emit Done");
        assert_eq!(saw_leaf, 3);
        assert_eq!(saw_combine, 2);
        assert!(ev.next().is_none(), "iterator should be exhausted");
    }
}
