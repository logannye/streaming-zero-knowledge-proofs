// crates/sezkp-fold/src/verify.rs

//! Verifier for the folding line: check leaf, fold, and wrap proofs.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{ensure, Result};

use crate::api::{Fold as FoldT, Leaf as LeafT, Wrap as WrapT};
use crate::driver::FoldProofBundle;

/// Verify a serialized folding bundle using the given gadgets.
///
/// Order is enforced strictly: Leaves → Folds → Wraps. Each gadget is
/// responsible for reconstructing its transcript and checking its micro-proof.
pub fn verify_bundle<L, F, W>(bundle: &FoldProofBundle<L::Proof, F::Proof, W::Proof>) -> Result<()>
where
    L: LeafT,
    F: FoldT,
    W: WrapT,
{
    // 1) Leaves
    for (c, pi, lp) in &bundle.leaves {
        ensure!(L::verify_leaf(c, pi, lp), "leaf proof failed");
    }

    // 2) Folds (bottom-up)
    for ((c_par, pi_par), (c_l, pi_l), (c_r, pi_r), pf) in &bundle.folds {
        ensure!(
            F::verify_fold((c_par, pi_par), (c_l, pi_l), (c_r, pi_r), pf),
            "fold proof failed"
        );
    }

    // 3) Wraps (if any)
    for ((c, pi), wp) in &bundle.wraps {
        ensure!(W::verify_wrap((c, pi), wp), "wrap proof failed");
    }

    Ok(())
}
