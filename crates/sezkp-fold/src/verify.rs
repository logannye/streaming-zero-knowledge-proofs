//! Verifier for the folding line: check leaf, fold, and wrap proofs.
//!
//! Supports two formats:
//! - **In-memory bundle:** a single serialized object with all leaves/folds/wraps.
//! - **Streaming (CBOR-seq):** `Header, Item*, Footer` where each element is a
//!   single CBOR value; verification proceeds incrementally with O(1) memory.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use anyhow::{anyhow, ensure, Context, Result};
use serde::de::DeserializeOwned;
use std::io::Read;

use crate::api::{commit_pi, Fold as FoldT, Leaf as LeafT, PiCommitment, Wrap as WrapT};
use crate::driver::{FoldProofBundle, StreamFooter, StreamHeader, StreamItem};

/// Verify an in-memory folding bundle using the given gadgets.
///
/// The order is enforced strictly (Leaves → Folds → Wraps).
/// Each gadget reconstructs its transcript and checks its micro-proof.
pub fn verify_bundle<L, F, W>(bundle: &FoldProofBundle<L::Proof, F::Proof, W::Proof>) -> Result<()>
where
    L: LeafT,
    F: FoldT,
    W: WrapT,
{
    // 1) Leaves
    for (c, pi, lp) in &bundle.leaves {
        let pi_cmt = commit_pi(pi);
        ensure!(L::verify_leaf(c, &pi_cmt, lp), "leaf proof failed");
    }

    // 2) Folds (bottom-up)
    for ((c_par, pi_par), (c_l, pi_l), (c_r, pi_r), pf) in &bundle.folds {
        let parent = (c_par, commit_pi(pi_par));
        let left = (c_l, commit_pi(pi_l));
        let right = (c_r, commit_pi(pi_r));
        ensure!(
            F::verify_fold((&parent.0, &parent.1), (&left.0, &left.1), (&right.0, &right.1), pf),
            "fold proof failed"
        );
    }

    // 3) Wraps (if any)
    for ((c, pi), wp) in &bundle.wraps {
        let pi_cmt = commit_pi(pi);
        ensure!(W::verify_wrap((c, &pi_cmt), wp), "wrap proof failed");
    }

    Ok(())
}

/// Streaming verifier: read CBOR sequence `{Header, Item*, Footer}`
/// and verify each record incrementally (O(1) extra space).
///
/// We consume one generic `ciborium::value::Value` at a time using
/// `ciborium::de::from_reader`, then convert it into either `StreamFooter`
/// or `StreamItem<…>` via `Value::deserialized::<T>()`. This avoids a dedicated
/// streaming-deserializer type and never rewinds.
pub fn verify_stream<L, F, W, R>(mut reader: R) -> Result<()>
where
    L: LeafT,
    F: FoldT,
    W: WrapT,
    L::Proof: DeserializeOwned,
    F::Proof: DeserializeOwned,
    W::Proof: DeserializeOwned,
    R: Read,
{
    use ciborium::{de, value::Value};

    // 1) Header
    let header: StreamHeader = de::from_reader(&mut reader).context("decoding stream header")?;
    ensure!(
        header.magic == "sezkp-fold-seq" && header.ver == 1,
        "unsupported stream format"
    );

    // 2) Items until we reach a footer.
    let mut n_leaves: u64 = 0;
    let mut final_root: Option<(crate::api::Commitment, PiCommitment)> = None;

    loop {
        // Pull the next raw CBOR value (either Item or Footer).
        let v: Value = de::from_reader(&mut reader)
            .map_err(|e| anyhow!("reading next CBOR value in fold stream: {e}"))?;

        // Try Footer first.
        if let Ok(footer) = v.deserialized::<StreamFooter>() {
            ensure!(
                footer.n_blocks == n_leaves,
                "footer.n_blocks ({}) != counted leaves ({})",
                footer.n_blocks,
                n_leaves
            );
            if let Some((c, pi_cmt)) = final_root {
                ensure!(
                    c == footer.root_c && pi_cmt == footer.root_pi_cmt,
                    "footer root does not match last root seen"
                );
            }
            break; // footer terminates the stream
        }

        // Otherwise, it must be an item.
        let item: StreamItem<L::Proof, F::Proof, W::Proof> = v
            .deserialized()
            .map_err(|e| anyhow!("decoding stream item: {e}"))?;

        match item {
            StreamItem::Leaf { c, pi_cmt, proof } => {
                ensure!(L::verify_leaf(&c, &pi_cmt, &proof), "leaf proof failed");
                n_leaves = n_leaves.saturating_add(1);
            }
            StreamItem::Fold {
                parent,
                left,
                right,
                proof,
            } => {
                ensure!(
                    F::verify_fold((&parent.0, &parent.1), (&left.0, &left.1), (&right.0, &right.1), &proof),
                    "fold proof failed"
                );
                final_root = Some(parent);
            }
            StreamItem::Wrap { root, proof } => {
                ensure!(W::verify_wrap((&root.0, &root.1), &proof), "wrap proof failed");
                final_root = Some(root);
            }
        }
    }

    Ok(())
}
