//! Public API traits and small types for the folding/accumulation line.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use serde::{Deserialize, Serialize};

/// Domain separator used when binding **leaf** proofs to the transcript.
pub const DS_LEAF: &str = "fold/leaf";
/// Domain separator used when binding **fold/merge** proofs to the transcript.
pub const DS_FOLD: &str = "fold/merge";
/// Domain separator used when binding **wrap** attestations to the transcript.
pub const DS_WRAP: &str = "fold/wrap";

/// Compact commitment for a leaf/subtree in the fold tree.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// Merkle-style digest or opaque hash of the subtree.
    pub root: [u8; 32],
    /// Number of leaves spanned by the subtree.
    pub len: u32,
}

impl Commitment {
    /// Construct a new commitment with its digest and span length.
    #[must_use]
    pub fn new(root: [u8; 32], len: u32) -> Self {
        Self { root, len }
    }
}

/// Operating modes for the fold driver.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FoldMode {
    /// Keep O(T) tiny tokens (endpoints) to avoid recomputation.
    Balanced,
    /// Recompute endpoints on demand to minimize memory (O(log T) live).
    MinRam,
}

impl Default for FoldMode {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Driver options for the folding pipeline.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverOptions {
    /// Whether to keep a small ledger of endpoints or recompute them.
    pub fold_mode: FoldMode,
    /// Emit a wrap proof every `wrap_cadence` internal folds (0 = never).
    pub wrap_cadence: u32,
    /// Endpoint LRU cache capacity (only used in MinRam mode).
    pub endpoint_cache: u32,
}

impl Default for DriverOptions {
    fn default() -> Self {
        Self {
            fold_mode: FoldMode::Balanced,
            wrap_cadence: 0,
            endpoint_cache: 64, // sensible small default
        }
    }
}

/// Leaf gadget: prove/verify a single block and produce its `(π, C)`.
pub trait Leaf {
    /// Serialized proof object for the leaf gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Prove a single leaf block, returning `(π, C, proof)`.
    fn prove_leaf(block: &sezkp_core::BlockSummary) -> (crate::are::Pi, Commitment, Self::Proof);

    /// Verify a single leaf proof against the commitment and projection.
    fn verify_leaf(commit: &Commitment, pi: &crate::are::Pi, proof: &Self::Proof) -> bool;
}

/// Fold gadget: merge two siblings into their parent with an interface check.
pub trait Fold {
    /// Serialized proof object for the fold gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Fold `(left, right)` into a parent `(C, π)`, using an interface witness.
    fn fold(
        left: (&Commitment, &crate::are::Pi),
        right: (&Commitment, &crate::are::Pi),
        iface: &crate::are::InterfaceWitness,
    ) -> (Commitment, crate::are::Pi, Self::Proof);

    /// Verify a parent `(C, π)` against its two children and the fold proof.
    fn verify_fold(
        parent: (&Commitment, &crate::are::Pi),
        left: (&Commitment, &crate::are::Pi),
        right: (&Commitment, &crate::are::Pi),
        proof: &Self::Proof,
    ) -> bool;
}

/// Optional wrapper gadget: periodically attest to the current root `(C, π)`.
pub trait Wrap {
    /// Serialized proof object for the wrap gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Produce a wrap proof for the current root `(C, π)`.
    fn wrap(root: (&Commitment, &crate::are::Pi)) -> Self::Proof;

    /// Verify a wrap proof for the given root `(C, π)`.
    fn verify_wrap(root: (&Commitment, &crate::are::Pi), proof: &Self::Proof) -> bool;
}
