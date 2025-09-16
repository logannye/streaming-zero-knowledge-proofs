//! Public API traits and small types for the folding/accumulation line.
//!
//! These interfaces are intentionally tiny and stable so backends (leaf/fold/wrap
//! gadgets) can evolve internally without churn for callers.

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

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Domain separator used when binding **leaf** proofs to the transcript.
pub const DS_LEAF: &str = "fold/leaf";
/// Domain separator used when binding **fold/merge** proofs to the transcript.
pub const DS_FOLD: &str = "fold/merge";
/// Domain separator used when binding **wrap** attestations to the transcript.
pub const DS_WRAP: &str = "fold/wrap";

/// Compact commitment for a leaf/subtree in the fold tree.
///
/// `root` is an opaque digest (e.g., Merkle), and `len` is the number of leaves
/// spanned by this subtree. Callers should not assume a particular hash scheme.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// Merkle-style digest or opaque hash of the subtree.
    pub root: [u8; 32],
    /// Number of leaves spanned by the subtree.
    pub len: u32,
}

impl Commitment {
    /// Construct a new commitment with its digest and span length.
    #[inline]
    #[must_use]
    pub fn new(root: [u8; 32], len: u32) -> Self {
        Self { root, len }
    }
}

/// Commitment to a public projection `π` (opaque on the wire).
///
/// This hides the internal shape of `π` in streamed artifacts; verifiers
/// check gadget proofs against this commitment instead of raw `π`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiCommitment(pub [u8; 32]);

/// Commit to a projection `π` with a stable, versioned hash.
///
/// We avoid serialization-dependent commits by hashing the canonical field
/// encodings of `π` parts in a fixed order. This must stay **wire-stable**.
#[inline]
#[must_use]
pub fn commit_pi(pi: &crate::are::Pi) -> PiCommitment {
    let mut h = Hasher::new();
    // Versioned DS so future upgrades can co-exist.
    h.update(b"sezkp-fold/pi-commitment/v1");
    h.update(&pi.ctrl_in.to_le_bytes());
    h.update(&pi.ctrl_out.to_le_bytes());
    h.update(&pi.flags.to_le_bytes());
    for a in &pi.acc {
        h.update(&a.to_le_bytes());
    }
    PiCommitment(*h.finalize().as_bytes())
}

/// Operating modes for the fold driver.
///
/// `Balanced` keeps a small set of boundary tokens to avoid recomputation.  
/// `MinRam` trades recomputation for sublinear memory at runtime.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FoldMode {
    /// Keep O(T) tiny tokens (endpoints) to avoid recomputation.
    Balanced,
    /// Recompute endpoints on demand to minimize memory (O(log T) live).
    MinRam,
}

impl Default for FoldMode {
    #[inline]
    fn default() -> Self {
        Self::Balanced
    }
}

/// Driver options for the folding pipeline.
///
/// These are hints to the driver; gadgets themselves are agnostic.
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
    #[inline]
    fn default() -> Self {
        Self {
            fold_mode: FoldMode::Balanced,
            wrap_cadence: 0,
            endpoint_cache: 64, // sensible small default
        }
    }
}

/// Leaf gadget: prove/verify a single block and produce its `(π, C)`.
///
/// Implementors should bind their transcript to [`DS_LEAF`].
///
/// Note: the streaming layer **does not** expose `π` on the wire; it exposes
/// a [`PiCommitment`] produced from the returned `π` via [`commit_pi`].
pub trait Leaf {
    /// Serialized proof object for the leaf gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Prove a single leaf block, returning `(π, C, proof)`.
    fn prove_leaf(block: &sezkp_core::BlockSummary) -> (crate::are::Pi, Commitment, Self::Proof);

    /// Verify a single leaf proof against the commitment and **π commitment**.
    ///
    /// Returns `true` on success; `false` on failure.
    fn verify_leaf(commit: &Commitment, pi_cmt: &PiCommitment, proof: &Self::Proof) -> bool;
}

/// Fold gadget: merge two siblings into their parent with an interface check.
///
/// Implementors should bind their transcript to [`DS_FOLD`].
///
/// Note: the driver passes `π` **internally** for interface checks but will
/// only **emit** [`PiCommitment`]s on the streamed wire format.
pub trait Fold {
    /// Serialized proof object for the fold gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Fold `(left, right)` into a parent `(C, π)`, using an interface witness.
    fn fold(
        left: (&Commitment, &crate::are::Pi),
        right: (&Commitment, &crate::are::Pi),
        iface: &crate::are::InterfaceWitness,
    ) -> (Commitment, crate::are::Pi, Self::Proof);

    /// Verify a parent `(C, π_commitment)` against its two children and the fold proof.
    ///
    /// Returns `true` on success; `false` on failure.
    fn verify_fold(
        parent: (&Commitment, &PiCommitment),
        left: (&Commitment, &PiCommitment),
        right: (&Commitment, &PiCommitment),
        proof: &Self::Proof,
    ) -> bool;
}

/// Optional wrapper gadget: periodically attest to the current root `(C, π)`.
///
/// Implementors should bind their transcript to [`DS_WRAP`].
pub trait Wrap {
    /// Serialized proof object for the wrap gadget.
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// Produce a wrap proof for the current root `(C, π)`.
    fn wrap(root: (&Commitment, &crate::are::Pi)) -> Self::Proof;

    /// Verify a wrap proof for the given root `(C, π_commitment)`.
    ///
    /// Returns `true` on success; `false` on failure.
    fn verify_wrap(root: (&Commitment, &PiCommitment), proof: &Self::Proof) -> bool;
}
