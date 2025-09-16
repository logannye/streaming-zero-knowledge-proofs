//! Minimal crypto substrate: Blake3 transcript with a simple absorb/challenge API.
//!
//! ⚠️ **Security note:** This is a scaffolding layer for experiments/tests. It models a
//! domain-separated random oracle using Blake3 but is **not** a final protocol design.
//! Do not treat this as a hardened transcript construction without a dedicated review.
//!
//! ## Overview
//! - [`Transcript`] is a tiny trait: absorb bytes under a label, squeeze challenges.
//! - [`Blake3Transcript`] is a deterministic, domain-separated implementation built on BLAKE3.
//! - [`Label`] centralizes canonical labels to avoid stringly-typed mistakes.
//! - [`TranscriptExt`] provides ergonomic helpers for `Label` and common patterns.
//!
//! ### Example
//! ```
//! use sezkp_crypto::{Blake3Transcript, Transcript, TranscriptExt, Label};
//!
//! let mut tr = Blake3Transcript::new("my-protocol/v1");
//! tr.absorb_label(Label::Params, b"N=1<<20");
//! tr.absorb_u64("seed/round", 0);
//! let chal = tr.challenge_bytes_label(Label::FriQuery, 32);
//! assert_eq!(chal.len(), 32);
//! ```

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
use std::io::Read;

/// Fixed domain prefix to seed transcripts.
///
/// Included before the user-supplied domain string to reduce the risk of
/// cross-protocol collisions across the workspace.
const TRANSCRIPT_PREFIX: &[u8] = b"sezkp.transcript.v0";

/// Transcript interface used across backends.
///
/// Implementations must apply **domain separation** for both absorbs and challenges.
/// All methods should be deterministic with respect to the transcript state.
pub trait Transcript {
    /// Add raw bytes under a label (domain-separated).
    fn absorb(&mut self, label: &str, bytes: &[u8]);

    /// Convenience: absorb an unsigned 64-bit value (LE).
    fn absorb_u64(&mut self, label: &str, x: u64) {
        self.absorb(label, &x.to_le_bytes());
    }

    /// Convenience: absorb a signed 64-bit value (two's-complement LE).
    fn absorb_i64(&mut self, label: &str, x: i64) {
        self.absorb(label, &x.to_le_bytes());
    }

    /// Squeeze `n` bytes as a challenge under `label`.
    ///
    /// Implementations should be deterministic with respect to the transcript state.
    #[must_use]
    fn challenge_bytes(&mut self, label: &str, n: usize) -> Vec<u8>;
}

/// Blake3-based transcript.
///
/// Deterministic, domain-separated random-oracle model suitable for scaffolding.
/// **Do not** rely on this exact construction for security-critical deployments.
#[derive(Clone, Debug)]
pub struct Blake3Transcript {
    st: Hasher,
}

impl Blake3Transcript {
    /// Create a new transcript with a domain separation prefix.
    #[must_use]
    pub fn new(domain_sep: &str) -> Self {
        let mut st = Hasher::new();
        // Seed with a fixed prefix and the domain string length+bytes.
        st.update(TRANSCRIPT_PREFIX);
        st.update(&(domain_sep.len() as u32).to_le_bytes());
        st.update(domain_sep.as_bytes());
        Self { st }
    }
}

impl Transcript for Blake3Transcript {
    fn absorb(&mut self, label: &str, bytes: &[u8]) {
        // Domain separation for each absorb:
        //   tag "absorb", label length+bytes, payload length+bytes.
        self.st.update(b"absorb");
        self.st.update(&(label.len() as u32).to_le_bytes());
        self.st.update(label.as_bytes());
        self.st.update(&(bytes.len() as u32).to_le_bytes());
        self.st.update(bytes);
    }

    fn challenge_bytes(&mut self, label: &str, n: usize) -> Vec<u8> {
        // Derive an XOF stream from current state + label.
        let mut st = self.st.clone();
        st.update(b"challenge");
        st.update(&(label.len() as u32).to_le_bytes());
        st.update(label.as_bytes());

        let mut rdr = st.finalize_xof();
        let mut out = vec![0u8; n];

        // `OutputReader` implements `Read`. Exact reads should not fail for a BLAKE3 XOF.
        // We keep the panic to preserve the trait's infallible signature.
        rdr.read_exact(&mut out)
            .expect("blake3::OutputReader::read_exact should not fail");

        // Model transcript "forward progress" after a challenge so future challenges differ.
        self.st.update(b"after_challenge");
        self.st.update(&(label.len() as u32).to_le_bytes());
        self.st.update(label.as_bytes());

        out
    }
}

/// Canonical transcript labels used across the SEZKP protocols.
/// Avoids stringly-typed mistakes in domain separation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Label {
    /// Global parameter absorption (N, blowup, rate, etc.).
    Params,
    /// Column-root absorption.
    ColRoot,
    /// Row-opening absorption.
    RowOpen,
    /// FRI root absorption.
    FriRoot,
    /// FRI query absorption.
    FriQuery,
    /// FRI final value.
    FriFinal,
    /// Manifest root absorption.
    Manifest,
}

impl Label {
    /// Borrow the canonical string.
    #[inline]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Params => "sezkp/params",
            Label::ColRoot => "sezkp/col_root",
            Label::RowOpen => "sezkp/row_open",
            Label::FriRoot => "sezkp/fri_root",
            Label::FriQuery => "sezkp/fri_query",
            Label::FriFinal => "sezkp/fri_final",
            Label::Manifest => "sezkp/manifest",
        }
    }
}

/// Ergonomic helpers implemented for all [`Transcript`]s.
///
/// These avoid manual `label.as_str()` calls and provide a couple of handy
/// convenience methods (e.g., `challenge_u64`).
pub trait TranscriptExt: Transcript {
    /// Absorb bytes under a canonical [`Label`].
    fn absorb_label(&mut self, label: Label, bytes: &[u8]) {
        self.absorb(label.as_str(), bytes);
    }

    /// Squeeze `n` bytes as a challenge under a canonical [`Label`].
    #[must_use]
    fn challenge_bytes_label(&mut self, label: Label, n: usize) -> Vec<u8> {
        self.challenge_bytes(label.as_str(), n)
    }

    /// Challenge as a little-endian `u64` under an arbitrary string label.
    #[must_use]
    fn challenge_u64(&mut self, label: &str) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.challenge_bytes(label, 8));
        u64::from_le_bytes(buf)
    }

    /// Challenge as a little-endian `u64` under a canonical [`Label`].
    #[must_use]
    fn challenge_u64_label(&mut self, label: Label) -> u64 {
        self.challenge_u64(label.as_str())
    }
}

impl<T: Transcript + ?Sized> TranscriptExt for T {}

#[cfg(test)]
mod tests {
    use super::{Blake3Transcript, Label, Transcript, TranscriptExt};

    #[test]
    fn determinism_and_label_sep() {
        let mut t1 = Blake3Transcript::new("dom");
        let mut t2 = Blake3Transcript::new("dom");

        t1.absorb("a", b"hello");
        t2.absorb("a", b"hello");

        assert_eq!(t1.challenge_bytes("c", 32), t2.challenge_bytes("c", 32));

        let mut t3 = Blake3Transcript::new("dom");
        t3.absorb("a", b"hello");
        // Different label → different output.
        assert_ne!(t1.challenge_bytes("c", 32), t3.challenge_bytes("d", 32));
    }

    #[test]
    fn domain_separation_changes_output() {
        let mut t1 = Blake3Transcript::new("dom1");
        let mut t2 = Blake3Transcript::new("dom2");
        t1.absorb("x", b"payload");
        t2.absorb("x", b"payload");
        assert_ne!(t1.challenge_bytes("c", 16), t2.challenge_bytes("c", 16));
    }

    #[test]
    fn extension_trait_helpers_work() {
        let mut t = Blake3Transcript::new("dom");
        t.absorb_label(Label::Params, b"N=1<<20");
        let x = t.challenge_u64_label(Label::FriFinal);
        // Make sure it's at least deterministic across identical transcripts:
        let mut t2 = Blake3Transcript::new("dom");
        t2.absorb_label(Label::Params, b"N=1<<20");
        let y = t2.challenge_u64_label(Label::FriFinal);
        assert_eq!(x, y);
    }

    #[test]
    fn state_progression_changes_future_challenges() {
        // After a challenge, the internal hasher is advanced; the next challenge differs.
        let mut t = Blake3Transcript::new("dom");
        t.absorb("x", b"p");
        let c1 = t.challenge_bytes("c", 16);
        let c2 = t.challenge_bytes("c", 16);
        assert_ne!(c1, c2);
    }
}
