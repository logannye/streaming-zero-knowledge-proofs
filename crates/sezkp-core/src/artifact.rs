//! Proof artifact types shared across backends and frontends (CLI/FFI/Python).
//!
//! These types define a stable, serialized boundary between proving backends
//! and callers. [`ProofArtifact`] is intentionally minimal: it pins the backend
//! identity, the committed `manifest_root`, backend-opaque `proof_bytes`, and a
//! free-form `meta` JSON value for lightweight diagnostics.
//!
//! Serialization is via `serde`; we keep the representation conservative
//! (e.g., raw bytes for CBOR friendliness).
//!
//! ## Backward/forward compatibility
//! - Do **not** add `#[serde(deny_unknown_fields)]` so newer producers with
//!   extra fields remain readable by older consumers.
//! - Enum variants may evolve; unknown variants map to [`BackendKind::Unknown`].
//! - Prefer adding new **optional** fields with `#[serde(default)]` rather than
//!   changing existing field types.
//!
//! ## When to use `meta`
//! `meta` is intended for human/ops diagnostics (timings, parameter echoes,
//! cache stats). Avoid parsing it in critical paths—if a value matters at
//! runtime, promote it into a stable, typed field.

use serde::{Deserialize, Serialize};

/// Which backend generated the proof.
///
/// Marked `#[non_exhaustive]` to allow adding future variants without
/// forcing downstream exhaustive matches at compile time. At *runtime*,
/// unknown serialized variants decode as [`BackendKind::Unknown`] to preserve
/// forward compatibility across crate versions.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// STARK-based backend (interactive oracle proof style).
    Stark,
    /// Folding/aggregation-based backend.
    Fold,
    /// Catch-all for newer/unknown backends when deserializing.
    #[serde(other)]
    Unknown,
}

/// Serialized proof produced by a backend.
///
/// The `proof_bytes` field is backend-defined; callers should treat it as an
/// opaque blob. The `meta` field is free-form JSON intended for diagnostics or
/// light telemetry (e.g., timing, parameter choices). **Avoid** parsing `meta`
/// in critical paths; instead, expose stable fields if you need them.
///
/// **Invariants**
/// - `manifest_root` must match the root used during proving.
/// - `backend` must reflect the backend that produced `proof_bytes`; verifiers
///   must reject mismatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifact {
    /// Backend that produced the proof.
    pub backend: BackendKind,
    /// Commitment root the proof is tied to (e.g., Merkle root).
    pub manifest_root: [u8; 32],
    /// Opaque, backend-specific encoding of the proof.
    pub proof_bytes: Vec<u8>,
    /// Free-form metadata for debugging/observability.
    ///
    /// Not required; omitted values deserialize as `Null`.
    #[serde(default)]
    pub meta: serde_json::Value,
}

impl ProofArtifact {
    /// Construct a new [`ProofArtifact`].
    #[inline]
    #[must_use]
    pub fn new(
        backend: BackendKind,
        manifest_root: [u8; 32],
        proof_bytes: Vec<u8>,
        meta: serde_json::Value,
    ) -> Self {
        Self {
            backend,
            manifest_root,
            proof_bytes,
            meta,
        }
    }

    /// Returns the proof bytes.
    #[inline]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    /// Consumes the artifact, returning the owned proof bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.proof_bytes
    }

    /// Length of the proof bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Whether the proof byte vector is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proof_bytes.is_empty()
    }

    /// Returns the backend kind.
    #[inline]
    #[must_use]
    pub fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Returns the manifest root this artifact is bound to.
    #[inline]
    #[must_use]
    pub fn manifest_root(&self) -> &[u8; 32] {
        &self.manifest_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serde_roundtrip_json() {
        let artifact = ProofArtifact::new(
            BackendKind::Stark,
            [0u8; 32],
            vec![1, 2, 3, 4],
            json!({"k": "v", "n": 1}),
        );

        let ser = serde_json::to_vec(&artifact).expect("serialize");
        let de: ProofArtifact = serde_json::from_slice(&ser).expect("deserialize");

        assert_eq!(de.backend, artifact.backend);
        assert_eq!(de.manifest_root, artifact.manifest_root);
        assert_eq!(de.bytes(), artifact.bytes());
        // meta is intentionally free-form; ensure at least that keys survived:
        assert!(de.meta.get("k").is_some());
    }

    #[test]
    fn unknown_backend_is_tolerated() {
        // Serialize with a future/unknown backend name by hand.
        #[derive(Serialize)]
        struct Wire<'a> {
            backend: &'a str,
            manifest_root: [u8; 32],
            proof_bytes: &'a [u8],
            #[serde(default)]
            meta: serde_json::Value,
        }

        let w = Wire {
            backend: "supernova", // not in the enum
            manifest_root: [7u8; 32],
            proof_bytes: &[9, 9, 9],
            meta: serde_json::Value::Null,
        };
        let ser = serde_json::to_vec(&w).unwrap();
        let de: ProofArtifact = serde_json::from_slice(&ser).unwrap();

        assert_eq!(de.backend, BackendKind::Unknown);
        assert_eq!(de.manifest_root, [7u8; 32]);
        assert_eq!(de.bytes(), &[9, 9, 9]);
    }
}
