//! Small (de)serialization helpers for artifacts and payloads.
//!
//! Defaults to **bincode** helpers; optional CBOR helpers are enabled with
//! the `cbor` cargo feature.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;

/* ------------------------------- bincode ---------------------------------- */

/// Serialize to a compact binary vector using `bincode`.
#[inline]
pub fn to_vec_bin<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}

/// Deserialize from a `bincode` slice.
#[inline]
pub fn from_slice_bin<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(bincode::deserialize(bytes)?)
}

/* --------------------------------- CBOR ----------------------------------- */

#[cfg(feature = "cbor")]
/// Serialize to CBOR using the `serde_cbor` crate.
#[inline]
pub fn to_vec_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_cbor::to_vec(value)?)
}

#[cfg(feature = "cbor")]
/// Deserialize from CBOR using the `serde_cbor` crate.
#[inline]
pub fn from_slice_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_cbor::from_slice(bytes)?)
}

#[cfg(not(feature = "cbor"))]
/// Fallback CBOR serialization when the `cbor` feature is disabled (uses bincode).
#[inline]
pub fn to_vec_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    to_vec_bin(value)
}

#[cfg(not(feature = "cbor"))]
/// Fallback CBOR deserialization when the `cbor` feature is disabled (uses bincode).
#[inline]
pub fn from_slice_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    from_slice_bin(bytes)
}
