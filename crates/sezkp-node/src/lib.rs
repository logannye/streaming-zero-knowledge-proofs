// crates/sezkp-node/src/lib.rs

//! `sezkp-node`: optional Node.js (N-API) bindings.
//!
//! By default this compiles as a plain Rust library so the workspace builds
//! without Node toolchains. Enable the `node` feature to build an N-API addon
//! exposing `version()`.

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

#[cfg(feature = "node")]
mod node_api {
    use napi::bindgen_prelude::*;
    use napi_derive::napi;

    /// Return the crate version as a JavaScript string.
    #[napi]
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

#[cfg(feature = "node")]
pub use node_api::version;

#[cfg(not(feature = "node"))]
mod no_node {
    /// Placeholder so the crate isn’t empty under the default build.
    #[must_use]
    pub fn _build_ok() -> &'static str {
        "sezkp-node (stub build; enable `node` feature for N-API addon)"
    }
}

#[cfg(not(feature = "node"))]
pub use no_node::_build_ok as _node_stub_ok;
