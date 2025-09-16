//! `sezkp-node`: optional Node.js (N-API) bindings.
//!
//! ## What this crate does
//! - By default, this compiles as a normal Rust library so the workspace builds
//!   without Node toolchains.
//! - When the `node` feature is enabled, we compile a minimal N-API addon that
//!   exposes `version()` to JavaScript.
//!
//! ## Building the addon (locally)
//! ```bash
//! # Default: Rust-only library (no Node toolchain required)
//! cargo build -p sezkp-node
//!
//! # N-API addon (requires Node toolchain / napi-rs prerequisites)
//! cargo build -p sezkp-node --features node --release
//! ```
//!
//! ## Publishing / packaging
//! For a production addon, switch `crate-type` to include `"cdylib"` in
//! `Cargo.toml` (see inline comment there), and publish via your preferred
//! Node packaging flow.

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
    ///
    /// ### JS usage (after building addon)
    /// ```js
    /// const { version } = require('./path-to-built-addon.node');
    /// console.log(version()); // e.g. "0.1.0"
    /// ```
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
    ///
    /// Kept to ensure the crate contributes to the workspace even without the
    /// Node feature (and makes `cargo check`/`build` happy everywhere).
    #[must_use]
    pub fn _build_ok() -> &'static str {
        "sezkp-node (stub build; enable `node` feature for N-API addon)"
    }
}

#[cfg(not(feature = "node"))]
pub use no_node::_build_ok as _node_stub_ok;
