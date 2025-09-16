//! `sezkp-py`: optional Python bindings (stub by default).
//!
//! ## What this crate does
//! - Builds as a normal Rust library by default (no Python toolchain needed).
//! - With the `python` feature enabled, compiles a minimal CPython extension
//!   module exposing `version()` using PyO3 (stable abi3 for Python ≥ 3.8).
//!
//! ## Building the extension (locally)
//! ```bash
//! # Default: Rust-only library
//! cargo build -p sezkp-py
//!
//! # CPython extension (requires Python toolchain + PyO3 prerequisites)
//! cargo build -p sezkp-py --features python --release
//! ```
//!
//! For packaging wheels, consider `maturin`:
//! ```bash
//! maturin develop -m crates/sezkp-py/Cargo.toml --features python
//! ```
//!
//! ## Module name
//! The compiled extension exposes a Python module named `sezkp_py`.

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

#[cfg(feature = "python")]
mod py {
    use pyo3::prelude::*;

    /// Return the crate version as a Python string.
    ///
    /// ### Python usage (after building the extension)
    /// ```python
    /// import sezkp_py
    /// print(sezkp_py.version())  # e.g. "0.1.0"
    /// ```
    #[pyfunction]
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Python module `sezkp_py`.
    ///
    /// This name determines the `import` path from Python.
    #[pymodule]
    fn sezkp_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(version, m)?)?;
        Ok(())
    }
}

#[cfg(not(feature = "python"))]
mod no_py {
    /// Placeholder so the crate isn’t empty under the default build.
    #[must_use]
    pub fn _build_ok() -> &'static str {
        "sezkp-py (stub build; enable `python` feature for CPython module)"
    }
}

#[cfg(not(feature = "python"))]
pub use no_py::_build_ok as _py_stub_ok;
