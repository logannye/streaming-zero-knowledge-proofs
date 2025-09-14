// crates/sezkp-py/src/lib.rs

//! `sezkp-py`: optional Python bindings (stub by default).
//!
//! This crate builds as a plain Rust lib by default. Enable the `python` feature
//! to compile a minimal CPython extension module exposing `version()`.

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
    #[pyfunction]
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Python module `sezkp_py`.
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

// Public re-exports (nice-to-have for feature consumers/stubs).
#[cfg(not(feature = "python"))]
pub use no_py::_build_ok as _py_stub_ok;
