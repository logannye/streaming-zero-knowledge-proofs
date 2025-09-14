// crates/sezkp-ffi/src/lib.rs

//! `sezkp-ffi`: optional C ABI surface (stub by default).
//!
//! By default this crate builds a no-op Rust library so the workspace compiles
//! without requiring any system toolchains. Enable the `cabi` feature to expose
//! a tiny C ABI (currently: a version string), which you can expand later.

#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

#[cfg(feature = "cabi")]
mod cabi {
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::sync::OnceLock;

    // Lazily constructed NUL-terminated version string with 'static lifetime.
    static VERSION_CSTR: OnceLock<CString> = OnceLock::new();

    /// Return a pointer to a static, NUL-terminated version string.
    ///
    /// # Safety
    /// - Returns a valid, immutable pointer for the duration of the program.
    /// - The caller must **not** free this pointer.
    ///
    /// # Example (C)
    /// ```c
    /// const char* v = sezkp_version();
    /// printf("version: %s\n", v);
    /// ```
    #[no_mangle]
    pub extern "C" fn sezkp_version() -> *const c_char {
        let cstr = VERSION_CSTR.get_or_init(|| {
            // Safe: `CARGO_PKG_VERSION` never contains interior NULs.
            CString::new(env!("CARGO_PKG_VERSION")).expect("valid version cstring")
        });
        cstr.as_ptr()
    }
}

#[cfg(feature = "cabi")]
pub use cabi::sezkp_version;

#[cfg(not(feature = "cabi"))]
mod no_cabi {
    /// Placeholder so the crate isn’t empty under the default build.
    #[must_use]
    pub fn _build_ok() -> &'static str {
        "sezkp-ffi (stub build; enable `cabi` feature for C ABI)"
    }
}

#[cfg(not(feature = "cabi"))]
pub use no_cabi::_build_ok as _ffi_stub_ok;
