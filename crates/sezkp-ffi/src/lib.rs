//! `sezkp-ffi`: optional C ABI surface (stub by default).
//!
//! By default this crate builds a no-op Rust library so the workspace compiles
//! without requiring any system toolchains. Enable the `cabi` feature to expose
//! a tiny C ABI you can expand over time.
//!
//! ## What’s exported with `--features cabi`
//! - `sezkp_abi_version() -> uint32_t`: a stable ABI contract version (not the crate version).
//! - `sezkp_version() -> const char*`: a NUL-terminated UTF-8 semver string for this crate.
//!
//! ```bash
//! cargo build -p sezkp-ffi --features cabi
//! # to produce a shared library (Linux/macOS):
//! # add "cdylib" to [lib].crate-type in Cargo.toml before distributing to C callers.
//! ```
//!
//! ### Minimal C usage
//! ```c
//! #include <stdint.h>
//! #include <stdio.h>
//!
//! uint32_t sezkp_abi_version(void);
//! const char* sezkp_version(void);
//!
//! int main(void) {
//!   printf("SEZKP FFI ABI v%u, crate v%s\n",
//!          sezkp_abi_version(), sezkp_version());
//!   return 0;
//! }
//! ```
//!
//! ### Versioning policy
//! - `sezkp_abi_version()` changes only on **ABI** breaking changes.
//! - The Rust crate/package version may change independently (features, fixes, etc.).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown
)]

#[cfg(feature = "cabi")]
mod cabi {
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::sync::OnceLock;

    /// Stable ABI contract version (bump on breaking C ABI changes).
    pub const SEZKP_FFI_ABI_VERSION: u32 = 1;

    // Lazily constructed NUL-terminated version string with 'static lifetime.
    static VERSION_CSTR: OnceLock<CString> = OnceLock::new();

    /// Return a stable ABI contract version.
    ///
    /// This is **not** the crate semver; it only changes when the C ABI changes
    /// in a backward-incompatible way.
    #[no_mangle]
    pub extern "C" fn sezkp_abi_version() -> u32 {
        SEZKP_FFI_ABI_VERSION
    }

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
pub use cabi::{sezkp_abi_version, sezkp_version};

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

#[cfg(test)]
mod tests {
    #[cfg(feature = "cabi")]
    #[test]
    fn abi_and_version_present() {
        // Smoke tests that symbols exist and return plausible values.
        let abi = super::sezkp_abi_version();
        assert!(abi >= 1);
        let v = unsafe {
            // Safe: sezkp_version guarantees a static, non-null, valid C string pointer.
            std::ffi::CStr::from_ptr(super::sezkp_version())
        };
        assert!(!v.to_bytes().is_empty());
    }

    #[cfg(not(feature = "cabi"))]
    #[test]
    fn stub_build_has_placeholder() {
        assert!(super::_ffi_stub_ok().contains("stub build"));
    }
}
