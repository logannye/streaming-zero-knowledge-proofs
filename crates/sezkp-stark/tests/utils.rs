//! Test utilities (intentionally tiny).
//!
//! We keep memory-introspection out by default to ensure this crate builds
//! everywhere (including Windows and minimal CI containers). If you want to
//! inspect RSS locally, uncomment the snippet below and add `sysinfo` as a
//! dev-dependency (already included in Cargo.toml).

#![allow(unused_imports)]

/*
// Example implementation using `sysinfo` (Linux/macOS/Windows):
// Uncomment if you want real RSS readings in local experiments.
//
// use sysinfo::{ProcessExt, System, SystemExt};
//
// pub fn rss_mib() -> u64 {
//     let mut sys = System::new();
//     sys.refresh_processes();
//     let pid = std::process::id() as i32;
//     if let Some(p) = sys.process(pid) {
//         (p.memory() / 1024) as u64 // KiB -> MiB
//     } else {
//         0
//     }
// }
*/

/// No-op stub used by tests that want to log memory in CI without failing.
pub fn rss_mib() -> u64 {
    0
}
