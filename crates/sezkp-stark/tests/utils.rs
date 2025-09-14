// crates/sezkp-stark/tests/utils.rs

#![allow(unused_imports)]

// pub fn rss_mib() -> u64 {
//     use sysinfo::{{System, SystemExt, ProcessExt};
//     let mut sys = System::new();
//     sys.refresh_processes();
//     let pid = std::process::id() as i32;
//     if let Some(p) = sys.process(pid) {
//         (p.memory() / 1024) as u64 // KiB -> MiB
//     } else { 0 }
// }

pub fn rss_mib() -> u64 {
    0
}
