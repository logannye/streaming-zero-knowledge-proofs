#![no_main]
use ciborium::de::from_reader;
use libfuzzer_sys::fuzz_target;
use sezkp_core::BlockSummary;

fuzz_target!(|data: &[u8]| {
    let _ = from_reader::<BlockSummary, _>(data);
});
