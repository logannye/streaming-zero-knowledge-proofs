// crates/sezkp-fold/tests/fold_line.rs

#![allow(dead_code)]

use sezkp_fold::api::{DriverOptions, FoldMode};
use sezkp_fold::{driver::run_pipeline, verify};
use sezkp_trace::{generator::generate_trace, partition::partition_trace};

fn bundle_top<Lp, Fp, Wp>(
    b: &sezkp_fold::driver::FoldProofBundle<Lp, Fp, Wp>,
) -> (sezkp_fold::api::Commitment, sezkp_fold::are::Pi) {
    if let Some(((c, p), _, _, _)) = b.folds.last() {
        (*c, *p)
    } else if let Some((c, p, _)) = b.leaves.last() {
        (*c, *p)
    } else {
        (sezkp_fold::api::Commitment::new([0u8; 32], 0), sezkp_fold::are::Pi::default())
    }
}

#[test]
fn fold_line_balanced_vs_minram_top_matches_and_verifies() {
    let sizes = [1u32, 2, 3, 4, 8, 17, 128];

    for &t in &sizes {
        let tr = generate_trace(t as u64, 2);
        // Use ~sqrt(T) blocks to get varied trees
        let b = (f64::sqrt(t as f64).ceil() as u32).max(1);
        let blocks = partition_trace(&tr, b);

        // Balanced
        let opts_bal = DriverOptions {
            fold_mode: FoldMode::Balanced,
            wrap_cadence: 0,
            endpoint_cache: 0,
        };
        let bundle_bal = run_pipeline::<sezkp_fold::leaf::CryptoLeaf, sezkp_fold::fold::CryptoFold, sezkp_fold::fold::CryptoWrap>(&blocks, &opts_bal);
        verify::verify_bundle::<sezkp_fold::leaf::CryptoLeaf, sezkp_fold::fold::CryptoFold, sezkp_fold::fold::CryptoWrap>(&bundle_bal).expect("balanced verify");

        // Min-RAM with a few cache sizes
        for &cap in &[1u32, 2, 8, 64] {
            let opts_min = DriverOptions {
                fold_mode: FoldMode::MinRam,
                wrap_cadence: 0,
                endpoint_cache: cap,
            };
            let bundle_min = run_pipeline::<sezkp_fold::leaf::CryptoLeaf, sezkp_fold::fold::CryptoFold, sezkp_fold::fold::CryptoWrap>(&blocks, &opts_min);
            verify::verify_bundle::<sezkp_fold::leaf::CryptoLeaf, sezkp_fold::fold::CryptoFold, sezkp_fold::fold::CryptoWrap>(&bundle_min).expect("minram verify");

            let (c_bal, pi_bal) = bundle_top(&bundle_bal);
            let (c_min, pi_min) = bundle_top(&bundle_min);
            assert_eq!(c_bal, c_min, "final commitment mismatch for T={}", t);
            assert_eq!(pi_bal, pi_min, "final π mismatch for T={}", t);
        }
    }
}
