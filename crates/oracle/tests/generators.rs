//! Generator tests: determinism, category coverage, and that lowering the full
//! suite through our encoder never fails (a lowering failure is itself a
//! finding, so this guards against regressions in the encoder too).

use std::collections::BTreeSet;

use oracle::kernel::{Domain, Generator};
use oracle::msdelta::generators::{
    default_suite, FuzzDerivedGen, ManifestPairGen, PePairGen, RandomGen, TextGen,
};
use oracle::msdelta::MsDeltaDomain;

#[test]
fn generation_is_deterministic() {
    let a = default_suite(0xABCDEF, 5);
    let b = default_suite(0xABCDEF, 5);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x.id, y.id);
        assert_eq!(x.reference, y.reference);
        assert_eq!(x.target, y.target);
    }
}

#[test]
fn different_seeds_diverge() {
    let a = RandomGen.generate(1, 8);
    let b = RandomGen.generate(2, 8);
    // Overwhelmingly likely to differ; assert at least one pair does.
    assert!(a.iter().zip(&b).any(|(x, y)| x.reference != y.reference));
}

#[test]
fn procedural_generators_honor_count() {
    assert_eq!(RandomGen.generate(7, 12).len(), 12);
    assert_eq!(TextGen.generate(7, 9).len(), 9);
    assert_eq!(FuzzDerivedGen.generate(7, 6).len(), 6);
}

#[test]
fn fixture_generators_present_in_dev_checkout() {
    // These rely on tests/fixtures/, which exist in a git checkout. If they
    // are missing we skip rather than fail (published-crate tree).
    let manifests = ManifestPairGen.generate(0, 16);
    let pes = PePairGen.generate(0, 16);
    if !manifests.is_empty() {
        assert!(manifests.iter().all(|c| c.category == "manifest_pair"));
        assert!(manifests.iter().all(|c| !c.target.is_empty()));
    }
    if !pes.is_empty() {
        assert!(pes.iter().all(|c| c.category == "pe_pair"));
    }
}

#[test]
fn ids_are_unique_across_suite() {
    let suite = default_suite(42, 4);
    let ids: BTreeSet<&str> = suite.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), suite.len(), "duplicate case ids in suite");
}

#[test]
fn fast_subset_lowers_without_encoder_failure() {
    // Lowering runs our encoder on every case; if any case crashes or errors
    // the encoder, build_job propagates it. This is the strongest local guard.
    //
    // PE cases are deliberately EXCLUDED here. Our PE/LZX match-finder is
    // ~O(n^2) and a debug build (overflow checks, no inlining) amplifies it
    // ~2700x: a single 340 KB cmd self-patch takes minutes in debug yet
    // <200 ms in release. PE encoding is covered by the release-mode
    // orchestrator and the msdelta crate's own tests; the debug unit test
    // stays on the fast procedural + manifest cases.
    let dir = tempfile::tempdir().unwrap();
    let mut suite = Vec::new();
    suite.extend(RandomGen.generate(0x1234, 4));
    suite.extend(TextGen.generate(0x1234, 4));
    suite.extend(FuzzDerivedGen.generate(0x1234, 4));
    // count=6 deliberately excludes the wow64 manifest (index 6), which
    // decodes to 3.26 MB of repetitive XML. Encoding that as raw is O(n^2) in
    // our match-finder (it greedily takes the longest match, and when that
    // match's offset is too large to encode it falls back to a single literal
    // instead of a shorter encodable match -- so it re-extends the same match
    // every byte). That is a real encoder finding for phase 4/optimal-parse,
    // not something to pay in the debug inner loop. The big case runs in the
    // release orchestrator.
    suite.extend(ManifestPairGen.generate(0x1234, 6));
    assert!(!suite.is_empty());

    let job = MsDeltaDomain
        .build_job(0x1234, &suite, dir.path())
        .expect("every generated case must lower (self-encode) cleanly");
    assert_eq!(job.cases.len(), suite.len());
}

#[test]
fn default_suite_is_nonempty_and_well_formed() {
    // Cheap structural check on the full suite without lowering (no encoding).
    let suite = default_suite(99, 2);
    assert!(suite.len() >= 12, "suite unexpectedly small: {}", suite.len());
    assert!(suite.iter().all(|c| !c.id.is_empty() && !c.reference.is_empty()));
}
