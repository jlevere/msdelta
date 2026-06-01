//! Offline tests for the pure shrink-candidate logic. The lab loop itself is
//! validated by running `oracle minimize` against a real failing case.

use oracle::msdelta::minimize::{ours_from_spec, shrink_candidates};
use oracle::msdelta::CreateSpec;

#[test]
fn shrink_candidates_are_smaller_and_distinct() {
    let target: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let cands = shrink_candidates(&target);
    assert!(!cands.is_empty());
    // Every candidate is strictly smaller and above the floor.
    assert!(cands
        .iter()
        .all(|c| c.target.len() < target.len() && c.target.len() >= 8));
    // Distinct lengths (deduped).
    let mut lens: Vec<usize> = cands.iter().map(|c| c.target.len()).collect();
    let before = lens.len();
    lens.sort_unstable();
    lens.dedup();
    assert_eq!(lens.len(), before, "candidate lengths should be distinct");
}

#[test]
fn tiny_targets_yield_no_candidates() {
    assert!(shrink_candidates(b"1234").is_empty());
    assert!(shrink_candidates(&[]).is_empty());
}

#[test]
fn ours_from_spec_maps_raw_exe_and_codecs() {
    // Raw spec -> raw file type, default codec.
    let raw = ours_from_spec(&CreateSpec::raw());
    let _ = raw; // smoke: constructs without panic
                 // bsdiff flag -> bsdiff codec; executables -> auto file type. We can only
                 // assert construction succeeds (CreateOptions fields are private), so this
                 // guards against panics / bad flag handling.
    let bsdiff = CreateSpec::raw().with_set_flags(0x100);
    let _ = ours_from_spec(&bsdiff);
    let _ = ours_from_spec(&CreateSpec::executables());
}
