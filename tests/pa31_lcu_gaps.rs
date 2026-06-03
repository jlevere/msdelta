//! PA31 regression corpus: the FULL set of baseless PA31 deltas from a real
//! Win11 24H2 LCU (KB5089549) express PSF -- 377 deltas, not just the hard
//! ones. See `PA31-LCU-GAPS.md`.
//!
//! Why the full population: an earlier corpus held only the 16 known failures.
//! A fix can pass all 16 yet silently regress deltas that previously worked --
//! exactly what happened (a fix took the population from 361/377 to 193/377
//! while the 16-blob corpus stayed green). This harness applies every delta so
//! such regressions are caught.
//!
//! The blobs are non-redistributable Microsoft payload, so they live in
//! `notes/pa31-lcu-gaps/` (git-ignored); this test SKIPS when absent.
//! Regenerate with the `msu` crate (dumps all 377 with `--all`):
//!
//!   cargo run --release -- gaps <KB5089549.msu> --all \
//!     -o <msdelta>/notes/pa31-lcu-gaps
//!
//! Each delta carries its own embedded target SHA256, so `pa30::apply`
//! returning `Ok` already means bit-exact reconstruction (it errors on the
//! embedded-hash mismatch); this test needs no external hashing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pa31-lcu-gaps")
}

/// blob filename -> target file name, parsed leniently from manifest.tsv
/// (column order independent: the blob is the `*.bin` token, name is last).
fn names(dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(dir.join("manifest.tsv")) {
        for line in text.lines().skip(1).filter(|l| !l.is_empty()) {
            let cols: Vec<&str> = line.split('\t').collect();
            if let Some(blob) = cols.iter().find(|c| c.ends_with(".bin")) {
                map.insert(blob.to_string(), cols.last().unwrap_or(&"").to_string());
            }
        }
    }
    map
}

#[test]
fn pa31_lcu_gap_corpus() {
    let dir = corpus();
    if !dir.exists() {
        eprintln!("pa31-lcu-gaps corpus absent ({dir:?}); skipping (see PA31-LCU-GAPS.md)");
        return;
    }

    let names = names(&dir);
    let mut blobs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    blobs.sort();
    if blobs.is_empty() {
        eprintln!("no delta blobs in {dir:?}; skipping");
        return;
    }

    let (mut total, mut reconstruct) = (0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    for blob in &blobs {
        let bytes = std::fs::read(blob).expect("read delta blob");
        assert_eq!(&bytes[..4], b"PA31", "{blob:?} is not PA31");
        total += 1;
        let fname = blob.file_name().unwrap().to_string_lossy().into_owned();
        // Null base: these are baseless (no <Basis> in the CIX).
        match msdelta::pa30::apply(&[], &bytes) {
            Ok(_) => reconstruct += 1,
            Err(e) => failures.push(format!(
                "  FAIL {fname} [{}B] {} :: {e}",
                bytes.len(),
                names.get(&fname).map(String::as_str).unwrap_or("")
            )),
        }
    }

    eprintln!("\nPA31 LCU corpus: {reconstruct}/{total} reconstruct (null base)");
    for f in failures.iter().take(40) {
        eprintln!("{f}");
    }
    if failures.len() > 40 {
        eprintln!("  ... and {} more", failures.len() - 40);
    }

    // Gate. Full population reconstructs bit-exactly: the LZMS rebuild-order +
    // dispatch fixes plus the header-flag-gated x86 0xE8 transform. FLOOR is the
    // no-regression line; any drop below it means a fix broke previously-working
    // deltas (this corpus is the population oracle that catches that).
    const FLOOR: usize = 377;
    const TARGET: usize = 377;
    assert!(
        reconstruct >= FLOOR,
        "regression: only {reconstruct}/{total} reconstruct, expected >= {FLOOR} \
         (target {TARGET}); a fix broke previously-passing deltas"
    );
}
