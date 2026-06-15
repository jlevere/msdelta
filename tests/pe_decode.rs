//! Committed native-PE decode regression gate.
//!
//! A small, architecture-diverse set of genuine `msdelta.dll` PE deltas with
//! their genuine target bytes, so CI actually validates the PE transform
//! pipeline (imports/exports/relocations/pdata/x86-calls) -- not just the
//! DCM manifest path. Each fixture is `apply(base, delta)` checked byte-for-byte
//! against the genuine target. See `tests/fixtures/pe-decode/README.md` for
//! provenance. The broader (git-ignored) bulk/matrix corpora remain the local
//! breadth gates; this is the portable subset that runs everywhere.

use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pe-decode")
}

/// Every committed fixture must decode byte-exact to its genuine target.
#[test]
fn pe_deltas_decode_byte_exact() {
    let root = fixtures_root();
    let mut checked = 0usize;
    let mut failures = Vec::new();

    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .expect("pe-decode fixtures present")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let base = std::fs::read(dir.join("base.bin")).expect("base.bin");
        let delta = std::fs::read(dir.join("delta.pa30")).expect("delta.pa30");
        let target = std::fs::read(dir.join("target.bin")).expect("target.bin");

        match msdelta::pa30::apply(&base, &delta) {
            Ok(out) if out == target => checked += 1,
            Ok(out) => failures.push(format!(
                "{name}: decoded {} bytes, expected {} ({} differ)",
                out.len(),
                target.len(),
                out.iter()
                    .zip(&target)
                    .filter(|(a, b)| a != b)
                    .count()
                    .max(out.len().abs_diff(target.len()))
            )),
            Err(e) => failures.push(format!("{name}: decode error: {e}")),
        }
    }

    assert!(checked > 0, "no pe-decode fixtures found under {root:?}");
    assert!(
        failures.is_empty(),
        "native PE decode regressed:\n{}",
        failures.join("\n")
    );
}
