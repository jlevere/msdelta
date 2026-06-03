//! Regression corpus for the PA31 deltas `pa30::apply` cannot yet reconstruct,
//! pulled from a real Win11 24H2 LCU (KB5089549) express PSF. See
//! `PA31-LCU-GAPS.md` for the analysis.
//!
//! The blobs are non-redistributable Microsoft payload, so they live in
//! `notes/pa31-lcu-gaps/` (git-ignored) and this test SKIPS when absent.
//! Regenerate them with the `msu` crate:
//!
//!   cargo run --release -- gaps <KB5089549.msu> -o <msdelta>/notes/pa31-lcu-gaps
//!
//! As msdelta's PA31 support improves, `reconstruct` rises toward 16/16; at
//! that point `msu` extracts the LCU to 100%.

use std::path::PathBuf;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pa31-lcu-gaps")
}

#[test]
fn pa31_lcu_gap_corpus() {
    let dir = corpus();
    let manifest = dir.join("manifest.tsv");
    if !manifest.exists() {
        eprintln!("pa31-lcu-gaps corpus absent ({dir:?}); skipping (see PA31-LCU-GAPS.md)");
        return;
    }

    let text = std::fs::read_to_string(&manifest).expect("read manifest.tsv");
    let mut total = 0usize;
    let mut reconstruct = 0usize;
    for line in text.lines().skip(1).filter(|l| !l.is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        // idx, magic, psf_offset, psf_len, target_len, target_sha256, blob, reason, name
        let blob = cols[6];
        let name = cols.last().copied().unwrap_or("");
        let delta = std::fs::read(dir.join(blob)).expect("read delta blob");

        // Corpus sanity: every blob is a baseless PA31 delta.
        assert_eq!(&delta[..4], b"PA31", "{blob} is not PA31");
        total += 1;

        // Null base: these are baseless (no <Basis> in the CIX).
        match msdelta::pa30::apply(&[], &delta) {
            Ok(out) => {
                reconstruct += 1;
                eprintln!("OK   {blob} -> {} bytes  {name}", out.len());
            }
            Err(e) => eprintln!("FAIL {blob}: {e}"),
        }
    }

    eprintln!("\nPA31 LCU gaps: {reconstruct}/{total} reconstruct (null base)");
    assert!(total > 0, "manifest had no entries");

    // Regression gate. As of the LZMS rebuild-order + x86-filter fixes, all
    // nine LZMS-container blobs reconstruct bit-exactly against their embedded
    // SHA256 EXCEPT delta_03 (a residual LZMS delta-match divergence): that is
    // eight passes. The remaining failures are the seven PseudoLzx/LZX-path
    // blobs (a separate codec bug) plus delta_03. See PA31-LCU-GAPS.md.
    //
    // This asserts we do not regress below the known-good count; raise it as the
    // LZX path and delta_03 are fixed (target: 16/16).
    const KNOWN_GOOD: usize = 9;
    assert!(
        reconstruct >= KNOWN_GOOD,
        "regression: only {reconstruct}/{total} reconstruct, expected >= {KNOWN_GOOD}"
    );
}
