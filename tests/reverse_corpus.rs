//! Reverse-delta decode against genuine WinSxS reverse differentials.
//!
//! Each gold dir holds `reference.bin` (the patched/new file), `reverse.pa31`
//! (the genuine reverse delta), and `base.bin` (the expected reconstruction, as
//! produced by genuine `UpdateCompression!ApplyDeltaB` and verified against the
//! delta's embedded hash). These are genuine Microsoft bytes kept out of the repo
//! (gitignored under `notes/`); the test skips when the corpus is absent (e.g. CI).

use std::fs;
use std::path::Path;

#[test]
fn reverse_corpus_roundtrips() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("notes/genuine-samples/corpus");
    let Ok(read_dir) = fs::read_dir(&dir) else {
        eprintln!("reverse corpus absent ({dir:?}); skipping");
        return;
    };

    let mut checked = 0;
    let mut failures = Vec::new();
    for entry in read_dir.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let (Ok(reference), Ok(delta), Ok(expected)) = (
            fs::read(p.join("reference.bin")),
            fs::read(p.join("reverse.pa31")),
            fs::read(p.join("base.bin")),
        ) else {
            continue;
        };
        let id = p.file_name().unwrap().to_string_lossy().into_owned();
        checked += 1;
        match msdelta::pa30::apply(&reference, &delta) {
            Ok(out) if out == expected => {}
            Ok(out) => failures.push(format!("{id}: output mismatch ({} vs {} bytes)", out.len(), expected.len())),
            Err(e) => failures.push(format!("{id}: {e}")),
        }
    }

    assert!(failures.is_empty(), "reverse decode failures:\n{}", failures.join("\n"));
    if checked > 0 {
        eprintln!("reverse corpus: {checked} golds decoded correctly");
    }
}
