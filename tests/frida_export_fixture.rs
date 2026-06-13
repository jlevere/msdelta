use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaExportOracle/raw-apply-delta-b"
);

#[test]
fn raw_apply_delta_b_export_fixture_is_curated() {
    let fixture = Path::new(FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let run = fs::read_to_string(fixture.join("native/run.json")).expect("read native run");
    let capture =
        fs::read_to_string(fixture.join("native/capture.json")).expect("read native capture");

    for required in [
        "atom = \"FridaExportOracle\"",
        "case = \"raw-apply-delta-b\"",
        "native_export = \"ApplyDeltaB\"",
        "transport = \"frida-inject\"",
        "capture_mode = \"file_sink\"",
        "file_type = \"0x1\"",
        "flags = \"0x0\"",
        "source_sha256 = \"64afc6db3aad1289533662e2d79e27dd55c7dcdb8cd918b08e145ad82ad5acb4\"",
        "delta_sha256 = \"69e2f9e82df18316f77d1fb13d1d169a42ce3238087292d5708604a7a3b1d61f\"",
        "target_sha256 = \"f51fab8041e5023d7290b540a2106f051ef0bd2bc3443c9daf318628b560fa29\"",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    for volatile in [".claude", "lab/frida/out", "jacks-MBP", "file_sink_path"] {
        assert!(
            !run.contains(volatile) && !capture.contains(volatile),
            "curated fixture should not retain volatile local field {volatile}"
        );
    }

    assert!(run.contains("\"device\": \"inject\""));
    assert!(run.contains(
        "\"sha256\": \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\""
    ));
    assert!(capture.contains("\"case_id\": \"raw-apply-delta-b\""));
    assert_eq!(capture.matches("\"symbol\": \"ApplyDeltaB\"").count(), 2);
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 1);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 1);
    assert!(capture.contains("\"success\": true"));
}

#[test]
fn raw_apply_delta_b_export_fixture_blobs_match_declared_hashes() {
    let fixture = Path::new(FIXTURE_DIR);
    assert_file_hash(
        fixture.join("source.bin"),
        339_968,
        "64afc6db3aad1289533662e2d79e27dd55c7dcdb8cd918b08e145ad82ad5acb4",
    );
    assert_file_hash(
        fixture.join("delta.pa30"),
        18_048,
        "69e2f9e82df18316f77d1fb13d1d169a42ce3238087292d5708604a7a3b1d61f",
    );
    assert_file_hash(
        fixture.join("target.bin"),
        65_536,
        "f51fab8041e5023d7290b540a2106f051ef0bd2bc3443c9daf318628b560fa29",
    );

    let blob_dir = fixture.join("native/blobs");
    let mut blob_summaries = fs::read_dir(&blob_dir)
        .expect("read native blob dir")
        .map(|entry| {
            let path = entry.expect("read native blob entry").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("blob file has utf-8 name")
                .to_owned();
            let bytes = fs::read(&path).expect("read native blob");
            (name, bytes.len(), sha256_hex(&bytes))
        })
        .collect::<Vec<_>>();
    blob_summaries.sort();

    assert_eq!(blob_summaries.len(), 3);
    assert!(blob_summaries.iter().any(|(name, size, hash)| {
        name.ends_with("ApplyDeltaB-enter-source.bin")
            && *size == 339_968
            && hash == "64afc6db3aad1289533662e2d79e27dd55c7dcdb8cd918b08e145ad82ad5acb4"
    }));
    assert!(blob_summaries.iter().any(|(name, size, hash)| {
        name.ends_with("ApplyDeltaB-enter-delta.bin")
            && *size == 18_048
            && hash == "69e2f9e82df18316f77d1fb13d1d169a42ce3238087292d5708604a7a3b1d61f"
    }));
    assert!(blob_summaries.iter().any(|(name, size, hash)| {
        name.ends_with("ApplyDeltaB-leave-target.bin")
            && *size == 65_536
            && hash == "f51fab8041e5023d7290b540a2106f051ef0bd2bc3443c9daf318628b560fa29"
    }));
}

fn assert_file_hash(path: PathBuf, expected_len: usize, expected_hash: &str) {
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(bytes.len(), expected_len, "{}", path.display());
    assert_eq!(sha256_hex(&bytes), expected_hash, "{}", path.display());
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
