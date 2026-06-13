use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaStageCapture/cli-metadata-win26100"
);

#[test]
fn cli_metadata_stage_fixture_is_curated_from_live_lab_capture() {
    let fixture = Path::new(FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");

    for required in [
        "atom = \"FridaStageCapture\"",
        "case = \"cli-metadata-win26100\"",
        "source_case = \"managed-corpus-msdelta\"",
        "module = \"msdelta.dll\"",
        "module_sha256 = \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
        "symbol = \"compo::CliMetadata::InternalFromBitReader\"",
        "legacy_symbol = \"CliMetadata::FromBitReader\"",
        "rva = \"0x1cba0\"",
        "abi = \"ms-x64-thiscall\"",
        "capture_adapter = \"cli_metadata_internal_from_bitreader\"",
        "object_layout = \"msdelta-win26100-compo-cli-metadata-v1\"",
        "target_atom = \"CliMetadataBitstream\"",
        "transport = \"frida-inject\"",
        "normalization_error_count = 0",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    assert_eq!(read_usize(&case, "export_event_count"), 36);
    assert_eq!(read_usize(&case, "stage_event_count"), 100);
    assert_eq!(read_usize(&case, "stage_leave_object_count"), 50);
    assert_eq!(read_usize(&case, "distinct_object_hash_count"), 6);

    for volatile in ["file_sink_path", ".claude", "lab/frida/out"] {
        assert!(
            !capture.contains(volatile),
            "curated stage fixture should not retain volatile field {volatile}"
        );
    }

    assert!(capture.contains("\"atom\": \"FridaStageCapture\""));
    assert!(capture.contains("\"target_atom\": \"CliMetadataBitstream\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMetadata::InternalFromBitReader\""));
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 50);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 50);
    assert_eq!(
        capture
            .matches("\"type\": \"CliMetadataBitstreamRecord\"")
            .count(),
        50
    );
}

#[test]
fn cli_metadata_stage_objects_are_logical_and_diverse() {
    let fixture = Path::new(FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");
    let object_dir = fixture.join("objects");

    let mut objects = fs::read_dir(&object_dir)
        .expect("read objects dir")
        .map(|entry| entry.expect("read object entry").path())
        .collect::<Vec<_>>();
    objects.sort();
    assert_eq!(objects.len(), read_usize(&case, "stage_leave_object_count"));

    let mut distinct_hashes = BTreeSet::new();
    let mut present_count = 0usize;
    let mut empty_count = 0usize;
    for object_path in objects {
        let text = fs::read_to_string(&object_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", object_path.display()));
        let hash = sha256_file(&object_path);
        distinct_hashes.insert(hash.clone());
        if text.contains("\"present\": true") {
            present_count += 1;
        } else if text.contains("\"present\": false") {
            empty_count += 1;
        }

        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            object_path.display()
        );
        for required in [
            "\"type\": \"CliMetadataBitstreamRecord\"",
            "\"native_layout\": \"msdelta-win26100-compo-cli-metadata-v1\"",
            "\"present\"",
            "\"metadata_file_offset\"",
            "\"metadata_size\"",
            "\"stream_count\"",
            "\"streams\"",
            "\"heap_widths\"",
            "\"valid_table_mask\"",
            "\"row_counts\"",
        ] {
            assert!(
                text.contains(required),
                "{} missing {required}",
                object_path.display()
            );
        }
        assert!(
            !text.contains("this_ptr") && !text.contains("reader_ptr"),
            "{} should not contain raw pointer fields",
            object_path.display()
        );
    }

    assert_eq!(
        distinct_hashes.len(),
        read_usize(&case, "distinct_object_hash_count")
    );
    assert!(
        present_count > 0,
        "fixture should include present metadata records"
    );
    assert!(
        empty_count > 0,
        "fixture should include empty metadata records"
    );

    let first = fs::read_to_string(fixture.join("objects/cli-metadata-001.json"))
        .expect("read first object");
    for required in [
        "\"metadata_file_offset\": 624",
        "\"metadata_size\": 732",
        "\"stream_count\": 5",
        "\"valid_table_mask\": \"0x0000000900001447\"",
    ] {
        assert!(first.contains(required), "first object missing {required}");
    }
}

fn read_usize(case: &str, key: &str) -> usize {
    let prefix = format!("{key} = ");
    case.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing scalar {key}"))
        .parse()
        .unwrap_or_else(|error| panic!("{key} should be usize: {error}"))
}

fn sha256_file(path: &PathBuf) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
