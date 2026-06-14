use sha2::{Digest, Sha256};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaStageCapture/cli-metadata-win26100"
);
const CLI_MAP_FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaStageCapture/cli-map-win26100"
);
const CLI_CODED_TOKEN_MAP_FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaStageCapture/cli-coded-token-map-win26100"
);
const CLI_BLOB_COMPRESSED_INTEGER_FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/FridaStageCapture/cli-blob-compressed-integer-win26100"
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
        "reader_layout = \"msdelta-win26100-bitreader-read-v1\"",
        "target_atom = \"CliMetadataBitstream\"",
        "transport = \"frida-inject\"",
        "normalization_error_count = 0",
        "reader_window_error_count = 0",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    assert_eq!(read_usize(&case, "export_event_count"), 36);
    assert_eq!(read_usize(&case, "stage_event_count"), 100);
    assert_eq!(read_usize(&case, "stage_leave_object_count"), 50);
    assert_eq!(read_usize(&case, "stage_leave_blob_count"), 50);
    assert_eq!(read_usize(&case, "distinct_object_hash_count"), 6);
    assert_eq!(read_usize(&case, "distinct_blob_hash_count"), 6);

    for volatile in [
        "file_sink_path",
        ".claude",
        "lab/frida/out",
        "this_ptr",
        "reader_ptr",
        "timestamp_ms",
        "thread_id",
    ] {
        assert!(
            !capture.contains(volatile),
            "curated stage fixture should not retain volatile field {volatile}"
        );
    }

    assert!(capture.contains("\"atom\": \"FridaStageCapture\""));
    assert!(capture.contains("\"target_atom\": \"CliMetadataBitstream\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMetadata::InternalFromBitReader\""));
    assert!(capture.contains("\"native_layout\": \"msdelta-win26100-bitreader-read-v1\""));
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 50);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 50);
    assert_eq!(
        capture
            .matches("\"type\": \"CliMetadataBitstreamRecord\"")
            .count(),
        50
    );
    assert_eq!(capture.matches("\"reader_window\"").count(), 50);
    assert_eq!(
        capture.matches("\"slot\": \"reader-bitstream\"").count(),
        50
    );
    assert!(
        !capture.contains("\"error\""),
        "curated reader-window fixture should not contain capture errors"
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

#[test]
fn cli_metadata_stage_reader_bitstreams_are_hashed_and_diverse() {
    let fixture = Path::new(FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");
    let blob_dir = fixture.join("blobs");

    let mut blobs = fs::read_dir(&blob_dir)
        .expect("read blobs dir")
        .map(|entry| entry.expect("read blob entry").path())
        .collect::<Vec<_>>();
    blobs.sort();
    assert_eq!(blobs.len(), read_usize(&case, "stage_leave_blob_count"));

    let mut distinct_hashes = BTreeSet::new();
    for blob_path in blobs {
        let bytes = fs::read(&blob_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", blob_path.display()));
        assert!(
            !bytes.is_empty(),
            "{} should contain a standalone reader bitstream",
            blob_path.display()
        );
        let hash = sha256_file(&blob_path);
        distinct_hashes.insert(hash.clone());
        let file_name = blob_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_else(|| panic!("blob path has no UTF-8 file name: {}", blob_path.display()));
        assert!(
            capture.contains(file_name),
            "capture should reference {}",
            blob_path.display()
        );
        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            blob_path.display()
        );
    }

    assert_eq!(
        distinct_hashes.len(),
        read_usize(&case, "distinct_blob_hash_count")
    );
}

#[test]
fn cli_map_stage_fixture_is_curated_from_live_lab_capture() {
    let fixture = Path::new(CLI_MAP_FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");

    for required in [
        "atom = \"FridaStageCapture\"",
        "case = \"cli-map-win26100\"",
        "source_case = \"managed-corpus-msdelta\"",
        "module = \"msdelta.dll\"",
        "module_sha256 = \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
        "symbol = \"compo::CliMap::FromBitReader\"",
        "legacy_symbol = \"CliMap::FromBitReader\"",
        "rva = \"0x1a160\"",
        "abi = \"ms-x64-thiscall\"",
        "capture_adapter = \"cli_map_from_bitreader\"",
        "object_layout = \"msdelta-win26100-compo-cli-map-v1\"",
        "reader_layout = \"msdelta-win26100-bitreader-read-v1\"",
        "target_atom = \"CliMapBitstream\"",
        "transport = \"frida-inject\"",
        "normalization_error_count = 0",
        "reader_window_error_count = 0",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    assert_eq!(read_usize(&case, "export_event_count"), 36);
    assert_eq!(read_usize(&case, "stage_event_count"), 100);
    assert_eq!(read_usize(&case, "stage_leave_object_count"), 50);
    assert_eq!(read_usize(&case, "stage_leave_blob_count"), 50);
    assert_eq!(read_usize(&case, "distinct_object_hash_count"), 4);
    assert_eq!(read_usize(&case, "distinct_blob_hash_count"), 4);
    assert_eq!(read_usize(&case, "empty_map_count"), 23);
    assert_eq!(read_usize(&case, "non_empty_map_count"), 27);

    for volatile in [
        "file_sink_path",
        ".claude",
        "lab/frida/out",
        "this_ptr",
        "reader_ptr",
        "timestamp_ms",
        "thread_id",
        "\"retval\"",
    ] {
        assert!(
            !capture.contains(volatile),
            "curated stage fixture should not retain volatile field {volatile}"
        );
    }

    assert!(capture.contains("\"atom\": \"FridaStageCapture\""));
    assert!(capture.contains("\"target_atom\": \"CliMapBitstream\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMap::FromBitReader\""));
    assert!(capture.contains("\"native_layout\": \"msdelta-win26100-bitreader-read-v1\""));
    assert!(capture.contains("\"trace_source\": \"reader-window\""));
    assert!(capture.contains("\"trace_source\": \"BitReader::Read\""));
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 50);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 50);
    assert_eq!(
        capture
            .matches("\"type\": \"CliMapBitstreamRecord\"")
            .count(),
        50
    );
    assert_eq!(capture.matches("\"reader_window\"").count(), 50);
    assert_eq!(
        capture.matches("\"slot\": \"reader-bitstream\"").count(),
        50
    );
    assert!(
        !capture.contains("\"error\""),
        "curated reader-window fixture should not contain capture errors"
    );
}

#[test]
fn cli_map_stage_objects_and_bitstreams_are_hashed_and_diverse() {
    let fixture = Path::new(CLI_MAP_FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");
    let object_dir = fixture.join("objects");
    let blob_dir = fixture.join("blobs");

    let mut objects = fs::read_dir(&object_dir)
        .expect("read objects dir")
        .map(|entry| entry.expect("read object entry").path())
        .collect::<Vec<_>>();
    objects.sort();
    assert_eq!(objects.len(), read_usize(&case, "stage_leave_object_count"));

    let mut distinct_object_hashes = BTreeSet::new();
    let mut empty_maps = 0usize;
    let mut non_empty_maps = 0usize;
    for object_path in objects {
        let text = fs::read_to_string(&object_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", object_path.display()));
        let hash = sha256_file(&object_path);
        distinct_object_hashes.insert(hash.clone());
        if text.matches("\"source\"").count() == 0 {
            empty_maps += 1;
        } else {
            non_empty_maps += 1;
        }

        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            object_path.display()
        );
        for required in [
            "\"type\": \"CliMapBitstreamRecord\"",
            "\"native_layout\": \"msdelta-win26100-compo-cli-map-v1\"",
            "\"strings\"",
            "\"user_strings\"",
            "\"blob\"",
            "\"guid\"",
            "\"tables\"",
            "\"entries\"",
            "\"sorted\"",
        ] {
            assert!(
                text.contains(required),
                "{} missing {required}",
                object_path.display()
            );
        }
    }

    assert_eq!(
        distinct_object_hashes.len(),
        read_usize(&case, "distinct_object_hash_count")
    );
    assert_eq!(empty_maps, read_usize(&case, "empty_map_count"));
    assert_eq!(non_empty_maps, read_usize(&case, "non_empty_map_count"));

    let mut blobs = fs::read_dir(&blob_dir)
        .expect("read blobs dir")
        .map(|entry| entry.expect("read blob entry").path())
        .collect::<Vec<_>>();
    blobs.sort();
    assert_eq!(blobs.len(), read_usize(&case, "stage_leave_blob_count"));

    let mut distinct_blob_hashes = BTreeSet::new();
    for blob_path in blobs {
        let bytes = fs::read(&blob_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", blob_path.display()));
        assert!(
            !bytes.is_empty(),
            "{} should contain a standalone reader bitstream",
            blob_path.display()
        );
        let hash = sha256_file(&blob_path);
        distinct_blob_hashes.insert(hash.clone());
        let file_name = blob_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_else(|| panic!("blob path has no UTF-8 file name: {}", blob_path.display()));
        assert!(
            capture.contains(file_name),
            "capture should reference {}",
            blob_path.display()
        );
        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            blob_path.display()
        );
    }

    assert_eq!(
        distinct_blob_hashes.len(),
        read_usize(&case, "distinct_blob_hash_count")
    );
}

#[test]
fn cli_coded_token_map_stage_fixture_is_curated_from_live_lab_capture() {
    let fixture = Path::new(CLI_CODED_TOKEN_MAP_FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");

    for required in [
        "atom = \"FridaStageCapture\"",
        "case = \"cli-coded-token-map-win26100\"",
        "source_case = \"managed-corpus-msdelta\"",
        "module = \"msdelta.dll\"",
        "module_sha256 = \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
        "symbols = [\"compo::CliMap::MapCoded\", \"compo::CliMap::MapCodedExact\"]",
        "rvas = [\"0x22578\", \"0x499c0\"]",
        "abi = \"ms-x64-thiscall\"",
        "capture_adapter = \"cli_map_coded_token_call\"",
        "call_layout = \"msdelta-win26100-compo-cli-map-coded-token-v1\"",
        "object_layout = \"msdelta-win26100-compo-cli-map-v1\"",
        "target_atom = \"CliCodedTokenMap\"",
        "transport = \"frida-inject\"",
        "normalization_error_count = 0",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    assert_eq!(read_usize(&case, "export_event_count"), 36);
    assert_eq!(read_usize(&case, "source_stage_event_count"), 4516);
    assert_eq!(read_usize(&case, "stage_event_count"), 160);
    assert_eq!(read_usize(&case, "stage_leave_object_count"), 80);
    assert_eq!(read_usize(&case, "stage_leave_blob_count"), 0);
    assert_eq!(read_usize(&case, "distinct_object_hash_count"), 80);
    assert_eq!(read_usize(&case, "map_coded_case_count"), 52);
    assert_eq!(read_usize(&case, "map_coded_exact_case_count"), 28);
    assert_eq!(read_usize(&case, "non_empty_map_count"), 52);
    assert_eq!(read_usize(&case, "exact_miss_count"), 4);
    assert_eq!(read_usize(&case, "large_s64_value_count"), 28);

    for volatile in [
        "file_sink_path",
        ".claude",
        "lab/frida/out",
        "this_ptr",
        "reader_ptr",
        "timestamp_ms",
        "thread_id",
        "\"retval\"",
    ] {
        assert!(
            !capture.contains(volatile),
            "curated stage fixture should not retain volatile field {volatile}"
        );
    }

    assert!(capture.contains("\"target_atom\": \"CliCodedTokenMap\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMap::MapCoded\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMap::MapCodedExact\""));
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 80);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 80);
    assert_eq!(
        capture
            .matches("\"type\": \"CliCodedTokenMapCallRecord\"")
            .count(),
        80
    );
    assert!(
        !capture.contains("\"error\""),
        "curated call fixture should not contain capture errors"
    );
}

#[test]
fn cli_coded_token_map_stage_objects_are_hashed_and_diverse() {
    let fixture = Path::new(CLI_CODED_TOKEN_MAP_FIXTURE_DIR);
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
    let mut map_coded = 0usize;
    let mut map_coded_exact = 0usize;
    let mut exact_miss = 0usize;
    let mut large_s64 = 0usize;
    let mut non_empty_maps = 0usize;
    for object_path in objects {
        let text = fs::read_to_string(&object_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", object_path.display()));
        let hash = sha256_file(&object_path);
        distinct_hashes.insert(hash.clone());
        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            object_path.display()
        );
        for required in [
            "\"type\": \"CliCodedTokenMapCallRecord\"",
            "\"native_layout\": \"msdelta-win26100-compo-cli-map-coded-token-v1\"",
            "\"kind\"",
            "\"raw\"",
            "\"result\"",
            "\"map\"",
            "\"type\": \"CliMapBitstreamRecord\"",
            "\"tables\"",
        ] {
            assert!(
                text.contains(required),
                "{} missing {required}",
                object_path.display()
            );
        }
        if text.contains("\"operation\": \"MapCoded\"") {
            map_coded += 1;
        }
        if text.contains("\"operation\": \"MapCodedExact\"") {
            map_coded_exact += 1;
        }
        if text.contains("\"result\": 4294967295") {
            exact_miss += 1;
        }
        if text.contains("\"9223372036854775807\"") {
            large_s64 += 1;
        }
        if text.matches("\"source\"").count() > 0 {
            non_empty_maps += 1;
        }
    }

    assert_eq!(
        distinct_hashes.len(),
        read_usize(&case, "distinct_object_hash_count")
    );
    assert_eq!(map_coded, read_usize(&case, "map_coded_case_count"));
    assert_eq!(
        map_coded_exact,
        read_usize(&case, "map_coded_exact_case_count")
    );
    assert_eq!(exact_miss, read_usize(&case, "exact_miss_count"));
    assert_eq!(large_s64, read_usize(&case, "large_s64_value_count"));
    assert_eq!(non_empty_maps, read_usize(&case, "non_empty_map_count"));
}

#[test]
fn cli_blob_compressed_integer_stage_fixture_is_curated_from_live_lab_capture() {
    let fixture = Path::new(CLI_BLOB_COMPRESSED_INTEGER_FIXTURE_DIR);
    let case = fs::read_to_string(fixture.join("case.toml")).expect("read case.toml");
    let capture = fs::read_to_string(fixture.join("capture.json")).expect("read capture.json");

    for required in [
        "atom = \"FridaStageCapture\"",
        "case = \"cli-blob-compressed-integer-win26100\"",
        "source_case = \"managed-corpus-msdelta\"",
        "module = \"msdelta.dll\"",
        "module_sha256 = \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
        "symbol = \"compo::CliMetadata::GetBlobContent\"",
        "legacy_symbol = \"CliMetadata::GetBlobContent\"",
        "rva = \"0x1f5cc\"",
        "abi = \"ms-x64-thiscall\"",
        "capture_adapter = \"cli_blob_get_content_call\"",
        "call_layout = \"msdelta-win26100-compo-cli-metadata-get-blob-content-v1\"",
        "target_atom = \"CliBlobCompressedInteger\"",
        "transport = \"frida-inject\"",
        "coverage_note = \"current managed corpus covers successful one-byte compressed integer prefixes only\"",
        "normalization_error_count = 0",
    ] {
        assert!(case.contains(required), "case.toml missing {required}");
    }

    assert_eq!(read_usize(&case, "export_event_count"), 36);
    assert_eq!(read_usize(&case, "source_stage_event_count"), 2182);
    assert_eq!(read_usize(&case, "stage_event_count"), 22);
    assert_eq!(read_usize(&case, "stage_leave_object_count"), 11);
    assert_eq!(read_usize(&case, "stage_leave_blob_count"), 0);
    assert_eq!(read_usize(&case, "distinct_object_hash_count"), 11);
    assert_eq!(read_usize(&case, "native_success_count"), 11);
    assert_eq!(read_usize(&case, "native_failure_count"), 0);
    assert_eq!(read_usize(&case, "one_byte_width_count"), 11);
    assert_eq!(read_usize(&case, "two_byte_width_count"), 0);
    assert_eq!(read_usize(&case, "four_byte_width_count"), 0);
    assert_eq!(read_usize(&case, "distinct_decoded_length_count"), 11);

    for volatile in [
        "file_sink_path",
        ".claude",
        "lab/frida/out",
        "this_ptr",
        "reader_ptr",
        "metadata_ptr",
        "out_length_ptr",
        "encoded_ptr",
        "content_ptr",
        "timestamp_ms",
        "thread_id",
        "\"retval\"",
    ] {
        assert!(
            !capture.contains(volatile),
            "curated stage fixture should not retain volatile field {volatile}"
        );
    }

    assert!(capture.contains("\"target_atom\": \"CliBlobCompressedInteger\""));
    assert!(capture.contains("\"symbol\": \"compo::CliMetadata::GetBlobContent\""));
    assert!(capture.contains("\"capture\": \"cli_blob_get_content_call\""));
    assert!(capture.contains("\"blob_stream\""));
    assert!(capture.contains("\"encoded_prefix\""));
    assert_eq!(capture.matches("\"phase\": \"enter\"").count(), 11);
    assert_eq!(capture.matches("\"phase\": \"leave\"").count(), 11);
    assert_eq!(
        capture
            .matches("\"type\": \"CliBlobCompressedIntegerCallRecord\"")
            .count(),
        11
    );
    assert_eq!(capture.matches("\"width\": 1").count(), 22);
    assert!(
        !capture.contains("\"width\": 2") && !capture.contains("\"width\": 4"),
        "current fixture should not pretend to cover multi-byte prefixes"
    );
    assert!(
        !capture.contains("\"error\""),
        "curated call fixture should not contain capture errors"
    );
}

#[test]
fn cli_blob_compressed_integer_stage_objects_are_hashed_and_semantic() {
    let fixture = Path::new(CLI_BLOB_COMPRESSED_INTEGER_FIXTURE_DIR);
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
    let mut decoded_lengths = BTreeSet::new();
    let mut one_byte_widths = 0usize;
    let mut successes = 0usize;
    for object_path in objects {
        let text = fs::read_to_string(&object_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", object_path.display()));
        let hash = sha256_file(&object_path);
        distinct_hashes.insert(hash.clone());
        assert!(
            capture.contains(&hash),
            "capture should reference hash for {}",
            object_path.display()
        );
        for required in [
            "\"type\": \"CliBlobCompressedIntegerCallRecord\"",
            "\"native_layout\": \"msdelta-win26100-compo-cli-metadata-get-blob-content-v1\"",
            "\"blob_offset\"",
            "\"blob_stream\"",
            "\"available_bytes\"",
            "\"encoded_prefix\"",
            "\"status\": \"ok\"",
            "\"result\"",
            "\"success\": true",
            "\"decoded_length\"",
            "\"encoded_width\"",
        ] {
            assert!(
                text.contains(required),
                "{} missing {required}",
                object_path.display()
            );
        }
        for volatile in [
            "this_ptr",
            "reader_ptr",
            "metadata_ptr",
            "out_length_ptr",
            "encoded_ptr",
            "content_ptr",
            "\"retval\"",
            "\"error\"",
        ] {
            assert!(
                !text.contains(volatile),
                "{} should not contain volatile field {volatile}",
                object_path.display()
            );
        }

        let value: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", object_path.display()));
        assert_eq!(
            value["type"].as_str(),
            Some("CliBlobCompressedIntegerCallRecord")
        );
        assert_eq!(
            value["native_layout"].as_str(),
            Some("msdelta-win26100-compo-cli-metadata-get-blob-content-v1")
        );
        assert_eq!(value["result"]["success"].as_bool(), Some(true));
        successes += 1;

        let decoded_length = value["result"]["decoded_length"]
            .as_u64()
            .expect("decoded length should be numeric");
        let encoded_width = value["result"]["encoded_width"]
            .as_u64()
            .expect("encoded width should be numeric");
        let prefix_decode = &value["encoded_prefix"]["decode"];
        assert_eq!(prefix_decode["status"].as_str(), Some("ok"));
        assert_eq!(prefix_decode["value"].as_u64(), Some(decoded_length));
        assert_eq!(prefix_decode["width"].as_u64(), Some(encoded_width));
        if encoded_width == 1 {
            one_byte_widths += 1;
        }
        decoded_lengths.insert(decoded_length);
    }

    assert_eq!(
        distinct_hashes.len(),
        read_usize(&case, "distinct_object_hash_count")
    );
    assert_eq!(successes, read_usize(&case, "native_success_count"));
    assert_eq!(one_byte_widths, read_usize(&case, "one_byte_width_count"));
    assert_eq!(
        decoded_lengths.len(),
        read_usize(&case, "distinct_decoded_length_count")
    );

    let first = fs::read_to_string(fixture.join("objects/cli-blob-compressed-integer-001.json"))
        .expect("read first object");
    for required in [
        "\"blob_offset\": 19",
        "\"value\": 2",
        "\"decoded_length\": 2",
        "\"encoded_width\": 1",
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
