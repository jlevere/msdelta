use super::{apply, parse};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

const DLL_SHA256: &str = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
const HARNESS_SHA256: &str = "06f385c4039c5f014f1262b4780934e4fc52ed9d45dc328a65a59161754a4871";

#[derive(Deserialize)]
struct Provenance {
    schema: u32,
    dll_sha256: String,
    harness_sha256: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    source_size: usize,
    target_size: usize,
    observations: Vec<Observation>,
    artifact_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Observation {
    flags: i64,
    native_capture: Capture,
    changed_offsets: Vec<usize>,
}

#[derive(Deserialize)]
struct Capture {
    dll_sha256: String,
    harness_sha256: String,
    uninstrumented_output_equal: bool,
    decompress_source_unchanged: bool,
    artifact_sha256: BTreeMap<String, String>,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn native_raw_postprocess_flags_boundaries_and_operand_advance() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/PePostProcessNative");
    let provenance: Provenance =
        serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance.schema, 1);
    assert_eq!(provenance.dll_sha256, DLL_SHA256);
    assert_eq!(provenance.harness_sha256, HARNESS_SHA256);
    assert_eq!(provenance.cases.len(), 11);
    for case in provenance.cases {
        let read = |name: &str| std::fs::read(root.join(&case.id).join(name)).unwrap();
        assert_eq!(case.artifact_sha256.len(), 7);
        for (name, expected) in &case.artifact_sha256 {
            assert_eq!(&digest(&read(name)), expected, "{}/{name}", case.id);
        }
        let source = read("source.bin");
        let original_delta = read("original.pa30");
        let original = parse(&original_delta).unwrap();
        let decompressed = read("decompressed.bin");
        assert_eq!(source.len(), case.source_size);
        assert_eq!(decompressed.len(), case.target_size);
        assert!(
            !decompressed.starts_with(b"MZ"),
            "{} is a RAW control",
            case.id
        );
        assert_eq!(original.header.file_type, 1);
        assert_eq!(original.header.flags, 0);
        assert_eq!(original.header.hash_alg_id, 0x8003);
        assert_eq!(original.header.target_hash.len(), 16);
        assert_eq!(
            apply(&source, &original_delta).unwrap(),
            decompressed,
            "{} original native delta",
            case.id
        );
        assert_eq!(case.observations.len(), 2);
        for (flag, observation) in case.observations.iter().enumerate() {
            assert_eq!(observation.flags, flag as i64);
            let capture = &observation.native_capture;
            assert_eq!(capture.dll_sha256, DLL_SHA256);
            assert_eq!(capture.harness_sha256, HARNESS_SHA256);
            assert!(capture.uninstrumented_output_equal);
            assert!(capture.decompress_source_unchanged);
            assert_eq!(
                capture.artifact_sha256["decompressed-target.bin"],
                digest(&decompressed)
            );
            let delta = read(&format!("flag-{flag}.pa30"));
            let expected = read(&format!("target-flag-{flag}.bin"));
            assert_eq!(capture.artifact_sha256["source.bin"], digest(&source));
            assert_eq!(capture.artifact_sha256["delta.pa30"], digest(&delta));
            assert_eq!(capture.artifact_sha256["target.bin"], digest(&expected));
            let parsed = parse(&delta).unwrap();
            assert_eq!(parsed.header.file_type, 1);
            assert_eq!(parsed.header.flags, flag as i64);
            assert_eq!(parsed.header.hash_alg_id, 0);
            assert!(parsed.header.target_hash.is_empty());
            assert_eq!(parsed.preprocess, original.preprocess);
            assert_eq!(parsed.patch_data, original.patch_data);
            let changed: Vec<_> = decompressed
                .iter()
                .zip(&expected)
                .enumerate()
                .filter_map(|(index, (before, after))| (before != after).then_some(index))
                .collect();
            assert_eq!(changed, observation.changed_offsets);
            if flag == 0 {
                assert!(changed.is_empty());
            }
            assert_eq!(
                apply(&source, &delta).unwrap(),
                expected,
                "{} flag {flag}",
                case.id
            );
        }
    }
}
