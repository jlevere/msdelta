use super::{apply, parse, parse_pe_preprocess};
use crate::pe::parse::PeInfo;
use crate::pe::transform::{build_transformed_source, zero_pe_checksum};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

const CASES: &[(&str, i64)] = &[
    ("x86-rva-moved", 2),
    ("x86-rva-preserved", 2),
    ("x64-rva-moved", 8),
    ("x64-rva-preserved", 8),
];

#[derive(Deserialize)]
struct Capture {
    schema: u32,
    dll_sha256: String,
    decompress_rva: u32,
    sum_rva: u32,
    reference_size: usize,
    original_source_size: usize,
    target_size: usize,
    uninstrumented_output_equal: bool,
    decompress_source_unchanged: bool,
    artifact_sha256: BTreeMap<String, String>,
}

fn read(case: &str, name: &str) -> Vec<u8> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/Pa30CopyNative");
    std::fs::read(root.join(case).join(name)).unwrap()
}

fn assert_bytes(label: &str, actual: &[u8], expected: &[u8]) {
    let differences: Vec<_> = actual
        .iter()
        .zip(expected)
        .enumerate()
        .filter(|(_, (actual, expected))| actual != expected)
        .take(12)
        .map(|(offset, (actual, expected))| format!("{offset:#x}: {actual:02x} != {expected:02x}"))
        .collect();
    assert!(
        actual == expected,
        "{label}: lengths {} / {}; {}",
        actual.len(),
        expected.len(),
        differences.join(", ")
    );
}

#[test]
fn native_pe_copy_source_and_complete_apply_match() {
    for &(case, file_type) in CASES {
        let capture: Capture = serde_json::from_slice(&read(case, "capture.json")).unwrap();
        assert_eq!(capture.schema, 1);
        assert_eq!(
            capture.dll_sha256,
            "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
        );
        assert_eq!(capture.decompress_rva, 0x7b40);
        assert_eq!(capture.sum_rva, 0x1ce10);
        assert!(capture.uninstrumented_output_equal);
        assert!(capture.decompress_source_unchanged);
        let names = [
            "source.bin",
            "delta.pa30",
            "target.bin",
            "transformed-source.bin",
            "decompressed-target.bin",
            "caller-rift.bin",
            "patch-rift.bin",
            "merged-rift.bin",
        ];
        assert_eq!(capture.artifact_sha256.len(), names.len());
        for name in names {
            let hash: String = Sha256::digest(read(case, name))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(capture.artifact_sha256[name], hash, "{case}/{name}");
        }
        let source = read(case, "source.bin");
        let delta = read(case, "delta.pa30");
        let parsed = parse(&delta).unwrap();
        assert_eq!(
            parsed.header.file_type, file_type,
            "{case}: native PE graph"
        );
        assert_eq!(source.len(), capture.original_source_size);
        assert_eq!(source.len(), capture.reference_size);
        assert_eq!(parsed.header.target_size as usize, capture.target_size);
        let preprocess = parse_pe_preprocess(&parsed.preprocess).unwrap();
        assert!(!preprocess.has_managed_cli_state());

        let mut transformed = source.clone();
        zero_pe_checksum(&mut transformed);
        let pe = PeInfo::parse_lenient(&transformed).unwrap();
        build_transformed_source(
            &mut transformed,
            &pe,
            &preprocess.preprocess_rift,
            parsed.header.flags as u64,
            preprocess.target_info.image_base,
            preprocess.target_info.time_date_stamp,
        );
        assert_bytes(case, &transformed, &read(case, "transformed-source.bin"));
        assert_bytes(
            case,
            &apply(&source, &delta).unwrap(),
            &read(case, "target.bin"),
        );
    }
}

#[test]
fn native_lock_prefix_deltas_apply_through_the_registered_pipeline() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/LockPrefixesNative");
    for case in [
        "mixed-targets",
        "raw-boundary",
        "absent-table",
        "short-directory",
        "raw-after-virtual",
    ] {
        let read = |name: &str| std::fs::read(root.join(case).join(name)).unwrap();
        let source = read("base.bin");
        let delta = read("native.pa30");
        assert_eq!(parse(&delta).unwrap().header.flags & 0x40, 0x40);
        assert_bytes(case, &apply(&source, &delta).unwrap(), &read("target.bin"));
    }
}

#[test]
fn registered_lock_prefix_pass_is_flag_and_machine_gated_without_marker_changes() {
    use crate::lzx::rift::RiftTable;
    use crate::pe::atom::run_registered;
    use crate::pe::parse::PeMachine;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/atoms/LockPrefixesNative/mixed-targets");
    let before = std::fs::read(root.join("before.bin")).unwrap();
    let after = std::fs::read(root.join("after.bin")).unwrap();
    let original_pe = PeInfo::parse_lenient(&before).unwrap();
    for (machine, flags, expected) in [
        (PeMachine::I386, 0x40, &after),
        (PeMachine::I386, 0, &before),
        (PeMachine::Amd64, 0x40, &before),
    ] {
        let mut image = before.clone();
        let mut pe = original_pe.clone();
        pe.machine = machine;
        let mut marker = vec![0xa5; image.len()];
        run_registered(
            &mut image,
            &pe,
            &RiftTable {
                entries: Vec::new(),
            },
            &mut marker,
            pe.image_base,
            flags,
        );
        assert_bytes("registered lock pass", &image, expected);
        assert!(marker.iter().all(|byte| *byte == 0xa5));
    }
}
