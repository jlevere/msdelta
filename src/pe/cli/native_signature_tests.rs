//! Replay owned native metadata signatures and independently captured CLI maps.

use super::blob::read_compressed_u32;
use super::metadata::{parse_cli_metadata_from_pe, CliColumnValue, CliMetadataModel};
use super::metadata_transform::transform_cli_metadata_with_rva_map;
use super::schema::{table, table_schema, CliSchemaFlavor, HeapKind};
use super::tokens::BlobHeapOffset;
use crate::lzx::rift::RiftTable;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CASES: [&str; 3] = ["definition-moves", "reference-moves", "both-move"];
const FAMILIES: [&str; 2] = ["CliSignaturesNative", "CliSignatureGrammarNative"];
const DLL_SHA256: &str = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";

#[derive(Deserialize)]
struct Provenance {
    schema: u32,
    dll_sha256: String,
    harness_sha256: String,
    cases: BTreeMap<String, BTreeMap<String, String>>,
    source_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Input {
    schema: u32,
    case: String,
    source: InputImage,
    target: InputImage,
}

#[derive(Deserialize)]
struct InputImage {
    normalized_sha256: String,
    source_sha256: String,
}

#[derive(Deserialize)]
struct Capture {
    schema: u32,
    dll_sha256: String,
    harness_sha256: String,
    stage_trace_sha256: String,
    uninstrumented_output_equal: bool,
    decompress_source_unchanged: bool,
    artifact_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct NativeMaps {
    schema: u32,
    dll_sha256: String,
    harness_sha256: String,
    stage: String,
    unchanged_on_return: bool,
    artifact_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Stages {
    schema: u32,
    dll_sha256: String,
    harness_sha256: String,
    stages: Vec<Stage>,
}

#[derive(Deserialize)]
struct Stage {
    id: usize,
    name: String,
    artifact_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Observations {
    schema: u32,
    case: String,
    capture_sha256: String,
    cli_maps_sha256: String,
    records: Vec<SignatureRecord>,
}

#[derive(Deserialize)]
struct SignatureRecord {
    table: String,
    table_id: u8,
    rid: u32,
    source_heap_offset: u32,
    signature_file_offset: usize,
    signature_size: usize,
    source_signature_hex: String,
    native_after_signature_hex: String,
    target_rid: u32,
    target_heap_offset: u32,
    target_signature_hex: String,
    tokens: Vec<TokenRecord>,
}

#[derive(Deserialize)]
struct TokenRecord {
    role: String,
    element: String,
    signature_offset: usize,
    width: usize,
    coded: u32,
    table_id: u8,
    rid: u32,
    native_after_coded: u32,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn verified(directory: &Path, file: &str, expected: &str) -> Vec<u8> {
    let bytes = std::fs::read(directory.join(file)).unwrap();
    assert_eq!(digest(&bytes), expected, "{}: {file}", directory.display());
    bytes
}

fn fixture(family: &str, name: &str) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/atoms")
        .join(family);
    let provenance: Provenance = read_json(&root.join("provenance.json"));
    assert_eq!(provenance.schema, 1);
    assert_eq!(provenance.dll_sha256, DLL_SHA256);
    assert_eq!(
        provenance
            .cases
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        CASES.into_iter().collect()
    );
    for (source, hash) in &provenance.source_sha256 {
        verified(Path::new(env!("CARGO_MANIFEST_DIR")), source, hash);
    }
    let directory = root.join(name);
    for (file, hash) in &provenance.cases[name] {
        verified(&directory, file, hash);
    }
    let input: Input = read_json(&directory.join("input.json"));
    assert_eq!(input.schema, 1);
    assert_eq!(input.case, name);
    for (label, image) in [("source", input.source), ("target", input.target)] {
        verified(
            &directory,
            &format!("{label}.bin"),
            &image.normalized_sha256,
        );
        verified(&directory, &format!("{label}.cs"), &image.source_sha256);
    }
    let capture: Capture = read_json(&directory.join("capture.json"));
    assert_eq!(capture.schema, 1);
    assert_eq!(capture.dll_sha256, DLL_SHA256);
    assert_eq!(capture.harness_sha256, provenance.harness_sha256);
    assert!(capture.uninstrumented_output_equal && capture.decompress_source_unchanged);
    for (file, hash) in &capture.artifact_sha256 {
        verified(&directory, file, hash);
    }
    verified(&directory, "stages.json", &capture.stage_trace_sha256);
    let stages: Stages = read_json(&directory.join("stages.json"));
    assert_eq!(stages.schema, 1);
    assert_eq!(stages.dll_sha256, DLL_SHA256);
    assert_eq!(stages.harness_sha256, provenance.harness_sha256);
    let metadata_stages: Vec<_> = stages
        .stages
        .iter()
        .filter(|stage| stage.name == "cli-metadata")
        .collect();
    assert_eq!(metadata_stages.len(), 1);
    let stage = metadata_stages[0];
    let load_stage = |phase: &str| {
        let file = format!("stage-{:02}-cli-metadata-{phase}.bin", stage.id);
        verified(&directory, &file, &stage.artifact_sha256[&file])
    };
    let before = load_stage("before");
    let after = load_stage("after");
    (directory, before, after)
}

fn native_pairs(bytes: &[u8]) -> Vec<(i64, i64)> {
    assert_eq!(bytes.len() % 16, 0);
    bytes
        .chunks_exact(16)
        .map(|entry| {
            (
                i64::from_le_bytes(entry[..8].try_into().unwrap()),
                i64::from_le_bytes(entry[8..].try_into().unwrap()),
            )
        })
        .collect()
}

fn rust_pairs(map: &RiftTable) -> Vec<(i64, i64)> {
    map.entries
        .iter()
        .map(|entry| (entry.source, entry.target))
        .collect()
}

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn verify_blob_owner(
    metadata: &CliMetadataModel,
    image: &[u8],
    table_id: u8,
    rid: u32,
    heap_offset: u32,
) {
    let row = metadata.table_row_by_id(image, table_id, rid).unwrap();
    let CliColumnValue::Heap {
        kind: HeapKind::Blob,
        offset,
    } = row.column("Signature").unwrap()
    else {
        panic!("signature owner must name a blob heap index");
    };
    assert_eq!(offset, heap_offset);
}

#[test]
fn grammar_controls_distinguish_return_types_and_generic_argument_counts() {
    use super::tokens::StringsHeapOffset;
    for case in ["definition-moves", "both-move"] {
        let (directory, before, _) = fixture("CliSignatureGrammarNative", case);
        let metadata = parse_cli_metadata_from_pe(&before, CliSchemaFlavor::Classic).unwrap();
        let observations: Observations = read_json(&directory.join("observations.json"));
        let mut checked = BTreeSet::new();
        for record in observations
            .records
            .iter()
            .filter(|r| r.table_id == table::METHOD_DEF)
        {
            let row = metadata
                .table_row_by_id(&before, table::METHOD_DEF, record.rid)
                .unwrap();
            let CliColumnValue::Heap {
                kind: HeapKind::Strings,
                offset,
            } = row.column("Name").unwrap()
            else {
                panic!("method name must use string heap")
            };
            let name = metadata
                .strings(&before, StringsHeapOffset::new(offset))
                .unwrap();
            match name {
                "StaticVoid" | "InstanceVoid" => {
                    assert!(!record.tokens.is_empty());
                    assert!(record
                        .tokens
                        .iter()
                        .all(|t| t.coded == t.native_after_coded));
                }
                "StaticClass" | "InstanceClass" | "StaticPrimitive" => {
                    let parameters: Vec<_> = record
                        .tokens
                        .iter()
                        .filter(|t| t.role.starts_with("parameter["))
                        .collect();
                    assert_eq!(parameters.len(), 2);
                    assert!(parameters
                        .iter()
                        .all(|t| t.width == 2 && t.coded != t.native_after_coded));
                }
                "GenericArityOne" | "GenericArityTwo" => {
                    let first_arg = record
                        .tokens
                        .iter()
                        .find(|t| t.role == "parameter[0].generic_argument[0]")
                        .unwrap();
                    assert_eq!(
                        first_arg.coded != first_arg.native_after_coded,
                        name == "GenericArityTwo"
                    );
                    assert!(record
                        .tokens
                        .iter()
                        .filter(|t| t.role == "parameter[1]" || t.role == "parameter[2]")
                        .all(|t| t.coded == t.native_after_coded));
                }
                _ => continue,
            }
            checked.insert(name.to_owned());
        }
        assert_eq!(
            checked,
            [
                "StaticVoid",
                "InstanceVoid",
                "StaticClass",
                "InstanceClass",
                "StaticPrimitive",
                "GenericArityOne",
                "GenericArityTwo"
            ]
            .map(str::to_owned)
            .into_iter()
            .collect()
        );
    }
}

#[test]
fn captured_signature_maps_and_typed_observations_match() {
    let mut changed_memberref_valuetypes = 0;
    let mut changed_methods = 0;
    let mut unchanged_generic_arguments = 0;
    for (family, name) in FAMILIES
        .into_iter()
        .flat_map(|family| CASES.map(|name| (family, name)))
    {
        let (directory, before, after) = fixture(family, name);
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let parsed = crate::pa30::parse(&delta).unwrap();
        let pp = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess).unwrap();
        let changes_rows = |id: u8| {
            pp.cli_map.tables[id as usize]
                .entries
                .iter()
                .any(|entry| entry.source != entry.target)
        };
        assert_eq!(
            changes_rows(table::TYPE_DEF),
            name != "reference-moves",
            "{name}: TypeDef experimental dimension"
        );
        assert_eq!(
            changes_rows(table::TYPE_REF),
            name != "definition-moves",
            "{name}: TypeRef experimental dimension"
        );
        let maps: NativeMaps = read_json(&directory.join("cli-maps.json"));
        let capture: Capture = read_json(&directory.join("capture.json"));
        assert_eq!(maps.schema, 1);
        assert_eq!(maps.dll_sha256, DLL_SHA256);
        assert_eq!(maps.harness_sha256, capture.harness_sha256);
        assert_eq!(maps.stage, "cli-metadata");
        assert!(maps.unchanged_on_return);
        let mut expected_names = BTreeSet::new();
        for (name, map) in [
            ("strings", &pp.cli_map.strings),
            ("user-strings", &pp.cli_map.user_strings),
            ("blob", &pp.cli_map.blob),
            ("guid", &pp.cli_map.guid),
        ] {
            let file = format!("cli-map-heap-{name}.bin");
            assert_eq!(
                rust_pairs(map),
                native_pairs(&verified(&directory, &file, &maps.artifact_sha256[&file])),
                "{name}: native heap map"
            );
            expected_names.insert(file);
        }
        for id in 0..64 {
            let file = format!("cli-map-table-{id:02x}.bin");
            assert_eq!(
                rust_pairs(&pp.cli_map.tables[id]),
                native_pairs(&verified(&directory, &file, &maps.artifact_sha256[&file])),
                "{name}: native table {id:02x}"
            );
            expected_names.insert(file);
        }
        assert_eq!(
            maps.artifact_sha256
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_names
        );
        let observations: Observations = read_json(&directory.join("observations.json"));
        assert_eq!(observations.schema, 1);
        assert_eq!(observations.case, name);
        verified(&directory, "capture.json", &observations.capture_sha256);
        verified(&directory, "cli-maps.json", &observations.cli_maps_sha256);
        let source_metadata =
            parse_cli_metadata_from_pe(&before, CliSchemaFlavor::Classic).unwrap();
        let target = std::fs::read(directory.join("target.bin")).unwrap();
        let target_metadata =
            parse_cli_metadata_from_pe(&target, CliSchemaFlavor::Classic).unwrap();
        let expected_owners: BTreeSet<_> = [table::TYPE_SPEC, table::METHOD_DEF, table::MEMBER_REF]
            .into_iter()
            .flat_map(|table_id| {
                (1..=source_metadata.row_counts[table_id as usize]).map(move |rid| (table_id, rid))
            })
            .collect();
        assert_eq!(observations.records.len(), expected_owners.len());
        assert_eq!(
            observations
                .records
                .iter()
                .map(|r| (r.table_id, r.rid))
                .collect::<BTreeSet<_>>(),
            expected_owners
        );
        for record in observations.records {
            assert_eq!(table_schema(record.table_id).unwrap().name, record.table);
            verify_blob_owner(
                &source_metadata,
                &before,
                record.table_id,
                record.rid,
                record.source_heap_offset,
            );
            verify_blob_owner(
                &target_metadata,
                &target,
                record.table_id,
                record.target_rid,
                record.target_heap_offset,
            );
            let original = hex_bytes(&record.source_signature_hex);
            let native = hex_bytes(&record.native_after_signature_hex);
            assert_eq!(original.len(), record.signature_size);
            assert_eq!(native.len(), record.signature_size);
            assert_eq!(
                source_metadata
                    .blob(&before, BlobHeapOffset::new(record.source_heap_offset))
                    .unwrap(),
                original
            );
            assert_eq!(
                target_metadata
                    .blob(&target, BlobHeapOffset::new(record.target_heap_offset))
                    .unwrap(),
                hex_bytes(&record.target_signature_hex)
            );
            let heap_position = source_metadata.streams.blob.unwrap().file_offset
                + record.source_heap_offset as usize;
            let (length, prefix_width) = read_compressed_u32(&before[heap_position..]).unwrap();
            assert_eq!(length as usize, record.signature_size);
            assert_eq!(heap_position + prefix_width, record.signature_file_offset);
            let range =
                record.signature_file_offset..record.signature_file_offset + record.signature_size;
            assert_eq!(&before[range.clone()], original);
            assert_eq!(&after[range], native);
            for token in record.tokens {
                assert_eq!(
                    read_compressed_u32(&original[token.signature_offset..]).unwrap(),
                    (token.coded, token.width)
                );
                assert_eq!(
                    read_compressed_u32(&native[token.signature_offset..]).unwrap(),
                    (token.native_after_coded, token.width)
                );
                assert_eq!(token.rid, token.coded >> 2);
                assert_eq!(
                    token.table_id,
                    [table::TYPE_DEF, table::TYPE_REF, table::TYPE_SPEC]
                        [(token.coded & 3) as usize]
                );
                assert_eq!(
                    original[token.signature_offset - 1],
                    match token.element.as_str() {
                        "CLASS" => 0x12,
                        "VALUETYPE" => 0x11,
                        _ => panic!("unknown element"),
                    }
                );
                if record.table_id == table::MEMBER_REF
                    && token.element == "VALUETYPE"
                    && token.native_after_coded != token.coded
                {
                    changed_memberref_valuetypes += 1;
                }
                if record.table_id == table::METHOD_DEF && token.native_after_coded != token.coded {
                    changed_methods += 1;
                }
                if token.role.contains("generic_argument")
                    && token.native_after_coded == token.coded
                {
                    unchanged_generic_arguments += 1;
                }
            }
        }
    }
    assert!(
        changed_memberref_valuetypes > 0,
        "MemberRef requires positive native rewrite evidence"
    );
    assert!(changed_methods > 0);
    assert!(unchanged_generic_arguments > 0);
}

#[test]
fn captured_native_signature_metadata_stages_match() {
    for (family, name) in FAMILIES
        .into_iter()
        .flat_map(|family| CASES.map(|name| (family, name)))
    {
        let (directory, before, expected) = fixture(family, name);
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let parsed = crate::pa30::parse(&delta).unwrap();
        let pp = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess).unwrap();
        let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic).unwrap();
        let mut actual = before;
        transform_cli_metadata_with_rva_map(
            &mut actual,
            &metadata,
            &pp.cli_map,
            &pp.preprocess_rift,
        );
        let differences: Vec<_> = actual
            .iter()
            .zip(&expected)
            .enumerate()
            .filter_map(|(offset, (a, b))| (a != b).then_some(offset))
            .collect();
        assert!(
            actual == expected,
            "{name}: metadata stage differs at {} bytes, first offsets {:?}",
            differences.len(),
            &differences[..differences.len().min(16)]
        );
    }
}

#[test]
fn captured_native_signature_complete_apply_matches() {
    for (family, name) in FAMILIES
        .into_iter()
        .flat_map(|family| CASES.map(|name| (family, name)))
    {
        let (directory, _, _) = fixture(family, name);
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let expected = std::fs::read(directory.join("target.bin")).unwrap();
        assert_eq!(
            crate::pa30::apply(&source, &delta).unwrap(),
            expected,
            "{name}: native complete output"
        );
        crate::pa30::pipeline_tests::assert_captured_native_pipeline(&directory);
    }
}
