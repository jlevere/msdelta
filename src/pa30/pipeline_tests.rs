//! Opt-in snapshots of the production apply path for native boundary comparison.

use super::{apply_impl, parse, parse_pe_preprocess};
use crate::lzx::rift::RiftTable;
use crate::pe::parse::PeInfo;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

enum Event {
    Buffer {
        stage: String,
        phase: String,
        bytes: Vec<u8>,
        marker: Option<Vec<u8>>,
    },
    Rift {
        stage: String,
        phase: String,
        entries: Vec<(i64, i64)>,
    },
}

thread_local! {
    static ACTIVE: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
}

pub(crate) fn record_buffer(stage: &str, phase: &str, bytes: &[u8], marker: Option<&[u8]>) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(events) = active {
            events.push(Event::Buffer {
                stage: stage.into(),
                phase: phase.into(),
                bytes: bytes.to_vec(),
                marker: marker.map(<[u8]>::to_vec),
            });
        }
    });
}

pub(crate) fn record_rift(stage: &str, phase: &str, rift: &RiftTable) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(events) = active {
            events.push(Event::Rift {
                stage: stage.into(),
                phase: phase.into(),
                entries: rift
                    .entries
                    .iter()
                    .map(|entry| (entry.source, entry.target))
                    .collect(),
            });
        }
    });
}

struct Scope;

impl Scope {
    fn start() -> Self {
        ACTIVE.with_borrow_mut(|active| {
            assert!(active.is_none(), "nested pipeline capture");
            *active = Some(Vec::new());
        });
        Self
    }

    fn finish(self) -> Vec<Event> {
        ACTIVE.with_borrow_mut(|active| active.take().unwrap())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|active| *active = None);
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn output_root() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("MSDELTA_PIPELINE_OUTPUT")
            .expect("set MSDELTA_PIPELINE_OUTPUT to a research output directory"),
    );
    assert!(path.is_absolute(), "research output path must be absolute");
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn rift_json(rift: &RiftTable) -> Value {
    json!(rift
        .entries
        .iter()
        .map(|entry| (entry.source, entry.target))
        .collect::<Vec<_>>())
}

fn classify(source: &[u8], delta: &[u8]) -> Value {
    let mut result = json!({ "source_size": source.len(), "delta_size": delta.len(), "source_sha256": digest(source), "delta_sha256": digest(delta) });
    if let Ok(parsed) = parse(delta) {
        result["header"] = json!({ "format": format!("{:?}", parsed.header.version), "file_type_set": parsed.header.file_type_set, "file_type": parsed.header.file_type, "flags": parsed.header.flags, "target_size": parsed.header.target_size, "hash_algorithm": parsed.header.hash_alg_id, "preprocess_size": parsed.preprocess.len(), "patch_size": parsed.patch_data.len() });
        if !parsed.preprocess.is_empty() {
            match parse_pe_preprocess(&parsed.preprocess) {
                Ok(pp) => {
                    result["preprocess"] = json!({ "target_image_base": pp.target_info.image_base, "target_timestamp": pp.target_info.time_date_stamp, "target_checksum": pp.target_info.checksum, "has_managed_cli_state": pp.has_managed_cli_state(), "preprocess_rift": rift_json(&pp.preprocess_rift), "target_section_rift": rift_json(&pp.target_info.target_rva_to_file_offset) })
                }
                Err(error) => result["preprocess_error"] = json!(error.to_string()),
            }
        }
    }
    match PeInfo::parse_lenient(source) {
        Ok(pe) => {
            result["pe"] = json!({ "machine": format!("{:?}", pe.machine), "machine_raw": pe.machine.raw(), "is_managed": crate::pe::transform::is_managed_pe(source), "image_base": pe.image_base, "image_size": pe.size_of_image, "timestamp": pe.timestamp, "checksum": pe.checksum, "data_directories": pe.data_directories, "sections": pe.sections.iter().map(|section| json!({ "name": section.name, "rva": section.virtual_address, "virtual_size": section.virtual_size, "raw_offset": section.raw_offset, "raw_size": section.raw_size, "characteristics": section.characteristics })).collect::<Vec<_>>() });
        }
        Err(error) => result["pe_error"] = json!(error.to_string()),
    }
    result
}

#[test]
#[ignore = "requires private local corpora and explicit research output directory"]
fn classify_pe_corpora() {
    let mut cases = Vec::new();
    for corpus in ["pe-fixtures-bulk", "pe-fixtures-managed"] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("notes")
            .join(corpus);
        let manifest = std::fs::read_to_string(root.join("manifest.csv")).unwrap();
        for row in manifest.lines() {
            let fields: Vec<_> = row.split(',').collect();
            assert!(fields.len() >= 2);
            let case = root.join(fields[0]);
            let source_path = case.join("base.bin");
            let delta_path = case.join("forward.delta");
            let source = std::fs::read(&source_path).unwrap();
            let delta = std::fs::read(&delta_path).unwrap();
            let mut metadata = classify(&source, &delta);
            metadata["corpus"] = json!(corpus);
            metadata["id"] = json!(fields[0]);
            metadata["source"] = json!(source_path);
            metadata["delta"] = json!(delta_path);
            metadata["expected_sha256"] = json!(fields[1]);
            match apply_impl(&source, &delta, false) {
                Ok(bytes) => {
                    let hash = digest(&bytes);
                    metadata["outcome"] = json!(if hash == fields[1] {
                        "exact"
                    } else {
                        "mismatch"
                    });
                    metadata["actual_sha256"] = json!(hash);
                }
                Err(error) => {
                    metadata["outcome"] = json!("error");
                    metadata["error"] = json!(error.to_string());
                }
            }
            cases.push(metadata);
        }
    }
    write_json(
        &output_root().join("corpus-classification.json"),
        &json!({ "schema": 1, "claim_scope": "local corpus outcomes and structural metadata; causes unclassified until native boundary comparison", "cases": cases }),
    );
}

#[derive(Deserialize)]
struct Input {
    id: String,
    source: PathBuf,
    delta: PathBuf,
    expected_sha256: String,
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn source_fingerprints() -> BTreeMap<String, String> {
    fn walk(root: &Path, directory: &Path, hashes: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, hashes);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                hashes.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    digest(&std::fs::read(&path).unwrap()),
                );
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hashes = BTreeMap::new();
    walk(root, &root.join("src"), &mut hashes);
    hashes
}

#[test]
#[ignore = "requires explicit input manifest and research output directory"]
fn trace_production_pe_pipeline() {
    let inputs = std::env::var_os("MSDELTA_PIPELINE_INPUTS")
        .expect("set MSDELTA_PIPELINE_INPUTS to a JSON array of input cases");
    let inputs: Vec<Input> = serde_json::from_slice(&std::fs::read(inputs).unwrap()).unwrap();
    assert!(!inputs.is_empty());
    let output_root = output_root();
    let fingerprints = source_fingerprints();
    for input in inputs {
        let source = std::fs::read(&input.source).unwrap();
        let delta = std::fs::read(&input.delta).unwrap();
        let scope = Scope::start();
        let applied = apply_impl(&source, &delta, false);
        let events = scope.finish();
        assert!(
            !events.is_empty(),
            "production pipeline hooks missing for {}",
            input.id
        );
        let output = output_root.join(safe_name(&input.id));
        std::fs::create_dir_all(&output).unwrap();
        let mut index = Vec::new();
        for (ordinal, event) in events.into_iter().enumerate() {
            match event {
                Event::Buffer {
                    stage,
                    phase,
                    bytes,
                    marker,
                } => {
                    let file = format!(
                        "{ordinal:03}-{}-{}.bin",
                        safe_name(&stage),
                        safe_name(&phase)
                    );
                    std::fs::write(output.join(&file), &bytes).unwrap();
                    let mut record = json!({ "kind": "buffer", "ordinal": ordinal, "stage": stage, "phase": phase, "file": file, "size": bytes.len(), "sha256": digest(&bytes) });
                    if let Some(marker) = marker {
                        let file = format!("{ordinal:03}-marker.bin");
                        std::fs::write(output.join(&file), &marker).unwrap();
                        record["marker"] = json!({ "file": file, "size": marker.len(), "sha256": digest(&marker) });
                    }
                    index.push(record);
                }
                Event::Rift {
                    stage,
                    phase,
                    entries,
                } => {
                    let file = format!(
                        "{ordinal:03}-{}-{}.rift",
                        safe_name(&stage),
                        safe_name(&phase)
                    );
                    let bytes: Vec<_> = entries
                        .iter()
                        .flat_map(|(source, target)| {
                            source.to_le_bytes().into_iter().chain(target.to_le_bytes())
                        })
                        .collect();
                    std::fs::write(output.join(&file), &bytes).unwrap();
                    index.push(json!({ "kind": "rift", "ordinal": ordinal, "stage": stage, "phase": phase, "file": file, "sha256": digest(&bytes), "entries": entries }));
                }
            }
        }
        let outcome = match applied {
            Ok(bytes) => {
                std::fs::write(output.join("applied.bin"), &bytes).unwrap();
                json!({ "ok": true, "sha256": digest(&bytes), "expected_equal": digest(&bytes) == input.expected_sha256 })
            }
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        };
        write_json(
            &output.join("trace.json"),
            &json!({ "schema": 1, "id": input.id, "source": input.source, "delta": input.delta, "source_sha256": digest(&source), "delta_sha256": digest(&delta), "expected_sha256": input.expected_sha256, "rust_source_sha256": fingerprints, "verification": "target hash bypassed to observe reconstruction; source integrity remains enforced", "outcome": outcome, "events": index }),
        );
    }
}

#[derive(Deserialize)]
struct NativeStages {
    schema: u32,
    dll_sha256: String,
    stages: Vec<NativeStage>,
}

#[derive(Deserialize)]
struct NativeStage {
    id: usize,
    name: String,
    artifact_sha256: BTreeMap<String, String>,
    enter_order: usize,
    leave_order: usize,
    has_markers: bool,
}

fn native_stage_bytes(directory: &Path, stage: &NativeStage, suffix: &str) -> Vec<u8> {
    let name = format!("stage-{:02}-{}-{suffix}.bin", stage.id, stage.name);
    let bytes = std::fs::read(directory.join(&name)).unwrap();
    assert_eq!(digest(&bytes), stage.artifact_sha256[&name]);
    bytes
}

fn byte_difference(actual: &[u8], expected: &[u8]) -> Value {
    let offsets: Vec<_> = actual
        .iter()
        .zip(expected)
        .enumerate()
        .filter_map(|(offset, (a, b))| (a != b).then_some(offset))
        .collect();
    json!({ "equal": actual == expected, "actual_size": actual.len(), "expected_size": expected.len(), "different_byte_count": offsets.len() + actual.len().abs_diff(expected.len()), "first_different_offsets": &offsets[..offsets.len().min(16)] })
}

#[test]
fn owned_native_pe_pipeline_boundaries_match() {
    #[derive(Deserialize)]
    struct Provenance {
        schema: u32,
        dll_sha256: String,
        harness_sha256: String,
        cases: BTreeMap<String, BTreeMap<String, String>>,
    }
    #[derive(Deserialize)]
    struct Capture {
        dll_sha256: String,
        harness_sha256: String,
        uninstrumented_output_equal: bool,
        decompress_source_unchanged: bool,
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/PePipelineNative");
    let provenance: Provenance =
        serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance.schema, 1);
    assert_eq!(
        provenance.dll_sha256,
        "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
    );
    let names = [
        "x86-backed-executable",
        "x86-header-gap",
        "x86-raw-padding",
        "x86-virtual-tail-file-alias",
        "x86-virtual-tail-outside-file",
    ];
    assert_eq!(provenance.cases.len(), names.len());
    for name in names {
        let directory = root.join(name);
        for (file, expected) in &provenance.cases[name] {
            assert_eq!(
                digest(&std::fs::read(directory.join(file)).unwrap()),
                *expected,
                "{name}/{file}"
            );
        }
        let capture: Capture =
            serde_json::from_slice(&std::fs::read(directory.join("capture.json")).unwrap())
                .unwrap();
        assert_eq!(capture.dll_sha256, provenance.dll_sha256);
        assert_eq!(capture.harness_sha256, provenance.harness_sha256);
        assert!(capture.uninstrumented_output_equal && capture.decompress_source_unchanged);
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let target = std::fs::read(directory.join("target.bin")).unwrap();
        let header = super::parse_header(&delta).unwrap();
        assert_eq!(header.file_type, 2);
        assert_eq!(header.flags, 0xe1fe);
        let scope = Scope::start();
        let actual = apply_impl(&source, &delta, false);
        let events = scope.finish();
        assert_native_stages(&directory, &events);
        assert_native_boundaries(&directory, &events);
        assert_eq!(actual.unwrap(), target, "{name}: complete output");
        assert_eq!(
            super::apply(&source, &delta).unwrap(),
            target,
            "{name}: verified output"
        );
    }
}

fn assert_native_boundaries(directory: &Path, events: &[Event]) {
    let name = directory.file_name().unwrap().to_string_lossy();
    for (label, phase, artifact) in [
        ("TransformedSource", "after", "transformed-source.bin"),
        ("Decompress", "after", "decompressed-target.bin"),
        ("Apply", "after", "target.bin"),
    ] {
        let snapshots: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Buffer {
                    stage,
                    phase: event_phase,
                    bytes,
                    ..
                } if stage == label && event_phase == phase => Some(bytes),
                _ => None,
            })
            .collect();
        assert_eq!(snapshots.len(), 1, "{name}: {label}/{phase}");
        let expected = std::fs::read(directory.join(artifact)).unwrap();
        assert!(
            snapshots[0] == &expected,
            "{name}: {label}/{phase}: {}",
            byte_difference(snapshots[0], &expected)
        );
    }
    for (label, phase, artifact) in [
        ("CallerRift", "after", "caller-rift.bin"),
        ("PatchRift", "after", "patch-rift.bin"),
        ("MergedRift", "before-sort", "merged-rift.bin"),
    ] {
        let snapshots: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Rift {
                    stage,
                    phase: event_phase,
                    entries,
                } if stage == label && event_phase == phase => Some(entries),
                _ => None,
            })
            .collect();
        assert_eq!(snapshots.len(), 1, "{name}: {label}/{phase}");
        let bytes: Vec<_> = snapshots[0]
            .iter()
            .flat_map(|(source, target)| {
                source.to_le_bytes().into_iter().chain(target.to_le_bytes())
            })
            .collect();
        assert_eq!(
            bytes,
            std::fs::read(directory.join(artifact)).unwrap(),
            "{name}: {label}/{phase}"
        );
    }
}

pub(crate) fn assert_captured_native_pipeline(directory: &Path) {
    let source = std::fs::read(directory.join("source.bin")).unwrap();
    let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
    let scope = Scope::start();
    let actual = super::apply(&source, &delta);
    let events = scope.finish();
    assert_native_stages(directory, &events);
    assert_native_boundaries(directory, &events);
    assert_eq!(
        actual.unwrap(),
        std::fs::read(directory.join("target.bin")).unwrap()
    );
}

fn native_stage_label(name: &str) -> &str {
    match name {
        "mark-non-exe" => "MarkNonExe",
        "imports" => "TransformImports",
        "exports" => "TransformExports",
        "resources" => "TransformResources",
        "relocations" => "TransformRelocations",
        "inferred-i386" => "InferredRelocationsI386",
        "cli-disasm" => "TransformCliDisasm",
        "cli-metadata" => "TransformCliMetadata",
        "lock-source" => "SmashLockPrefixesX86",
        "jmps-i386" => "RelativeJmpsX86",
        "calls-i386" => "RelativeCallsX86",
        "disasm-amd64" => "DisasmX64",
        "pdata-amd64" => "PdataX64",
        _ => panic!("unmapped native stage {name}"),
    }
}

fn assert_native_stages(directory: &Path, events: &[Event]) {
    let stages: NativeStages =
        serde_json::from_slice(&std::fs::read(directory.join("stages.json")).unwrap()).unwrap();
    assert_eq!(stages.schema, 1);
    let mut observed_order = Vec::new();
    let mut expected_order = Vec::new();
    for stage in &stages.stages {
        let label = native_stage_label(&stage.name);
        for (phase, native_order) in [("before", stage.enter_order), ("after", stage.leave_order)] {
            let snapshots: Vec<_> = events
                .iter()
                .enumerate()
                .filter_map(|(index, event)| match event {
                    Event::Buffer {
                        stage,
                        phase: event_phase,
                        bytes,
                        marker,
                    } if stage == label && event_phase == phase => Some((index, bytes, marker)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                snapshots.len(),
                1,
                "{}: {label}/{phase}",
                directory.display()
            );
            let (index, bytes, marker) = snapshots[0];
            let expected = native_stage_bytes(directory, stage, phase);
            assert!(
                bytes == &expected,
                "{}: {label}/{phase}: {}",
                directory.display(),
                byte_difference(bytes, &expected)
            );
            if stage.has_markers {
                let expected = native_stage_bytes(directory, stage, &format!("marker-{phase}"));
                let actual = marker
                    .as_ref()
                    .expect("native marker stage must expose Rust marker");
                assert!(
                    actual == &expected,
                    "{}: {label}/marker-{phase}: {}",
                    directory.display(),
                    byte_difference(actual, &expected)
                );
            }
            observed_order.push((index, label, phase));
            expected_order.push((native_order, label, phase));
        }
    }
    observed_order.sort_by_key(|entry| entry.0);
    expected_order.sort_by_key(|entry| entry.0);
    assert_eq!(
        observed_order
            .iter()
            .map(|(_, label, phase)| (*label, *phase))
            .collect::<Vec<_>>(),
        expected_order
            .iter()
            .map(|(_, label, phase)| (*label, *phase))
            .collect::<Vec<_>>(),
        "{}: native leaf invocation order",
        directory.display()
    );
}

fn verified_native_directory(family: &str, name: &str, expected_names: &[&str]) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/atoms")
        .join(family);
    let provenance: Value =
        serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["schema"], 1);
    assert_eq!(
        provenance["dll_sha256"],
        "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
    );
    let cases = provenance["cases"].as_object().unwrap();
    assert_eq!(cases.len(), expected_names.len());
    for expected_name in expected_names {
        assert!(cases.contains_key(*expected_name));
    }
    let directory = root.join(name);
    for (file, hash) in cases[name].as_object().unwrap() {
        assert_eq!(
            digest(&std::fs::read(directory.join(file)).unwrap()),
            hash.as_str().unwrap(),
            "{name}/{file}"
        );
    }
    let capture: Value =
        serde_json::from_slice(&std::fs::read(directory.join("capture.json")).unwrap()).unwrap();
    assert_eq!(capture["dll_sha256"], provenance["dll_sha256"]);
    assert_eq!(capture["harness_sha256"], provenance["harness_sha256"]);
    assert_eq!(capture["uninstrumented_output_equal"], true);
    assert_eq!(capture["decompress_source_unchanged"], true);
    directory
}

const EXISTING_NATIVE_CASES: &[&str] = &[
    "cli-interface-impl",
    "cli-constructor-token-boundary",
    "cli-constructor-user-string-boundary",
    "cli-static-constructor-token-boundary",
    "x64-rva-moved",
    "x64-rva-preserved",
];

#[test]
fn owned_native_additional_pe_pipeline_stages_and_boundaries_match() {
    for (family, name, names) in [
        (
            "PePipelineExistingNative",
            "x64-rva-moved",
            EXISTING_NATIVE_CASES,
        ),
        (
            "PePipelineExistingNative",
            "x64-rva-preserved",
            EXISTING_NATIVE_CASES,
        ),
        (
            "PePipelineImportNative",
            "x86-import-name-beyond-section",
            &["x86-import-name-beyond-section"][..],
        ),
        (
            "PePipelineX64Native",
            "x64-rip-unwind-relocations",
            &["x64-rip-unwind-relocations"][..],
        ),
    ] {
        let directory = verified_native_directory(family, name, names);
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let scope = Scope::start();
        let actual = super::apply(&source, &delta);
        let events = scope.finish();
        assert_native_stages(&directory, &events);
        assert_native_boundaries(&directory, &events);
        assert_eq!(
            actual.unwrap(),
            std::fs::read(directory.join("target.bin")).unwrap()
        );
        if name == "x64-rip-unwind-relocations" {
            let stages: NativeStages =
                serde_json::from_slice(&std::fs::read(directory.join("stages.json")).unwrap())
                    .unwrap();
            for label in ["relocations", "disasm-amd64", "pdata-amd64"] {
                let stage = stages
                    .stages
                    .iter()
                    .find(|stage| stage.name == label)
                    .unwrap();
                assert_ne!(
                    native_stage_bytes(&directory, stage, "before"),
                    native_stage_bytes(&directory, stage, "after"),
                    "native {label} must exercise a rewrite"
                );
            }
        }
    }
}

#[test]
fn owned_native_managed_pipeline_matches() {
    for name in &EXISTING_NATIVE_CASES[..4] {
        let directory =
            verified_native_directory("PePipelineExistingNative", name, EXISTING_NATIVE_CASES);
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let scope = Scope::start();
        let actual = super::apply(&source, &delta);
        let events = scope.finish();
        assert_native_stages(&directory, &events);
        assert_native_boundaries(&directory, &events);
        assert_eq!(
            actual.unwrap(),
            std::fs::read(directory.join("target.bin")).unwrap()
        );
    }
}

#[test]
fn owned_native_cli_disasm_uses_uniform_tokens_and_native_method_bound() {
    use crate::pe::cli::{
        disasm, metadata, method,
        schema::{table, CliSchemaFlavor},
        tokens::StringsHeapOffset,
    };
    #[derive(Deserialize)]
    struct Provenance {
        schema: u32,
        dll_sha256: String,
        cases: BTreeMap<String, BTreeMap<String, String>>,
    }
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/PePipelineExistingNative");
    let provenance: Provenance =
        serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance.schema, 1);
    assert_eq!(
        provenance.dll_sha256,
        "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
    );
    let mut changed_constructors = 0;
    let mut remappable_final_methods_left_unchanged = 0;
    for name in [
        "cli-interface-impl",
        "cli-constructor-token-boundary",
        "cli-constructor-user-string-boundary",
        "cli-static-constructor-token-boundary",
    ] {
        let directory = root.join(name);
        for (file, expected) in &provenance.cases[name] {
            assert_eq!(
                digest(&std::fs::read(directory.join(file)).unwrap()),
                *expected,
                "{name}/{file}"
            );
        }
        let source = std::fs::read(directory.join("source.bin")).unwrap();
        let delta = std::fs::read(directory.join("delta.pa30")).unwrap();
        let parsed = parse(&delta).unwrap();
        let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
        let pe = PeInfo::parse_lenient(&source).unwrap();
        let metadata =
            metadata::parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic).unwrap();
        let stages: NativeStages =
            serde_json::from_slice(&std::fs::read(directory.join("stages.json")).unwrap()).unwrap();
        assert_eq!(stages.dll_sha256, provenance.dll_sha256);
        let stage = stages
            .stages
            .iter()
            .find(|stage| stage.name == "cli-disasm")
            .unwrap();
        let before = native_stage_bytes(&directory, stage, "before");
        let expected = native_stage_bytes(&directory, stage, "after");
        let mut actual = before.clone();
        disasm::transform_cli_disasm_tokens(&mut actual, &pe, &metadata, &pp.cli_map);
        assert!(
            actual == expected,
            "{name}: isolated native CLI disasm: {}",
            byte_difference(&actual, &expected)
        );
        for body in method::cli_method_bodies(&before, &pe, &metadata) {
            let start = body.file_offset + body.header_size;
            let end = start + body.code_size;
            let row = metadata
                .table_row_by_id(&before, table::METHOD_DEF, body.rid)
                .unwrap();
            let metadata::CliColumnValue::Heap { offset, .. } = row.column("Name").unwrap() else {
                panic!("method name must be a string heap index")
            };
            let method_name = metadata
                .strings(&before, StringsHeapOffset::new(offset))
                .unwrap();
            if body.rid == metadata.row_counts[table::METHOD_DEF as usize] {
                assert_eq!(
                    &before[start..end],
                    &expected[start..end],
                    "{name}: native final method"
                );
                let mut counterfactual = before[start..end].to_vec();
                disasm::transform_il_tokens(&mut counterfactual, &pp.cli_map);
                if counterfactual != before[start..end] {
                    remappable_final_methods_left_unchanged += 1;
                }
            } else if matches!(method_name, ".ctor" | ".cctor")
                && before[start..end] != expected[start..end]
            {
                changed_constructors += 1;
            }
        }
    }
    assert!(
        changed_constructors > 0,
        "native constructors inside the walked range must exercise token rewrites"
    );
    assert!(
        remappable_final_methods_left_unchanged > 0,
        "native final-row exclusion must differ from a token no-op"
    );
}

#[test]
#[ignore = "counterfactual isolation experiment requiring native research captures"]
fn replay_native_cli_boundaries() {
    use crate::pe::cli::{disasm, metadata, metadata_transform, schema::CliSchemaFlavor};
    let inputs = std::env::var_os("MSDELTA_PIPELINE_INPUTS").expect("set MSDELTA_PIPELINE_INPUTS");
    let inputs: Vec<Input> = serde_json::from_slice(&std::fs::read(inputs).unwrap()).unwrap();
    let native_root = PathBuf::from(
        std::env::var_os("MSDELTA_PIPELINE_NATIVE").expect("set MSDELTA_PIPELINE_NATIVE"),
    );
    let output = output_root();
    let mut results = Vec::new();
    for input in inputs {
        let source = std::fs::read(&input.source).unwrap();
        if !crate::pe::transform::is_managed_pe(&source) {
            continue;
        }
        let delta = std::fs::read(&input.delta).unwrap();
        let parsed = parse(&delta).unwrap();
        let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
        let pe = PeInfo::parse_lenient(&source).unwrap();
        let metadata =
            metadata::parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic).unwrap();
        let directory = native_root.join(&input.id);
        assert_eq!(std::fs::read(directory.join("source.bin")).unwrap(), source);
        let stages: NativeStages =
            serde_json::from_slice(&std::fs::read(directory.join("stages.json")).unwrap()).unwrap();
        assert_eq!(stages.schema, 1);
        assert_eq!(
            stages.dll_sha256,
            "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
        );
        let case_output = output.join(safe_name(&input.id));
        std::fs::create_dir_all(&case_output).unwrap();
        let mut observations = Vec::new();
        for name in ["cli-disasm", "cli-metadata"] {
            let stage = stages
                .stages
                .iter()
                .find(|stage| stage.name == name)
                .unwrap();
            let before = native_stage_bytes(&directory, stage, "before");
            let expected = native_stage_bytes(&directory, stage, "after");
            let mut actual = before.clone();
            if name == "cli-disasm" {
                disasm::transform_cli_disasm_tokens(&mut actual, &pe, &metadata, &pp.cli_map);
            } else {
                metadata_transform::transform_cli_metadata_with_rva_map(
                    &mut actual,
                    &metadata,
                    &pp.cli_map,
                    &pp.preprocess_rift,
                );
            }
            std::fs::write(
                case_output.join(format!("{name}-isolated-rust-after.bin")),
                &actual,
            )
            .unwrap();
            let mut detail = json!({});
            if name == "cli-disasm" {
                let mut uniform = before.clone();
                let mut excluding_last = before.clone();
                let mut methods = Vec::new();
                let bodies = crate::pe::cli::method::cli_method_bodies(&before, &pe, &metadata);
                let last_rid =
                    metadata.row_counts[crate::pe::cli::schema::table::METHOD_DEF as usize];
                for body in &bodies {
                    let start = body.file_offset + body.header_size;
                    let end = start + body.code_size;
                    disasm::transform_il_tokens(&mut uniform[start..end], &pp.cli_map);
                    if body.rid < last_rid {
                        disasm::transform_il_tokens(&mut excluding_last[start..end], &pp.cli_map);
                    }
                    if actual[start..end] != expected[start..end] {
                        let method_name = metadata
                            .table_row_by_id(
                                &before,
                                crate::pe::cli::schema::table::METHOD_DEF,
                                body.rid,
                            )
                            .ok()
                            .and_then(|row| row.column("Name").ok())
                            .and_then(|column| match column {
                                metadata::CliColumnValue::Heap { offset, .. } => metadata
                                    .strings(
                                        &before,
                                        crate::pe::cli::tokens::StringsHeapOffset::new(offset),
                                    )
                                    .ok(),
                                _ => None,
                            });
                        methods.push(json!({ "rid": body.rid, "name": method_name, "rva": body.rva, "file_offset": body.file_offset, "code_size": body.code_size, "difference": byte_difference(&actual[start..end], &expected[start..end]) }));
                    }
                }
                std::fs::write(
                    case_output.join("cli-disasm-uniform-token-map.bin"),
                    &uniform,
                )
                .unwrap();
                detail["uniform_token_map_counterfactual"] = byte_difference(&uniform, &expected);
                detail["uniform_excluding_last_method_counterfactual"] =
                    byte_difference(&excluding_last, &expected);
                detail["method_def_row_count"] = json!(last_rid);
                detail["uniform_residual_methods"] = json!(bodies.iter().filter_map(|body| {
                    let start = body.file_offset + body.header_size;
                    let end = start + body.code_size;
                    (uniform[start..end] != expected[start..end]).then(|| json!({ "rid": body.rid, "rva": body.rva, "file_offset": body.file_offset, "code_size": body.code_size, "difference": byte_difference(&uniform[start..end], &expected[start..end]) }))
                }).collect::<Vec<_>>());
                detail["methods_with_code_differences"] = json!(methods);
            } else {
                let streams = [
                    ("tables", Some(metadata.streams.tables)),
                    ("blob", metadata.streams.blob),
                    ("strings", metadata.streams.strings),
                    ("user_strings", metadata.streams.user_strings),
                    ("guid", metadata.streams.guid),
                ];
                let mut regions: BTreeMap<&str, usize> = BTreeMap::new();
                for (offset, (a, b)) in actual.iter().zip(&expected).enumerate() {
                    if a == b {
                        continue;
                    }
                    let region = streams
                        .iter()
                        .find(|(_, stream)| {
                            stream.is_some_and(|stream| {
                                (stream.file_offset..stream.file_offset + stream.size as usize)
                                    .contains(&offset)
                            })
                        })
                        .map_or("outside_metadata_streams", |(name, _)| *name);
                    *regions.entry(region).or_default() += 1;
                }
                detail["mismatch_regions"] = json!(regions);
            }
            observations.push(json!({ "stage": name, "input_sha256": digest(&before), "native_output_sha256": digest(&expected), "rust_output_sha256": digest(&actual), "difference": byte_difference(&actual, &expected), "detail": detail }));
        }
        let disasm_stage = stages
            .stages
            .iter()
            .find(|stage| stage.name == "cli-disasm")
            .unwrap();
        let metadata_stage = stages
            .stages
            .iter()
            .find(|stage| stage.name == "cli-metadata")
            .unwrap();
        let mut chain = native_stage_bytes(&directory, disasm_stage, "before");
        super::apply_classic_cli_source_transforms(
            &mut chain,
            &pe,
            &metadata,
            &pp.cli_map,
            &pp.preprocess_rift,
            parsed.header.flags as u64,
        );
        let expected = native_stage_bytes(&directory, metadata_stage, "after");
        std::fs::write(case_output.join("cli-chain-rust-after.bin"), &chain).unwrap();
        results.push(json!({ "id": input.id, "isolated_stages": observations, "chain_difference": byte_difference(&chain, &expected) }));
    }
    assert!(!results.is_empty());
    write_json(
        &output.join("cli-isolation.json"),
        &json!({ "schema": 1, "scope": "counterfactual: Rust CLI functions on native captured input states; not the production pipeline order", "rust_source_sha256": source_fingerprints(), "cases": results }),
    );
}
