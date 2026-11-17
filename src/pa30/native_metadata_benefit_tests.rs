//! Controlled native metadata ablation, with decoder-derived reference origins.

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::blob::read_compressed_u32;
use crate::pe::cli::metadata::{parse_cli_metadata_from_pe, CliColumnValue};
use crate::pe::cli::schema::{table, CliSchemaFlavor, HeapKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DLL_SHA256: &str = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(transparent)]
struct SourceFileOffset(usize);

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(transparent)]
struct TargetFileOffset(usize);

#[derive(Deserialize)]
struct Candidate {
    table: String,
    rid: u32,
    target_rid: u32,
    source_file_offset: SourceFileOffset,
    target_file_offset: TargetFileOffset,
    length: usize,
    signature_hex: String,
}

#[derive(Deserialize)]
struct Measurements {
    schema: u32,
    only_changed_actual_header_flag: i64,
    normal_delta_reproduces_baseline: bool,
    identical_source_and_target: bool,
    measurements: BTreeMap<String, Sizes>,
    transformed_source_different_bytes: usize,
    reusable_signature_candidates: Vec<Candidate>,
}

#[derive(Deserialize)]
struct Sizes {
    flags: i64,
    delta_size: usize,
    preprocess_size: usize,
    patch_size: usize,
    delta_sha256: String,
    transformed_source_sha256: String,
}

struct Replay {
    source: Vec<u8>,
    target: Vec<u8>,
    transformed: Vec<u8>,
    decompressed: Vec<u8>,
    origins: Vec<i64>,
    parsed: super::ParsedDelta,
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

fn verified(directory: &Path, name: &str, hash: &str) -> Vec<u8> {
    let bytes = std::fs::read(directory.join(name)).unwrap();
    assert_eq!(digest(&bytes), hash, "{}: {name}", directory.display());
    bytes
}

fn read_rift(bytes: &[u8]) -> RiftTable {
    assert_eq!(bytes.len() % 16, 0);
    RiftTable {
        entries: bytes
            .chunks_exact(16)
            .map(|entry| RiftEntry {
                source: i64::from_le_bytes(entry[..8].try_into().unwrap()),
                target: i64::from_le_bytes(entry[8..].try_into().unwrap()),
            })
            .collect(),
    }
}

fn replay(directory: &Path, sizes: &Sizes, provenance: &Value) -> Replay {
    let capture: Value = read_json(&directory.join("capture.json"));
    assert_eq!(capture["dll_sha256"], DLL_SHA256);
    assert_eq!(
        capture["harness_sha256"],
        provenance["capture_harness_sha256"]
    );
    assert_eq!(capture["uninstrumented_output_equal"], true);
    assert_eq!(capture["decompress_source_unchanged"], true);
    let mode = directory.file_name().unwrap().to_str().unwrap();
    for (file, hash) in provenance["cases"][mode].as_object().unwrap() {
        verified(directory, file, hash.as_str().unwrap());
    }
    for (file, hash) in capture["artifact_sha256"].as_object().unwrap() {
        verified(directory, file, hash.as_str().unwrap());
    }
    let creation: Value = read_json(&directory.join("creation.json"));
    assert_eq!(creation["dll_sha256"], DLL_SHA256);
    assert_eq!(
        creation["harness_sha256"],
        provenance["creation_harness_sha256"]
    );
    assert_eq!(creation["mode"], mode);
    assert_eq!(
        creation["reset_flags"],
        if mode == "normal" { 0 } else { 0x8000 }
    );
    for field in ["create_ok", "apply_ok", "output_equal", "inputs_unchanged"] {
        assert_eq!(creation[field], true);
    }
    assert_eq!(creation["create_error"], 0);
    assert_eq!(creation["apply_error"], 0);
    let source = verified(
        directory,
        "source.bin",
        creation["source_sha256"].as_str().unwrap(),
    );
    let target = verified(
        directory,
        "target.bin",
        creation["target_sha256"].as_str().unwrap(),
    );
    let delta = verified(directory, "delta.pa30", &sizes.delta_sha256);
    assert_eq!(creation["delta_sha256"], sizes.delta_sha256);
    let transformed = verified(
        directory,
        "transformed-source.bin",
        &sizes.transformed_source_sha256,
    );
    let parsed = super::parse(&delta).unwrap();
    assert_eq!(parsed.header.flags, sizes.flags);
    assert_eq!(delta.len(), sizes.delta_size);
    assert_eq!(parsed.preprocess.len(), sizes.preprocess_size);
    assert_eq!(parsed.patch_data.len(), sizes.patch_size);
    // This runs the actual apply path and checks all captured stage buffers,
    // markers, invocation order, copy maps and decompression/output boundaries.
    super::pipeline_tests::assert_captured_native_pipeline(directory);
    let caller = read_rift(&std::fs::read(directory.join("caller-rift.bin")).unwrap());
    let (decompressed, origins) = crate::lzx::decompress_with_copy_source(
        &transformed,
        &parsed.patch_data,
        parsed.header.target_size.try_into().unwrap(),
        Some(&caller),
    )
    .unwrap();
    assert_eq!(
        decompressed,
        std::fs::read(directory.join("decompressed-target.bin")).unwrap()
    );
    assert_eq!(origins.len(), decompressed.len());
    for (target_offset, origin) in origins.iter().copied().enumerate() {
        if origin == -1 {
            continue;
        }
        let source_offset = usize::try_from(origin).expect("origin must be -1 or nonnegative");
        assert!(source_offset < transformed.len());
        assert_eq!(
            decompressed[target_offset], transformed[source_offset],
            "{mode}: reference origin at output{target_offset}"
        );
    }
    Replay {
        source,
        target,
        transformed,
        decompressed,
        origins,
        parsed,
    }
}

fn blob_range(image: &[u8], table_id: u8, rid: u32) -> (usize, usize) {
    let metadata = parse_cli_metadata_from_pe(image, CliSchemaFlavor::Classic).unwrap();
    let row = metadata.table_row_by_id(image, table_id, rid).unwrap();
    let CliColumnValue::Heap {
        kind: HeapKind::Blob,
        offset,
    } = row.column("Signature").unwrap()
    else {
        panic!("signature blob owner");
    };
    let position = metadata.streams.blob.unwrap().file_offset + offset as usize;
    let (size, prefix) = read_compressed_u32(&image[position..]).unwrap();
    (position + prefix, size as usize)
}

fn signature_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_cli_metadata_ablation_and_actual_reference_reuse() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = repository.join("tests/fixtures/atoms/CliSignatureAblationNative");
    let provenance: Value = read_json(&root.join("provenance.json"));
    assert_eq!(provenance["schema"], 1);
    assert_eq!(provenance["dll_sha256"], DLL_SHA256);
    assert_eq!(
        provenance["cases"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["normal", "no-metadata"].into_iter().collect()
    );
    for (file, hash) in provenance["source_sha256"].as_object().unwrap() {
        verified(repository, file, hash.as_str().unwrap());
    }
    let baseline = repository.join(provenance["input_fixture"].as_str().unwrap());
    verified(
        baseline.parent().unwrap(),
        "provenance.json",
        provenance["input_fixture_provenance_sha256"]
            .as_str()
            .unwrap(),
    );
    let measurements: Measurements = serde_json::from_slice(&verified(
        &root,
        "measurements.json",
        provenance["measurements_sha256"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(measurements.schema, 1);
    assert_eq!(measurements.only_changed_actual_header_flag, 0x8000);
    assert!(
        measurements.normal_delta_reproduces_baseline && measurements.identical_source_and_target
    );
    let normal = replay(
        &root.join("normal"),
        &measurements.measurements["normal"],
        &provenance,
    );
    let disabled = replay(
        &root.join("no-metadata"),
        &measurements.measurements["no-metadata"],
        &provenance,
    );
    assert_eq!(normal.source, disabled.source);
    assert_eq!(normal.target, disabled.target);
    assert_eq!(
        normal.source,
        std::fs::read(baseline.join("source.bin")).unwrap()
    );
    assert_eq!(
        normal.target,
        std::fs::read(baseline.join("target.bin")).unwrap()
    );
    assert_eq!(
        std::fs::read(root.join("normal/delta.pa30")).unwrap(),
        std::fs::read(baseline.join("delta.pa30")).unwrap()
    );
    let a = &normal.parsed.header;
    let b = &disabled.parsed.header;
    assert_eq!(a.flags ^ b.flags, 0x8000);
    assert_ne!(a.flags & 0x8000, 0);
    assert_eq!(
        (
            a.version,
            a.target_file_time,
            a.file_type_set,
            a.file_type,
            a.target_size,
            a.hash_alg_id,
            &a.target_hash
        ),
        (
            b.version,
            b.target_file_time,
            b.file_type_set,
            b.file_type,
            b.target_size,
            b.hash_alg_id,
            &b.target_hash
        )
    );
    assert!(a.pa31_extra.is_none() && b.pa31_extra.is_none());
    assert_eq!(normal.transformed.len(), disabled.transformed.len());
    let changed_positions: BTreeSet<_> = normal
        .transformed
        .iter()
        .zip(&disabled.transformed)
        .enumerate()
        .filter_map(|(offset, (a, b))| (a != b).then_some(offset))
        .collect();
    assert_eq!(
        changed_positions.len(),
        measurements.transformed_source_different_bytes
    );
    let summarize = |replay: &Replay| {
        let mut used_changed = BTreeSet::new();
        let mut changed_output_count = 0usize;
        let mut reference_output_count = 0usize;
        for origin in &replay.origins {
            let Ok(position) = usize::try_from(*origin) else {
                continue;
            };
            reference_output_count += 1;
            if changed_positions.contains(&position) {
                changed_output_count += 1;
                used_changed.insert(position);
            }
        }
        json!({ "reference_derived_output_bytes_including_output_backreference_propagation": reference_output_count,
            "reference_derived_output_bytes_from_positions_changed_by_cli_metadata": changed_output_count,
            "distinct_changed_source_positions_reused": used_changed.len(),
            "changed_source_positions_reused": used_changed })
    };
    let mut candidates = Vec::new();
    let mut used_candidate_bytes = 0usize;
    let total_candidate_bytes: usize = measurements
        .reusable_signature_candidates
        .iter()
        .map(|candidate| candidate.length)
        .sum();
    assert_eq!(measurements.reusable_signature_candidates.len(), 3);
    for candidate in measurements.reusable_signature_candidates {
        let table_id = match candidate.table.as_str() {
            "TypeSpec" => table::TYPE_SPEC,
            "MethodDef" => table::METHOD_DEF,
            _ => panic!("unexpected candidate table"),
        };
        let source_offset = candidate.source_file_offset.0;
        let target_offset = candidate.target_file_offset.0;
        assert_eq!(
            blob_range(&normal.source, table_id, candidate.rid),
            (source_offset, candidate.length)
        );
        assert_eq!(
            blob_range(&normal.target, table_id, candidate.target_rid),
            (target_offset, candidate.length)
        );
        let bytes = signature_bytes(&candidate.signature_hex);
        assert_eq!(
            &normal.transformed[source_offset..source_offset + candidate.length],
            bytes
        );
        assert_eq!(
            &normal.target[target_offset..target_offset + candidate.length],
            bytes
        );
        assert_eq!(
            &normal.decompressed[target_offset..target_offset + candidate.length],
            bytes
        );
        let trace = |replay: &Replay| -> Vec<Value> {
            (0..candidate.length).map(|offset| {
            let origin = replay.origins[target_offset + offset];
            let origin = usize::try_from(origin).ok().map(SourceFileOffset);
            json!({ "target_file_offset": TargetFileOffset(target_offset + offset),
                "declared_candidate_source_file_offset": SourceFileOffset(source_offset + offset),
                "actual_reference_origin": origin,
                "uses_declared_candidate_source": origin.is_some_and(|position| position.0 == source_offset+offset) })
        }).collect()
        };
        let normal_trace = trace(&normal);
        used_candidate_bytes += normal_trace
            .iter()
            .filter(|row| row["uses_declared_candidate_source"] == true)
            .count();
        candidates.push(json!({ "table": candidate.table, "rid": candidate.rid, "target_rid": candidate.target_rid,
            "source_file_offset": candidate.source_file_offset, "target_file_offset": candidate.target_file_offset,
            "length": candidate.length, "normal": normal_trace, "no_metadata": trace(&disabled) }));
    }
    assert_eq!(
        used_candidate_bytes, total_candidate_bytes,
        "all three observed signature candidates must reuse their exact source ranges"
    );
    let normal_summary = summarize(&normal);
    assert!(
        normal_summary["reference_derived_output_bytes_from_positions_changed_by_cli_metadata"]
            .as_u64()
            .unwrap()
            > 0
    );
    let report = json!({ "schema": 1,
        "scope": "owned one-pair native creation ablation; actual Rust decoder origins after exact native pipeline replay, including output-backreference propagation; not native copy-instruction tracing",
        "native_creation_sizes": { "normal": { "delta": measurements.measurements["normal"].delta_size, "patch": measurements.measurements["normal"].patch_size }, "no_metadata": { "delta": measurements.measurements["no-metadata"].delta_size, "patch": measurements.measurements["no-metadata"].patch_size } },
        "transformed_source_changed_bytes": changed_positions.len(), "normal": normal_summary,
        "no_metadata": summarize(&disabled), "signature_candidate_byte_origins": candidates });
    eprintln!("native metadata benefit: normal changed-origin output={} ({} distinct source positions), disabled={} ({} distinct), candidate bytes used={used_candidate_bytes}",
        report["normal"]["reference_derived_output_bytes_from_positions_changed_by_cli_metadata"],
        report["normal"]["distinct_changed_source_positions_reused"],
        report["no_metadata"]["reference_derived_output_bytes_from_positions_changed_by_cli_metadata"],
        report["no_metadata"]["distinct_changed_source_positions_reused"]);
    if let Some(output) = std::env::var_os("MSDELTA_PIPELINE_OUTPUT") {
        let output = PathBuf::from(output);
        assert!(output.is_absolute());
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(
            output.join("metadata-benefit.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "research counterfactual using private native captures and prior Rust snapshots"]
fn diagnose_mmi_signature_source_counterfactual() {
    #[derive(Deserialize)]
    struct Input {
        old_rust: PathBuf,
        new_rust: PathBuf,
        native: PathBuf,
        delta: PathBuf,
    }
    let input: Input = read_json(&PathBuf::from(
        std::env::var_os("MSDELTA_MMI_EXPERIMENT").unwrap(),
    ));
    let output = PathBuf::from(std::env::var_os("MSDELTA_PIPELINE_OUTPUT").unwrap());
    assert!(output.is_absolute());
    let snapshot = |directory: &Path, label: &str, phase: &str| {
        let trace: Value = read_json(&directory.join("trace.json"));
        let events: Vec<_> = trace["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["stage"] == label && e["phase"] == phase)
            .collect();
        assert_eq!(events.len(), 1);
        verified(
            directory,
            events[0]["file"].as_str().unwrap(),
            events[0]["sha256"].as_str().unwrap(),
        )
    };
    let native_capture: Value = read_json(&input.native.join("capture.json"));
    assert_eq!(native_capture["dll_sha256"], DLL_SHA256);
    let native = |file: &str| {
        verified(
            &input.native,
            file,
            native_capture["artifact_sha256"][file].as_str().unwrap(),
        )
    };
    let sources = [
        snapshot(&input.old_rust, "TransformedSource", "after"),
        snapshot(&input.new_rust, "TransformedSource", "after"),
        native("transformed-source.bin"),
    ];
    let maps = [
        snapshot(&input.old_rust, "CallerRift", "after"),
        snapshot(&input.new_rust, "CallerRift", "after"),
        native("caller-rift.bin"),
    ];
    assert_eq!(maps[0], maps[2]);
    assert_eq!(maps[1], maps[2]);
    for (label, phase, artifact) in [
        ("PatchRift", "after", "patch-rift.bin"),
        ("MergedRift", "before-sort", "merged-rift.bin"),
    ] {
        assert_eq!(snapshot(&input.old_rust, label, phase), native(artifact));
        assert_eq!(snapshot(&input.new_rust, label, phase), native(artifact));
    }
    let delta = std::fs::read(&input.delta).unwrap();
    let parsed = super::parse(&delta).unwrap();
    let expected = native("decompressed-target.bin");
    let names = ["old", "new", "native"];
    let mut observations = Vec::new();
    let mut decoded = Vec::new();
    let mut all_origins = Vec::new();
    for (source_index, source) in sources.iter().enumerate() {
        let mut result = None;
        for (map_index, map) in maps.iter().enumerate() {
            let (bytes, origins) = crate::lzx::decompress_with_copy_source(
                source,
                &parsed.patch_data,
                parsed.header.target_size as usize,
                Some(&read_rift(map)),
            )
            .unwrap();
            if let Some((prior_bytes, prior_origins)) = &result {
                assert_eq!(&bytes, prior_bytes);
                assert_eq!(&origins, prior_origins);
            }
            let wrong = bytes.iter().zip(&expected).filter(|(a, b)| a != b).count();
            observations.push(json!({ "source": names[source_index], "map": names[map_index], "wrong_output_bytes": wrong, "output_sha256": digest(&bytes) }));
            result = Some((bytes, origins));
        }
        let (bytes, origins) = result.unwrap();
        decoded.push(bytes);
        all_origins.push(origins);
    }
    assert_eq!(decoded[0], snapshot(&input.old_rust, "Decompress", "after"));
    assert_eq!(decoded[1], snapshot(&input.new_rust, "Decompress", "after"));
    assert_eq!(decoded[2], expected);
    assert_eq!(all_origins[0], all_origins[1]);
    assert_eq!(all_origins[1], all_origins[2]);
    let changed_source: Vec<_> = sources[0].iter().zip(&sources[1]).enumerate().filter(|(_, (old,new))| old != new).map(|(offset,(old,new))| json!({"source_file_offset":offset,"old":old,"new":new,"native":sources[2][offset]})).collect();
    let changed_output: Vec<_> = decoded[0].iter().zip(&decoded[1]).enumerate().filter_map(|(offset,(old,new))| {
        if old == new { return None; }
        let source_origin = usize::try_from(all_origins[1][offset]).expect("changed output has reference origin");
        assert_eq!(*old, sources[0][source_origin]); assert_eq!(*new, sources[1][source_origin]); assert_eq!(expected[offset], sources[2][source_origin]);
        Some(json!({"target_file_offset":offset,"old":old,"new":new,"native":expected[offset],"source_origin":source_origin,"source_old":sources[0][source_origin],"source_new":sources[1][source_origin],"source_native":sources[2][source_origin]}))
    }).collect();
    let report = json!({ "schema":1, "scope":"counterfactual decoded original patch with each captured old/new/native source and each independently captured old/new/native caller map; all maps identical; reference origins include output-backreference propagation", "source_sha256":sources.iter().map(|bytes|digest(bytes)).collect::<Vec<_>>(), "cases":observations, "changed_source":changed_source,"changed_output":changed_output });
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(
        output.join("mmi-source-counterfactual.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!("{}", report["changed_output"]);
}
