//! Native reverse-delta observations, independent of the Rust reverse encoder.

use super::{apply_impl, parse_header, FormatVersion};
use crate::bitstream::BitReader;
use crate::lzx::rift::{IntFormat, RiftTable};
use crate::Error;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DLL_SHA256: &str = "b2abf7125b94c5061f4044f747e23477237cb28c7a25ceae74f3d6dcbc887958";
const CASES: &[&str] = &[
    "native-literal",
    "native-copy",
    "literal-source-hash-corrupt",
    "literal-source-hash-empty",
    "literal-source-hash-31",
    "literal-source-hash-33",
    "literal-reference-byte",
    "literal-target-hash-corrupt",
    "copy-source-hash-corrupt",
    "copy-reference-byte",
    "copy-reference-byte-target-hash-empty",
];

#[derive(Deserialize)]
struct Observation {
    schema: u32,
    dll_sha256: String,
    source_sha256: String,
    delta_sha256: String,
    target_sha256: String,
    get_info_ok: bool,
    apply_ok: bool,
    target_equal: bool,
    applied_sha256: String,
    header_info_sha256: String,
    noneditable_inputs_unchanged: bool,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa31-reverse-native")
}

fn read(case: &Path, name: &str) -> Vec<u8> {
    std::fs::read(case.join(name)).unwrap()
}

fn observation(case: &Path) -> Observation {
    serde_json::from_slice(&read(case, "observation.json")).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn cases() -> Vec<PathBuf> {
    CASES
        .iter()
        .map(|name| {
            let case = root().join(name);
            assert!(
                case.join("observation.json").is_file(),
                "missing native reverse observation: {name}"
            );
            assert!(
                case.join("delta.pa31").is_file(),
                "missing native reverse delta: {name}"
            );
            case
        })
        .collect()
}

#[test]
fn native_reverse_baselines_preserve_forward_creation_lineage() {
    #[derive(Deserialize)]
    struct Lineage {
        native_reverse_created: bool,
        forward_delta_sha256: String,
        get_reverse_target_sha256: String,
    }
    for name in ["native-literal", "native-copy"] {
        let case = root().join(name);
        let native = observation(&case);
        assert!(native.get_info_ok && native.apply_ok && native.target_equal);
        let lineage: Lineage = serde_json::from_slice(&read(&case, "observation.json")).unwrap();
        assert!(lineage.native_reverse_created);
        let source = read(&case, "source.bin");
        let target = read(&case, "target.bin");
        let forward = read(&case, "forward.pa31");
        assert_eq!(digest(&forward), lineage.forward_delta_sha256);
        assert_eq!(read(&case, "forward-source.bin"), target);
        assert_eq!(read(&case, "forward-target.bin"), source);
        assert_eq!(read(&case, "forward-applied.bin"), source);
        let reverse_generated_target = read(&case, "get-reverse-target.bin");
        assert_eq!(
            digest(&reverse_generated_target),
            lineage.get_reverse_target_sha256
        );
        assert_eq!(reverse_generated_target, source);
        let forward_header = parse_header(&forward).unwrap();
        assert_eq!(forward_header.version, FormatVersion::PA31);
        assert_eq!(forward_header.file_type_set & 0x100, 0);
        assert_eq!(apply_impl(&target, &forward, true).unwrap(), source);
        let header = parse_header(&read(&case, "delta.pa31")).unwrap();
        assert_ne!(header.file_type_set & 0x100, 0);
        assert_eq!(header.hash_alg_id, 0x800c);
        assert_eq!(header.target_size as usize, target.len());
        assert_eq!(header.target_hash, Sha256::digest(&target).as_slice());
        assert_eq!(
            header.pa31_extra.unwrap().source_hash,
            Sha256::digest(&source).as_slice()
        );
        assert_eq!(read(&case, "applied.bin"), target);
    }
}

#[test]
fn native_reverse_copy_control_reads_reference_byte_zero() {
    let delta = read(&root().join("native-copy"), "delta.pa31");
    let (_, payload) = wire_parts(&delta);
    let mut reader = BitReader::new(&payload).unwrap();
    assert_eq!(reader.read_bits(32).unwrap(), 0x4d53_5250);
    let _count = reader.read_bits(32).unwrap();
    let mut copies = Vec::new();
    while reader.remaining() > 0 {
        let section = reader.read_buffer().unwrap();
        let mut section = BitReader::new(&section).unwrap();
        let payload_type = section.read_bits(32).unwrap();
        let _reserved = section.read_bits(32).unwrap();
        if payload_type == 1 {
            let _compressed = section.read_bits(32).unwrap();
            let deletions = RiftTable::from_reader(&mut section).unwrap();
            assert!(
                deletions.entries.is_empty(),
                "identity reverse has no deleted ranges"
            );
            continue;
        }
        let rift = RiftTable::from_reader(&mut section).unwrap();
        if payload_type == 2 {
            assert!(
                rift.entries.is_empty(),
                "identity reverse has no byte patches"
            );
            continue;
        }
        assert_eq!(payload_type, 0);
        let lengths = IntFormat::init_default().unwrap();
        for entry in rift.entries {
            copies.push((
                entry.source,
                entry.target,
                lengths.read_number(&mut section).unwrap(),
            ));
        }
    }
    assert_eq!(copies, [(0, 0, 4096)]);
    assert_eq!(read(&root().join("native-copy"), "source.bin").len(), 4096);
}

#[test]
fn native_reverse_probes_change_only_the_declared_input() {
    #[derive(Deserialize)]
    struct Probe {
        control: String,
        native_control_sha256: String,
        payload_unchanged: bool,
        native_noop_roundtrip_exact: bool,
        mutation: Mutation,
    }
    #[derive(Deserialize)]
    struct Mutation {
        parent: Option<String>,
        field: String,
    }
    for name in CASES
        .iter()
        .copied()
        .filter(|name| !name.starts_with("native-"))
    {
        let parent = if name == "copy-reference-byte-target-hash-empty" {
            "copy-reference-byte"
        } else if name.starts_with("copy-") {
            "native-copy"
        } else {
            "native-literal"
        };
        let case = root().join(name);
        let parent = root().join(parent);
        let probe: Probe = serde_json::from_slice(&read(&case, "probe.json")).unwrap();
        let control = if name.starts_with("copy-") {
            "native-copy"
        } else {
            "native-literal"
        };
        assert_eq!(probe.control, control);
        assert_eq!(
            probe.native_control_sha256,
            digest(&read(&root().join(control), "delta.pa31"))
        );
        assert!(probe.payload_unchanged && probe.native_noop_roundtrip_exact);
        assert_eq!(
            probe.mutation.parent.as_deref().unwrap_or(control),
            parent.file_name().unwrap().to_str().unwrap()
        );
        let delta = read(&case, "delta.pa31");
        let parent_delta = read(&parent, "delta.pa31");
        assert_eq!(&delta[..12], &parent_delta[..12]);
        let (fields, payload) = wire_parts(&delta);
        let (parent_fields, parent_payload) = wire_parts(&parent_delta);
        assert_eq!(payload, parent_payload, "{name}: reversal payload");
        assert_eq!(read(&case, "target.bin"), read(&parent, "target.bin"));
        let mut differences: Vec<_> = fields
            .iter()
            .filter(|(name, value)| parent_fields[*name] != **value)
            .map(|(name, _)| *name)
            .collect();
        let reference = read(&case, "source.bin");
        let parent_reference = read(&parent, "source.bin");
        if reference != parent_reference {
            assert_eq!(reference.len(), parent_reference.len());
            assert_eq!(&reference[1..], &parent_reference[1..]);
            assert_eq!(reference[0] ^ parent_reference[0], 1);
            differences.push("reference[0]");
        }
        let expected = if name.ends_with("reference-byte") {
            "reference[0]"
        } else if name.contains("target-hash") {
            "target_hash"
        } else {
            "source_hash"
        };
        assert_eq!(probe.mutation.field, expected);
        assert_eq!(differences, [expected], "{name}");
    }
}

#[test]
fn native_reverse_bypasses_source_integrity_but_checks_reconstructed_target() {
    for name in [
        "literal-source-hash-corrupt",
        "literal-source-hash-empty",
        "literal-source-hash-31",
        "literal-reference-byte",
        "copy-source-hash-corrupt",
    ] {
        let case = root().join(name);
        let native = observation(&case);
        assert!(
            native.get_info_ok && native.apply_ok && native.target_equal,
            "{name}"
        );
        let reference = read(&case, "source.bin");
        let delta = read(&case, "delta.pa31");
        let target = read(&case, "target.bin");
        let header = parse_header(&delta).unwrap();
        assert_ne!(
            header.pa31_extra.unwrap().source_hash,
            Sha256::digest(&reference).as_slice(),
            "{name}"
        );
        for verify in [false, true] {
            assert_eq!(
                apply_impl(&reference, &delta, verify).unwrap(),
                target,
                "{name}: verify={verify}"
            );
        }
    }
    for name in ["literal-target-hash-corrupt", "copy-reference-byte"] {
        let case = root().join(name);
        let native = observation(&case);
        assert!(native.get_info_ok && !native.apply_ok, "{name}");
        let reference = read(&case, "source.bin");
        let delta = read(&case, "delta.pa31");
        assert!(
            matches!(
                apply_impl(&reference, &delta, true),
                Err(Error::HashMismatch { .. })
            ),
            "{name}"
        );
        let unchecked = apply_impl(&reference, &delta, false).unwrap();
        if name == "copy-reference-byte" {
            let control = root().join("copy-reference-byte-target-hash-empty");
            let native_control = observation(&control);
            assert!(native_control.apply_ok && !native_control.target_equal);
            assert_eq!(unchecked, read(&control, "applied.bin"));
            assert_eq!(
                unchecked, reference,
                "the native identity copy preserves the changed byte"
            );
            assert_ne!(unchecked, read(&case, "target.bin"));
        } else {
            assert_eq!(unchecked, read(&case, "target.bin"));
        }
    }
    let oversized = root().join("literal-source-hash-33");
    let native = observation(&oversized);
    assert!(!native.get_info_ok && !native.apply_ok);
    for verify in [false, true] {
        assert!(matches!(
            apply_impl(
                &read(&oversized, "source.bin"),
                &read(&oversized, "delta.pa31"),
                verify
            ),
            Err(Error::HashTooLarge { size: 33, max: 32 })
        ));
    }
}

// Read the exact wire fields even for inputs the semantic parser rejects.
fn wire_parts(delta: &[u8]) -> (BTreeMap<&'static str, Vec<u8>>, Vec<u8>) {
    assert_eq!(&delta[..4], b"PA31");
    let mut outer = BitReader::new(&delta[12..]).unwrap();
    let nested = outer.read_buffer().unwrap();
    let mut reader = BitReader::new(&nested).unwrap();
    let mut fields = BTreeMap::new();
    for name in [
        "file_type_set",
        "file_type",
        "flags",
        "target_size",
        "hash_algorithm",
    ] {
        fields.insert(name, reader.read_i64().unwrap().to_le_bytes().to_vec());
    }
    let file_type_set = i64::from_le_bytes(fields["file_type_set"].as_slice().try_into().unwrap());
    assert_ne!(file_type_set & 0x100, 0, "native reverse flag missing");
    fields.insert("target_hash", reader.read_buffer().unwrap());
    for name in ["structure_size", "format_version", "minimum_client_version"] {
        fields.insert(name, reader.read_i64().unwrap().to_le_bytes().to_vec());
    }
    fields.insert("source_hash", reader.read_buffer().unwrap());
    assert_eq!(reader.remaining(), 0);
    let payload = outer.read_buffer().unwrap();
    assert_eq!(
        outer.remaining(),
        0,
        "reverse delta must have one payload buffer"
    );
    (fields, payload)
}

#[test]
fn native_reverse_header_and_apply_outcomes_match() {
    for case in cases() {
        let observation = observation(&case);
        assert_eq!(observation.schema, 1);
        assert_eq!(observation.dll_sha256, DLL_SHA256);
        assert!(observation.noneditable_inputs_unchanged);
        let source = read(&case, "source.bin");
        let delta = read(&case, "delta.pa31");
        let target = read(&case, "target.bin");
        assert_eq!(digest(&source), observation.source_sha256);
        assert_eq!(digest(&delta), observation.delta_sha256);
        assert_eq!(digest(&target), observation.target_sha256);
        wire_parts(&delta);
        let header = parse_header(&delta);
        assert_eq!(
            header.is_ok(),
            observation.get_info_ok,
            "{}: {header:?}",
            case.display()
        );
        if let Ok(header) = header {
            assert_eq!(header.version, FormatVersion::PA31);
            assert_ne!(header.file_type_set & 0x100, 0);
            assert_eq!(
                digest(&read(&case, "header-info.bin")),
                observation.header_info_sha256
            );
        }
        let applied = apply_impl(&source, &delta, true);
        assert_eq!(
            applied.is_ok(),
            observation.apply_ok,
            "{}: {applied:?}",
            case.display()
        );
        if let Ok(bytes) = applied {
            assert_eq!(digest(&bytes), observation.applied_sha256);
            assert_eq!(bytes, read(&case, "applied.bin"), "{}", case.display());
            assert_eq!(
                bytes == target,
                observation.target_equal,
                "{}",
                case.display()
            );
        }
    }
}
