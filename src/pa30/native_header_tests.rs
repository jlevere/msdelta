//! Replay export-level observations from the pinned UpdateCompression build.

use super::{apply_impl, parse_header, CreateOptions, FormatVersion, Header};
use crate::bitstream::BitReader;
use crate::Error;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    info_output_size: usize,
    header_info_sha256: String,
    noneditable_inputs_unchanged: bool,
}

fn fixtures() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa31-native");
    let required = [
        "native-sha256",
        "native-empty-source",
        "native-pa30",
        "rust-md5",
        "rust-sha256",
        "rust-nohash",
        "structure-size-0",
        "structure-size-4",
        "structure-size-8",
        "structure-size-50",
        "structure-size-89",
        "structure-size-100000088",
        "format-version-0",
        "format-version-2",
        "format-version-ffffffff",
        "format-version-100000001",
        "minimum-version-1",
        "minimum-version-2",
        "minimum-version-ffffffff",
        "minimum-version-100000000",
        "minimum-version-100000001",
        "source-hash-corrupt",
        "source-hash-empty",
        "source-hash-31",
        "source-hash-33",
        "target-hash-33",
        "unused-source-byte",
        "unused-source-byte-unchecked",
        "hash-disabled-control",
        "hash-zero-source-nonempty",
    ];
    for name in required {
        let case = root.join(name);
        assert!(
            case.join("observation.json").is_file(),
            "missing native observation: {name}"
        );
        assert!(
            case.join("delta.pa31").is_file() || case.join("delta.pa30").is_file(),
            "missing native delta: {name}"
        );
    }
    let mut cases: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("delta.pa31").is_file() || path.join("delta.pa30").is_file())
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "native PA31 observations missing");
    cases
}

fn read_delta(case: &Path) -> Vec<u8> {
    read(
        case,
        if case.join("delta.pa31").is_file() {
            "delta.pa31"
        } else {
            "delta.pa30"
        },
    )
}

fn read(case: &Path, name: &str) -> Vec<u8> {
    std::fs::read(case.join(name)).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// The native export zeroes its caller's buffer, writes the caller's buffer size,
// then copies min(header_size, buffer_size) bytes from its parsed structure.
// This is an API layout, independent of the nested bitstream's encoded length.
fn native_info_bytes(header: &Header, output_size: usize) -> Vec<u8> {
    let extra = header.pa31_extra.as_ref();
    let header_size = extra.map_or(0x50, |extra| extra.header_size);
    let source_hash = extra.map_or(&[][..], |extra| extra.source_hash.as_slice());
    let mut structure = [0_u8; 0x88];
    structure[0..4].copy_from_slice(&header_size.to_le_bytes());
    structure[4..8].copy_from_slice(&extra.map_or(0, |extra| extra.format_version).to_le_bytes());
    structure[8..12].copy_from_slice(
        &extra
            .map_or(0, |extra| extra.min_client_version)
            .to_le_bytes(),
    );
    structure[0x10..0x18].copy_from_slice(&header.file_type_set.to_le_bytes());
    structure[0x18..0x20].copy_from_slice(&header.file_type.to_le_bytes());
    structure[0x20..0x28].copy_from_slice(&header.flags.to_le_bytes());
    structure[0x28..0x30].copy_from_slice(&header.target_size.to_le_bytes());
    structure[0x30..0x38].copy_from_slice(&header.target_file_time.to_le_bytes());
    structure[0x38..0x3c].copy_from_slice(&header.hash_alg_id.to_le_bytes());
    structure[0x3c..0x40].copy_from_slice(&(header.target_hash.len() as u32).to_le_bytes());
    structure[0x40..0x40 + header.target_hash.len()].copy_from_slice(&header.target_hash);
    structure[0x60..0x64].copy_from_slice(&(source_hash.len() as u32).to_le_bytes());
    structure[0x64..0x64 + source_hash.len()].copy_from_slice(source_hash);
    assert_eq!(output_size, structure.len());
    let mut output = vec![0_u8; output_size];
    output[..4].copy_from_slice(&(output_size as u32).to_le_bytes());
    let copied = (header_size as usize).min(output_size);
    output[..copied].copy_from_slice(&structure[..copied]);
    output
}

#[test]
fn native_pa31_header_and_apply_observations_match() {
    for case in fixtures() {
        let observation: Observation =
            serde_json::from_slice(&read(&case, "observation.json")).unwrap();
        assert_eq!(observation.schema, 1, "{}", case.display());
        assert!(
            observation.noneditable_inputs_unchanged,
            "{}",
            case.display()
        );
        assert_eq!(
            observation.dll_sha256,
            "b2abf7125b94c5061f4044f747e23477237cb28c7a25ceae74f3d6dcbc887958"
        );
        let source = read(&case, "source.bin");
        let delta = read_delta(&case);
        let target = read(&case, "target.bin");
        assert_eq!(digest(&source), observation.source_sha256);
        assert_eq!(digest(&delta), observation.delta_sha256);
        assert_eq!(digest(&target), observation.target_sha256);
        let parsed = parse_header(&delta);
        assert_eq!(
            parsed.is_ok(),
            observation.get_info_ok,
            "{}: {parsed:?}",
            case.display()
        );
        if let Ok(header) = parsed {
            let native_info = read(&case, "header-info.bin");
            assert_eq!(digest(&native_info), observation.header_info_sha256);
            assert_eq!(
                native_info_bytes(&header, observation.info_output_size),
                native_info,
                "{}: native API header bytes",
                case.display()
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
            assert_eq!(
                digest(&bytes),
                observation.applied_sha256,
                "{}",
                case.display()
            );
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

#[test]
fn native_pa31_source_hash_is_checked_even_when_target_verification_is_disabled() {
    let mut mismatches = 0;
    for case in fixtures() {
        let source = read(&case, "source.bin");
        let delta = read_delta(&case);
        let Ok(header) = parse_header(&delta) else {
            continue;
        };
        if header.file_type_set & 0x100 != 0 {
            continue;
        }
        let Some(extra) = header.pa31_extra else {
            continue;
        };
        if extra.source_hash.is_empty() || header.hash_alg_id != 0x800c {
            continue;
        }
        if extra.source_hash != Sha256::digest(&source).as_slice() {
            let observation: Observation =
                serde_json::from_slice(&read(&case, "observation.json")).unwrap();
            assert!(!observation.apply_ok, "{}", case.display());
            for verify in [false, true] {
                assert!(
                    matches!(
                        apply_impl(&source, &delta, verify),
                        Err(Error::SourceHashMismatch { .. })
                    ),
                    "{}: verify={verify}",
                    case.display()
                );
            }
            mismatches += 1;
        }
    }
    assert!(
        mismatches >= 2,
        "require independent source-byte and digest mutations"
    );
}

#[test]
fn pa31_encoder_reproduces_native_accepted_artifacts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa31-native");
    for (name, algorithm) in [
        ("rust-md5", 0x8003),
        ("rust-sha256", 0x800c),
        ("rust-nohash", 0),
    ] {
        let case = root.join(name);
        let observation: Observation =
            serde_json::from_slice(&read(&case, "observation.json")).unwrap();
        assert!(observation.apply_ok && observation.target_equal);
        let emitted = CreateOptions::new()
            .version(FormatVersion::PA31)
            .hash_algorithm(algorithm)
            .execute(&read(&case, "source.bin"), &read(&case, "target.bin"))
            .unwrap();
        assert_eq!(emitted, read(&case, "delta.pa31"), "{name}");
    }
}

#[test]
fn native_pa31_creation_requires_hash_even_though_apply_accepts_hashless() {
    #[derive(Deserialize)]
    struct Creation {
        schema: u32,
        dll_sha256: String,
        operation: String,
        native_create_flags: u32,
        hash_algorithm: u32,
        create_ok: bool,
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa31-native");
    let creation: Creation =
        serde_json::from_slice(&read(&root.join("native-no-hash"), "observation.json")).unwrap();
    assert_eq!(creation.schema, 1);
    assert_eq!(
        creation.dll_sha256,
        "b2abf7125b94c5061f4044f747e23477237cb28c7a25ceae74f3d6dcbc887958"
    );
    assert_eq!(creation.operation, "create-no-hash");
    assert_eq!(creation.native_create_flags, 0x10000000);
    assert_eq!(creation.hash_algorithm, 0);
    assert!(!creation.create_ok);
    let accepted: Observation =
        serde_json::from_slice(&read(&root.join("rust-nohash"), "observation.json")).unwrap();
    assert!(accepted.get_info_ok && accepted.apply_ok && accepted.target_equal);
}

#[test]
fn native_header_probes_change_only_the_declared_input() {
    // Decode wire values without semantic validation so rejected client versions
    // and 33-byte hashes can also be compared to their unmodified native control.
    fn wire_parts(delta: &[u8]) -> (BTreeMap<&'static str, Vec<u8>>, Vec<Vec<u8>>) {
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
        fields.insert("target_hash", reader.read_buffer().unwrap());
        for name in ["structure_size", "format_version", "minimum_client_version"] {
            fields.insert(name, reader.read_i64().unwrap().to_le_bytes().to_vec());
        }
        fields.insert("source_hash", reader.read_buffer().unwrap());
        let payload = vec![outer.read_buffer().unwrap(), outer.read_buffer().unwrap()];
        (fields, payload)
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa31-native");
    let native_delta = read_delta(&root.join("native-sha256"));
    let native_digest = digest(&native_delta);
    let mut probes = 0;
    for case in fixtures() {
        let probe_path = case.join("probe.json");
        if !probe_path.is_file() {
            continue;
        }
        let probe: serde_json::Value =
            serde_json::from_slice(&std::fs::read(probe_path).unwrap()).unwrap();
        assert_eq!(probe["native_control_sha256"], native_digest);
        assert_eq!(probe["payload_unchanged"], true);
        assert_eq!(probe["native_noop_roundtrip_exact"], true);
        let mutation = &probe["mutation"];
        let parent = root.join(mutation["parent"].as_str().unwrap_or("native-sha256"));
        let parent_delta = read_delta(&parent);
        let delta = read_delta(&case);
        assert_eq!(&delta[..12], &parent_delta[..12]);
        let (fields, payload) = wire_parts(&delta);
        let (parent_fields, parent_payload) = wire_parts(&parent_delta);
        assert_eq!(payload, parent_payload, "{}: payload", case.display());
        assert_eq!(read(&case, "target.bin"), read(&parent, "target.bin"));
        let mut differences: Vec<_> = fields
            .iter()
            .filter(|(name, value)| parent_fields[*name] != **value)
            .map(|(name, _)| *name)
            .collect();
        let source = read(&case, "source.bin");
        let parent_source = read(&parent, "source.bin");
        if source != parent_source {
            assert_eq!(source.len(), parent_source.len());
            assert_eq!(&source[1..], &parent_source[1..]);
            assert_eq!(source[0] ^ parent_source[0], 1);
            differences.push("source[0]");
        }
        if mutation["role"] == "control" {
            assert_eq!(
                differences,
                ["hash_algorithm", "source_hash", "target_hash"]
            );
        } else {
            assert_eq!(
                differences,
                [mutation["field"].as_str().unwrap()],
                "{}",
                case.display()
            );
        }
        probes += 1;
    }
    assert_eq!(probes, 24, "all declared header mutations must be checked");
}
