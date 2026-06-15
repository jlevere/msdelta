use msdelta::pa30;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const FIXTURE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/atoms/ManagedNativeCorpus"
);

const CASES: &[(&str, &str)] = &[
    (
        "cli-const-string",
        "managed-cli/user-string-and-method-body",
    ),
    ("cli-add-method", "managed-cli/metadata-row-growth"),
    (
        "cli-generics-signature",
        "managed-cli/signature-blob-and-memberref",
    ),
    (
        "cli-custom-attribute",
        "managed-cli/custom-attribute-table-and-blob",
    ),
    (
        "cli-resource",
        "managed-cli/manifest-resource-and-method-body",
    ),
    ("cli-platform-x64", "managed-cli/amd64-managed-pe"),
    (
        "cli-properties-events",
        "managed-cli/properties-events-semantics",
    ),
    (
        "cli-interface-impl",
        "managed-cli/interface-implementation-and-methodimpl",
    ),
    (
        "cli-constructor-token-boundary",
        "managed-cli/constructor-table-token-boundary",
    ),
    (
        "cli-static-constructor-token-boundary",
        "managed-cli/static-constructor-table-token-boundary",
    ),
    (
        "cli-constructor-user-string-boundary",
        "managed-cli/constructor-user-string-boundary",
    ),
    (
        "cli-exception-switch",
        "managed-cli/exception-handlers-and-switch-il",
    ),
    (
        "cli-pinvoke-module",
        "managed-cli/pinvoke-module-and-marshal",
    ),
    (
        "cli-nested-struct-enum-array",
        "managed-cli/nested-types-structs-enums-arrays",
    ),
];

#[test]
fn managed_native_corpus_is_diverse_and_native_verified() {
    let mut categories = BTreeSet::new();

    for (case_id, category) in CASES {
        let case_dir = Path::new(FIXTURE_ROOT).join(case_id);
        let case = fs::read_to_string(case_dir.join("case.toml")).expect("read case.toml");
        categories.insert(read_string(&case, "category"));

        for required in [
            "atom = \"ManagedNativeCorpus\"",
            "module = \"msdelta.dll\"",
            "module_sha256 = \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
            "native_export_create = \"CreateDeltaB\"",
            "native_export_apply = \"ApplyDeltaB\"",
            "file_type_set = \"0xf\"",
            "native_to_ours_status = \"OK\"",
            "native_to_native_status = \"PASS\"",
            "Rust managed apply support",
            "CliMetadataBitstream object parity",
            "CliMapBitstream object parity",
        ] {
            assert!(
                case.contains(required),
                "{case_id} case.toml missing {required}"
            );
        }

        assert_eq!(read_string(&case, "case"), *case_id);
        assert_eq!(read_string(&case, "category"), *category);
        assert_eq!(
            read_string(&case, "native_to_native_got_sha256"),
            read_string(&case, "target_sha256")
        );

        assert_fixture_file(
            &case_dir,
            "source.dll",
            &case,
            "source_size",
            "source_sha256",
        );
        assert_fixture_file(
            &case_dir,
            "target.dll",
            &case,
            "target_size",
            "target_sha256",
        );
        assert_fixture_file(&case_dir, "delta.pa30", &case, "delta_size", "delta_sha256");
        assert!(case_dir.join("source.cs").is_file(), "{case_id} source.cs");
        assert!(case_dir.join("target.cs").is_file(), "{case_id} target.cs");

        let delta = fs::read(case_dir.join("delta.pa30")).expect("read delta.pa30");
        assert!(delta.starts_with(b"PA30"), "{case_id} delta should be PA30");
    }

    assert_eq!(
        categories,
        CASES
            .iter()
            .map(|(_, category)| (*category).to_owned())
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn managed_native_corpus_applies_classic_managed_deltas() {
    for (case_id, _) in CASES {
        let case_dir = Path::new(FIXTURE_ROOT).join(case_id);
        let case = fs::read_to_string(case_dir.join("case.toml")).expect("read case.toml");
        let source = fs::read(case_dir.join("source.dll")).expect("read source.dll");
        let target = fs::read(case_dir.join("target.dll")).expect("read target.dll");
        let delta = fs::read(case_dir.join("delta.pa30")).expect("read delta.pa30");

        let output = pa30::apply(&source, &delta)
            .unwrap_or_else(|error| panic!("{case_id}: managed apply failed: {error}"));
        if output != target {
            let diffs = first_diffs(&output, &target, 24);
            panic!(
                "{case_id}: managed apply target mismatch: {} differing bytes, first diffs: {diffs:?}",
                diff_count(&output, &target)
            );
        }
        assert_eq!(
            sha256_hex(&output),
            read_string(&case, "target_sha256"),
            "{case_id}: managed apply target hash mismatch"
        );
    }
}

fn first_diffs(left: &[u8], right: &[u8], limit: usize) -> Vec<(usize, Option<u8>, Option<u8>)> {
    let len = left.len().max(right.len());
    let mut diffs = Vec::new();
    for index in 0..len {
        let left_byte = left.get(index).copied();
        let right_byte = right.get(index).copied();
        if left_byte != right_byte {
            diffs.push((index, left_byte, right_byte));
            if diffs.len() == limit {
                break;
            }
        }
    }
    diffs
}

fn diff_count(left: &[u8], right: &[u8]) -> usize {
    let len = left.len().max(right.len());
    (0..len)
        .filter(|&index| left.get(index) != right.get(index))
        .count()
}

fn assert_fixture_file(case_dir: &Path, name: &str, case: &str, size_key: &str, hash_key: &str) {
    let path = case_dir.join(name);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        bytes.len(),
        read_usize(case, size_key),
        "{}",
        path.display()
    );
    assert_eq!(
        sha256_hex(&bytes),
        read_string(case, hash_key),
        "{}",
        path.display()
    );
}

fn read_string(case: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let value = case
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing scalar {key}"));
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{key} should be a quoted string"))
        .replace("\\\\", "\\")
}

fn read_usize(case: &str, key: &str) -> usize {
    let prefix = format!("{key} = ");
    case.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing scalar {key}"))
        .parse()
        .unwrap_or_else(|error| panic!("{key} should be usize: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Managed encode gate: for each genuine classic-CLI managed fixture, run OUR
/// create(Auto) on (source, target) and require the result to (a) reconstruct
/// the target and (b) carry the genuine file_type + flags (measured against the
/// genuine managed delta). Byte-exactness vs genuine is reported, not asserted
/// (the same deep preprocess-rift / LZX-parse gap as native encode). Run with
/// `--nocapture` for the per-case byte-exact / size detail.
#[test]
fn managed_native_corpus_encode_reconstructs() {
    let (mut byte_exact, mut ft_flags_match) = (0u32, 0u32);
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for (case_id, _) in CASES {
        let dir = Path::new(FIXTURE_ROOT).join(case_id);
        let source = fs::read(dir.join("source.dll")).expect("source.dll");
        let target = fs::read(dir.join("target.dll")).expect("target.dll");
        let genuine = fs::read(dir.join("delta.pa30")).expect("delta.pa30");

        let ours = match pa30::CreateOptions::new()
            .file_type(pa30::FileType::Auto)
            .execute(&source, &target)
        {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{case_id}: create error: {e}"));
                continue;
            }
        };

        let hdr = |d: &[u8]| {
            pa30::parse(d)
                .ok()
                .map(|p| (p.header.file_type, p.header.flags))
        };
        let (g_ft, g_fl) = hdr(&genuine).unwrap_or((-1, 0));
        let (o_ft, o_fl) = hdr(&ours).unwrap_or((-2, 0));
        let be = ours == genuine;
        let rec = matches!(pa30::apply(&source, &ours), Ok(b) if b == target);
        if be {
            byte_exact += 1;
        }
        if (o_ft, o_fl) == (g_ft, g_fl) {
            ft_flags_match += 1;
        }
        if !rec {
            failures.push(format!(
                "{case_id}: our delta does not reconstruct the target"
            ));
        }
        rows.push(format!(
            "{case_id}: recon={rec} byte_exact={be} genuine[ft={g_ft} fl={g_fl:#x} {}B] ours[ft={o_ft} fl={o_fl:#x} {}B]",
            genuine.len(),
            ours.len()
        ));
    }
    eprintln!("\n=== MANAGED ENCODE ({} cases) ===", CASES.len());
    for r in &rows {
        eprintln!("  {r}");
    }
    eprintln!(
        "reconstruct={}/{}  same-ft+flags={ft_flags_match}/{}  byte-exact-vs-genuine={byte_exact}/{}",
        CASES.len() - failures.len(),
        CASES.len(),
        CASES.len(),
        CASES.len(),
    );
    assert!(
        failures.is_empty(),
        "managed encode regressed:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        ft_flags_match as usize,
        CASES.len(),
        "managed encode must pick the genuine file_type + flags for every case"
    );
}
