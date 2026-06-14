use std::collections::HashSet;

const REGISTRY: &str = include_str!("../docs/feature-atoms.tsv");

const HEADER: &[&str] = &[
    "atom",
    "layer",
    "kind",
    "file_types",
    "flag_mask",
    "native_reference",
    "status",
    "apply_policy",
    "oracle_level",
    "next_step",
    "proof",
];

/// Oracle levels that require executable native-backed evidence.
const ORACLE_BACKED_LEVELS: &[&str] = &["curated", "bulk", "release", "manual"];

/// Oracle levels consistent with having no evidence yet.
const UNPROVEN_LEVELS: &[&str] = &["none", "needs_fixture"];

const LAYERS: &[&str] = &[
    "format", "codec", "rift", "pe", "x86", "x64", "ia64", "arm", "arm64", "cli", "pipeline",
    "create", "lab",
];

const KINDS: &[&str] = &[
    "parser",
    "classifier",
    "algebra",
    "producer",
    "source_transform",
    "postprocess",
    "codec",
    "pipeline",
    "fixture",
    "gate",
    "create",
];

const STATUSES: &[&str] = &["supported", "partial", "missing", "rejected", "unknown"];
const POLICIES: &[&str] = &["allow", "reject", "lab_only", "n/a"];
const ORACLE_LEVELS: &[&str] = &[
    "none",
    "needs_fixture",
    "unit",
    "manual",
    "curated",
    "bulk",
    "release",
];

const REQUIRED_MANAGED_ATOMS: &[&str] = &[
    "ManagedFileTypeBranch",
    "PePreprocessManagedClassic",
    "PePreprocessManagedCli4",
    "CliMetadataStaticSchema",
    "CliMetadataFromPe",
    "CliMetadataRowsAndHeaps",
    "Cli4MetadataFromPe",
    "CliMetadataBitstream",
    "Cli4MetadataBitstream",
    "CliMapBitstream",
    "CliCodedTokenMap",
    "TransformContextManaged",
    "MarkNonExeCliMethods",
    "TransformCliDisasm",
    "TransformCli4Disasm",
    "CliBlobCompressedInteger",
    "CliBlobTypeTokenRemap",
    "TransformCliMetadata",
    "TransformCli4Metadata",
    "CliHeapRift",
    "CliTableRift",
    "CliCompressionRift",
    "Cli4CompressionRift",
    "FinalPeCopyRiftManaged",
    "CreateCliMapFromPEs",
    "CreateCli4MapFromPEs",
    "CliMapStringsHash",
    "CliMapBlobAndRvas",
    "CliMapSequenceTables",
    "CreateCli",
    "CreateCli4",
];

const REQUIRED_FRIDA_LAB_ATOMS: &[&str] = &[
    "FridaExportOracle",
    "FridaSymbolMap",
    "FridaStageCapture",
    "FridaCallStageCapture",
    "FridaObjectNormalizer",
    "FridaFixturePromotion",
    "WindowsVersionMatrix",
    "NativeOracleDiff",
];

const REQUIRED_X64_ATOMS: &[&str] = &["DisasmX64", "PdataX64"];

const CLASSIC_MANAGED_APPLY_ALLOWED_ATOMS: &[&str] = &[
    "ManagedFileTypeBranch",
    "PePreprocessManagedClassic",
    "CliMapBitstream",
    "TransformCliDisasm",
    "CliBlobTypeTokenRemap",
    "TransformCliMetadata",
    "CliHeapRift",
    "CliTableRift",
    "CliCompressionRift",
    "FinalPeCopyRiftManaged",
];

#[derive(Debug, Clone, Copy)]
struct AtomRow<'a> {
    atom: &'a str,
    status: &'a str,
    apply_policy: &'a str,
    oracle_level: &'a str,
    proof: &'a str,
}

#[test]
fn feature_atom_registry_is_well_formed() {
    let mut lines = REGISTRY.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next().expect("registry has a header");
    assert_eq!(
        header.split('\t').collect::<Vec<_>>(),
        HEADER,
        "registry columns changed; update tests and tools together"
    );

    let mut atoms = HashSet::new();
    let mut row_count = 0usize;

    for (line_number, line) in lines.enumerate() {
        let line_number = line_number + 2;
        let cols = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            cols.len(),
            HEADER.len(),
            "line {line_number}: expected {} TSV columns, got {}",
            HEADER.len(),
            cols.len()
        );

        let atom = cols[0];
        assert!(
            !atom.is_empty() && atom.chars().all(|c| c.is_ascii_alphanumeric()),
            "line {line_number}: atom names must be non-empty ASCII identifiers"
        );
        assert!(
            atoms.insert(atom),
            "line {line_number}: duplicate atom name {atom}"
        );

        assert!(
            LAYERS.contains(&cols[1]),
            "line {line_number}: invalid layer {}",
            cols[1]
        );
        assert!(
            KINDS.contains(&cols[2]),
            "line {line_number}: invalid kind {}",
            cols[2]
        );
        assert!(
            valid_file_types(cols[3]),
            "line {line_number}: invalid file_types {}",
            cols[3]
        );
        assert!(
            valid_flag_mask(cols[4]),
            "line {line_number}: invalid flag_mask {}",
            cols[4]
        );
        assert!(
            !cols[5].is_empty(),
            "line {line_number}: native_reference must be non-empty"
        );
        assert!(
            STATUSES.contains(&cols[6]),
            "line {line_number}: invalid status {}",
            cols[6]
        );
        assert!(
            POLICIES.contains(&cols[7]),
            "line {line_number}: invalid apply_policy {}",
            cols[7]
        );
        assert!(
            ORACLE_LEVELS.contains(&cols[8]),
            "line {line_number}: invalid oracle_level {}",
            cols[8]
        );
        assert!(
            !cols[9].is_empty(),
            "line {line_number}: next_step must be non-empty"
        );
        assert!(
            valid_proof(cols[10]),
            "line {line_number}: invalid proof {} (want none | oracle:<path> | unit:<path>)",
            cols[10]
        );
        if let Some(path) = proof_path(cols[10]) {
            assert!(
                proof_target_exists(path),
                "line {line_number}: proof cites {path}, which does not exist"
            );
        }
        row_count += 1;
    }

    assert!(row_count >= 40, "registry should cover the known atom map");
}

#[test]
fn managed_cli_atom_set_is_explicit() {
    let atoms = registry_rows()
        .into_iter()
        .map(|row| row.atom)
        .collect::<HashSet<_>>();

    for required in REQUIRED_MANAGED_ATOMS {
        assert!(
            atoms.contains(required),
            "managed CLI atom {required} is missing from registry"
        );
    }
}

#[test]
fn native_x64_atom_set_is_explicit() {
    let atoms = registry_rows()
        .into_iter()
        .map(|row| row.atom)
        .collect::<HashSet<_>>();

    for required in REQUIRED_X64_ATOMS {
        assert!(
            atoms.contains(required),
            "native x64 atom {required} is missing from registry"
        );
    }
}

#[test]
fn frida_oracle_atom_set_is_explicit() {
    let atoms = registry_rows()
        .into_iter()
        .map(|row| row.atom)
        .collect::<HashSet<_>>();

    for required in REQUIRED_FRIDA_LAB_ATOMS {
        assert!(
            atoms.contains(required),
            "Frida oracle atom {required} is missing from registry"
        );
    }
}

/// Every atom that claims progress must cite evidence. This is the core
/// anti-drift invariant: a `supported` or `partial` status cannot float
/// above an empty proof. (Exact status/policy distributions are deliberately
/// not asserted -- pinning tallies tests the map, not the territory.)
#[test]
fn progressing_atoms_cite_evidence() {
    for row in registry_rows() {
        if matches!(row.status, "supported" | "partial") {
            assert_ne!(
                row.proof, "none",
                "{} is {} but cites no proof",
                row.atom, row.status
            );
        }
    }
}

/// A `missing` atom has nothing to prove yet, so it must not cite evidence.
#[test]
fn missing_atoms_cite_no_evidence() {
    for row in registry_rows() {
        if row.status == "missing" {
            assert_eq!(
                row.proof, "none",
                "{} is missing but cites proof {}",
                row.atom, row.proof
            );
        }
    }
}

/// Proof kind and oracle level must agree: an `oracle:` proof requires a
/// native-backed oracle level, and a `none` proof requires an unproven level.
/// This catches the inflation the registry could previously hide -- claiming
/// a curated/bulk/release oracle level while pointing at nothing executable.
#[test]
fn proof_kind_agrees_with_oracle_level() {
    for row in registry_rows() {
        match proof_kind(row.proof) {
            "oracle" => assert!(
                ORACLE_BACKED_LEVELS.contains(&row.oracle_level),
                "{} cites an oracle proof but its oracle_level is {}",
                row.atom,
                row.oracle_level
            ),
            "none" => assert!(
                UNPROVEN_LEVELS.contains(&row.oracle_level),
                "{} cites no proof but its oracle_level is {}",
                row.atom,
                row.oracle_level
            ),
            _ => {}
        }
    }
}

#[test]
fn managed_apply_policy_only_allows_classic_apply_atoms() {
    let required = REQUIRED_MANAGED_ATOMS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let allowed = CLASSIC_MANAGED_APPLY_ALLOWED_ATOMS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for row in registry_rows() {
        if required.contains(row.atom) {
            let expected = if allowed.contains(row.atom) {
                "allow"
            } else {
                "reject"
            };
            assert_eq!(
                row.apply_policy, expected,
                "{} has an unexpected managed apply policy",
                row.atom
            );
        }
    }
}

fn valid_file_types(value: &str) -> bool {
    if matches!(value, "all" | "pe" | "pe,cli") {
        return true;
    }
    value.split(',').all(valid_hex_file_type)
}

fn valid_hex_file_type(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn valid_flag_mask(value: &str) -> bool {
    value == "-" || value == "unknown" || valid_hex_file_type(value)
}

fn registry_rows() -> Vec<AtomRow<'static>> {
    REGISTRY
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let cols = line.split('\t').collect::<Vec<_>>();
            AtomRow {
                atom: cols[0],
                status: cols[6],
                apply_policy: cols[7],
                oracle_level: cols[8],
                proof: cols[10],
            }
        })
        .collect()
}

/// A proof cell is `oracle:<path>` or `unit:<path>` (non-empty path), or the
/// bare word `none`. `oracle` cites a genuine/native artifact; `unit` cites
/// in-tree self-consistency / algebra / structural tests only.
fn valid_proof(value: &str) -> bool {
    match value.split_once(':') {
        Some((kind, path)) => matches!(kind, "oracle" | "unit") && !path.is_empty(),
        None => value == "none",
    }
}

/// The kind tag of a proof cell (`oracle`, `unit`, `none`, or the raw value
/// if it is malformed).
fn proof_kind(value: &str) -> &str {
    value.split_once(':').map(|(kind, _)| kind).unwrap_or(value)
}

/// The path a proof cites, if any (`None` for `none`).
fn proof_path(value: &str) -> Option<&str> {
    value.split_once(':').map(|(_, path)| path)
}

fn proof_target_exists(path: &str) -> bool {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(path)
        .exists()
}
