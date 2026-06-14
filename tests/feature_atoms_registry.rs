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
];

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

#[derive(Debug, Clone, Copy)]
struct AtomRow<'a> {
    atom: &'a str,
    layer: &'a str,
    status: &'a str,
    apply_policy: &'a str,
    oracle_level: &'a str,
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

#[test]
fn managed_cli_readiness_counts_are_explicit() {
    let rows = registry_rows();
    let cli_rows = rows
        .iter()
        .copied()
        .filter(|row| row.layer == "cli")
        .collect::<Vec<_>>();

    assert_eq!(cli_rows.len(), 24, "CLI-layer atom count changed");
    assert_eq!(count_by(&cli_rows, |row| row.status, "supported"), 1);
    assert_eq!(count_by(&cli_rows, |row| row.status, "partial"), 22);
    assert_eq!(count_by(&cli_rows, |row| row.status, "missing"), 0);
    assert_eq!(count_by(&cli_rows, |row| row.status, "rejected"), 1);
    assert_eq!(count_by(&cli_rows, |row| row.apply_policy, "reject"), 24);
    assert_eq!(count_by(&cli_rows, |row| row.oracle_level, "curated"), 6);
    assert_eq!(count_by(&cli_rows, |row| row.oracle_level, "unit"), 17);
    assert_eq!(
        count_by(&cli_rows, |row| row.oracle_level, "needs_fixture"),
        1
    );
}

#[test]
fn managed_workstream_readiness_counts_are_explicit() {
    let required = REQUIRED_MANAGED_ATOMS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let rows = registry_rows()
        .into_iter()
        .filter(|row| required.contains(row.atom))
        .collect::<Vec<_>>();

    assert_eq!(rows.len(), REQUIRED_MANAGED_ATOMS.len());
    assert_eq!(count_by(&rows, |row| row.status, "supported"), 1);
    assert_eq!(count_by(&rows, |row| row.status, "partial"), 22);
    assert_eq!(count_by(&rows, |row| row.status, "missing"), 7);
    assert_eq!(count_by(&rows, |row| row.status, "rejected"), 1);
    assert_eq!(count_by(&rows, |row| row.apply_policy, "reject"), 31);
    assert_eq!(count_by(&rows, |row| row.oracle_level, "curated"), 6);
    assert_eq!(count_by(&rows, |row| row.oracle_level, "unit"), 17);
    assert_eq!(count_by(&rows, |row| row.oracle_level, "needs_fixture"), 8);
}

#[test]
fn managed_apply_policy_stays_rejected_until_release_gate_changes() {
    let required = REQUIRED_MANAGED_ATOMS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for row in registry_rows() {
        if required.contains(row.atom) {
            assert_eq!(
                row.apply_policy, "reject",
                "{} must stay reject-gated until the managed release gate is intentionally changed",
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
                layer: cols[1],
                status: cols[6],
                apply_policy: cols[7],
                oracle_level: cols[8],
            }
        })
        .collect()
}

fn count_by(rows: &[AtomRow<'_>], key: impl Fn(AtomRow<'_>) -> &str, value: &str) -> usize {
    rows.iter()
        .copied()
        .filter(|&row| key(row) == value)
        .count()
}
