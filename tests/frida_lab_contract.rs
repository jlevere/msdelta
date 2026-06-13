const LAB_README: &str = include_str!("../lab/frida/README.md");
const PACKAGE_JSON: &str = include_str!("../lab/frida/package.json");
const PNPM_LOCK: &str = include_str!("../lab/frida/pnpm-lock.yaml");
const PNPM_WORKSPACE: &str = include_str!("../lab/frida/pnpm-workspace.yaml");
const HOST_WRAPPER: &str = include_str!("../lab/frida/capture-export-oracle.mjs");
const INJECT_IMPORTER: &str = include_str!("../lab/frida/import-inject-capture.mjs");
const MANAGED_CAPTURE: &str = include_str!("../lab/frida/capture-managed-corpus.sh");
const MANAGED_CORPUS: &str = include_str!("../lab/frida/managed-corpus.ps1");
const AGENT: &str = include_str!("../lab/frida/agent/export-oracle.js");
const CAPTURE_SCHEMA: &str = include_str!("../lab/frida/schemas/export-capture.schema.json");
const RUN_SCHEMA: &str = include_str!("../lab/frida/schemas/run.schema.json");
const FRIDA_SYSTEM_DOC: &str = include_str!("../docs/frida-oracle-system.md");

#[test]
fn frida_export_oracle_contract_is_documented() {
    for required in [
        "FridaExportOracle",
        "ApplyDeltaB",
        "ApplyDeltaGetReverseB",
        "CreateDeltaB",
        "DELTA_INPUT",
        "DELTA_OUTPUT",
        "crates/oracle/lab/oracle_harness.ps1",
    ] {
        assert!(
            LAB_README.contains(required),
            "lab README should document {required}"
        );
        assert!(
            FRIDA_SYSTEM_DOC.contains(required),
            "Frida system doc should document {required}"
        );
    }

    for required in [
        "Windows x64 only",
        "Internal stage hooks",
        "Logical object normalization",
        "Automatic fixture promotion",
    ] {
        assert!(
            LAB_README.contains(required),
            "lab README should make current scope explicit: {required}"
        );
    }
}

#[test]
fn frida_export_oracle_scaffold_has_expected_entrypoints() {
    for required in [
        "\"capture:export\"",
        "\"import:inject\"",
        "\"check\"",
        "node --check ./capture-export-oracle.mjs",
        "node --check ./import-inject-capture.mjs",
        "node --check ./agent/export-oracle.js",
        "\"frida\"",
        "\"packageManager\": \"pnpm@11.1.2\"",
    ] {
        assert!(
            PACKAGE_JSON.contains(required),
            "package.json should contain {required}"
        );
    }

    for required in [
        "FridaExportOracle",
        "frida.getLocalDevice()",
        "manager.addRemoteDevice(remote)",
        "--remote",
        "device.spawn(options.command)",
        "device.attach(pid)",
        "run.json",
        "capture.json",
        "sha256File",
    ] {
        assert!(
            HOST_WRAPPER.contains(required),
            "host wrapper should contain {required}"
        );
    }
}

#[test]
fn frida_inject_importer_normalizes_file_sink_output() {
    for required in [
        "frida-inject.exe",
        "MSDELTA_EXPORT_ORACLE_BLOB_DIR",
        "file_sink_path",
        "sha256Bytes",
        "readTextFile",
        "utf16le",
        "\"inject\"",
        "run.json",
        "capture.json",
        "blob_size_mismatch",
    ] {
        assert!(
            INJECT_IMPORTER.contains(required),
            "inject importer should contain {required}"
        );
    }
}

#[test]
fn managed_corpus_generator_creates_native_oracle_jobs() {
    for required in [
        "managed-corpus.ps1",
        "csc.exe",
        "job.json",
        "manifest.json",
        "native_to_ours",
        "native_to_native",
        "file_type_set = 15",
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
    ] {
        assert!(
            MANAGED_CORPUS.contains(required) || LAB_README.contains(required),
            "managed corpus tooling should document or contain {required}"
        );
    }
}

#[test]
fn managed_corpus_capture_wrapper_runs_full_lab_loop() {
    for required in [
        "capture-managed-corpus.sh",
        "SSH_HOST",
        "REMOTE_ROOT",
        "OUT_DIR",
        "managed-corpus.ps1",
        "oracle_harness.ps1",
        "export-oracle.js",
        "frida-inject.exe",
        "agent-ready.txt",
        "LoadLibrary(\"msdelta.dll\")",
        "MSDELTA_EXPORT_ORACLE_READY_FILE",
        "import:inject",
        "frida-out.txt",
        "managed-corpus-msdelta",
    ] {
        assert!(
            MANAGED_CAPTURE.contains(required) || LAB_README.contains(required),
            "managed capture wrapper should document or contain {required}"
        );
    }
}

#[test]
fn frida_package_manager_state_is_pinned() {
    for required in ["frida:", "version: 17.12.0"] {
        assert!(
            PNPM_LOCK.contains(required),
            "pnpm lockfile should contain {required}"
        );
    }

    for required in ["allowBuilds:", "frida: true"] {
        assert!(
            PNPM_WORKSPACE.contains(required),
            "pnpm workspace should approve Frida build scripts with {required}"
        );
    }
}

#[test]
fn frida_agent_locks_x64_export_abi_assumptions() {
    for required in [
        "Process.arch === \"x64\"",
        "Process.pointerSize",
        "ApplyDeltaB",
        "ApplyDeltaGetReverseB",
        "CreateDeltaB",
        "readDeltaInput",
        "readDeltaOutput",
        "stackArg",
        "MSDELTA_EXPORT_ORACLE_BLOB_DIR",
        "MSDELTA_EXPORT_ORACLE_READY_FILE",
        "ready file written",
        "file_sink_path",
        "UpdateCompression.dll",
        "mspatcha.dll",
    ] {
        assert!(AGENT.contains(required), "agent should contain {required}");
    }

    for offset in ["0x28", "(argIndex - 4) * POINTER_SIZE"] {
        assert!(
            AGENT.contains(offset),
            "agent should document x64 stack argument decoding with {offset}"
        );
    }
}

#[test]
fn frida_capture_schemas_are_tied_to_export_atom() {
    for schema in [CAPTURE_SCHEMA, RUN_SCHEMA] {
        for required in [
            "\"schema\"",
            "\"FridaExportOracle\"",
            "\"ApplyDeltaB\"",
            "\"ApplyDeltaGetReverseB\"",
            "\"CreateDeltaB\"",
        ] {
            assert!(
                schema.contains(required),
                "schema should contain {required}"
            );
        }
    }

    for required in [
        "\"frida\"",
        "\"remote\"",
        "\"inject\"",
        "\"modules\"",
        "\"sha256\"",
        "\"cases\"",
        "\"errors\"",
    ] {
        assert!(
            RUN_SCHEMA.contains(required),
            "run schema should contain {required}"
        );
    }

    for required in [
        "\"events\"",
        "\"blobs\"",
        "\"path\"",
        "\"sha256\"",
        "\"file_sink_path\"",
    ] {
        assert!(
            CAPTURE_SCHEMA.contains(required),
            "capture schema should contain {required}"
        );
    }
}
