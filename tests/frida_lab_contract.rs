const LAB_README: &str = include_str!("../lab/frida/README.md");
const PACKAGE_JSON: &str = include_str!("../lab/frida/package.json");
const PNPM_LOCK: &str = include_str!("../lab/frida/pnpm-lock.yaml");
const PNPM_WORKSPACE: &str = include_str!("../lab/frida/pnpm-workspace.yaml");
const HOST_WRAPPER: &str = include_str!("../lab/frida/capture-export-oracle.mjs");
const INJECT_IMPORTER: &str = include_str!("../lab/frida/import-inject-capture.mjs");
const STAGE_PROMOTER: &str = include_str!("../lab/frida/promote-stage-fixture.mjs");
const MANAGED_CAPTURE: &str = include_str!("../lab/frida/capture-managed-corpus.sh");
const STAGE_MAP_STATUS: &str = include_str!("../lab/frida/check-stage-symbol-map.sh");
const MANAGED_CORPUS: &str = include_str!("../lab/frida/managed-corpus.ps1");
const AGENT: &str = include_str!("../lab/frida/agent/export-oracle.js");
const STAGE_READER: &str = include_str!("../lab/frida/agent/stage/reader-window.js");
const STAGE_CLI_MANAGED: &str = include_str!("../lab/frida/agent/stage/cli-managed.js");
const STAGE_AGENT: &str = include_str!("../lab/frida/agent/stage-oracle.js");
const WIN26100_MSDELTA_STAGE_MAP: &str = include_str!(
    "../lab/frida/symbol-maps/msdelta/ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb.json"
);
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
        "\"promote:stage\"",
        "\"check\"",
        "node --check ./capture-export-oracle.mjs",
        "node --check ./import-inject-capture.mjs",
        "node --check ./promote-stage-fixture.mjs",
        "node --check ./agent/export-oracle.js",
        "node --check ./agent/stage/reader-window.js",
        "node --check ./agent/stage/cli-managed.js",
        "node --check ./agent/stage-oracle.js",
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
fn stage_fixture_promoter_has_first_call_record_mode() {
    for required in [
        "promote-stage-fixture.mjs",
        "--mode cli-blob-compressed-integer",
        "--mode cli-compression-rift",
        "--normalized <normalized-dir>",
        "--source-case <id>",
        "--case-id <id>",
        "--force",
        "CliBlobCompressedInteger",
        "CliBlobCompressedIntegerCallRecord",
        "GetBlobContent",
        "encoded-width/decoded-length/encoded-prefix",
        "selectCliBlobCompressedIntegerCalls",
        "stableCliBlobObject",
        "CliCompressionRift",
        "CliCompressionRiftRecord",
        "selectCliCompressionRiftRecords",
        "stableCliCompressionRiftObject",
        "source-size/fill-offset/rift-entry",
        "stage_leave_object_count",
        "one_byte_width_count",
        "two_byte_width_count",
        "four_byte_width_count",
    ] {
        assert!(
            STAGE_PROMOTER.contains(required),
            "stage promoter should contain {required}"
        );
    }

    for required in [
        "pnpm --dir lab/frida promote:stage",
        "--mode cli-blob-compressed-integer",
        "--normalized lab/frida/out/managed-corpus/normalized",
        "--source-case managed-corpus-msdelta",
        "--case-id cli-blob-compressed-integer-win26100",
        "strips raw pointers and lab",
        "successful one-byte blob length",
    ] {
        assert!(
            LAB_README.contains(required) || FRIDA_SYSTEM_DOC.contains(required),
            "lab docs should describe stage promotion with {required}"
        );
    }
}

#[test]
fn frida_inject_importer_normalizes_file_sink_output() {
    for required in [
        "frida-inject.exe",
        "MSDELTA_EXPORT_ORACLE_BLOB_DIR",
        "file_sink_path",
        "--object-dir",
        "MSDELTA_STAGE_ORACLE_OBJECT_DIR",
        "importObject",
        "object_json_invalid",
        "object_size_mismatch",
        "objects: []",
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
        "cli-properties-events",
        "cli-interface-impl",
        "cli-constructor-token-boundary",
        "cli-static-constructor-token-boundary",
        "cli-constructor-user-string-boundary",
        "cli-exception-switch",
        "cli-pinvoke-module",
        "cli-nested-struct-enum-array",
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
        "stage-oracle.js",
        "stage\\reader-window.js",
        "stage\\cli-managed.js",
        "System.Collections.Generic.List[string]",
        "symbol-maps",
        "Get-FileHash",
        "MSDELTA_STAGE_ORACLE_SYMBOL_MAP",
        "MSDELTA_STAGE_ORACLE_OBJECT_DIR",
        "MSDELTA_STAGE_ORACLE_BLOB_DIR",
        "MSDELTA_STAGE_ORACLE_READY_FILE",
        "stage hooks are hash-locked by design",
        "stage-agent-ready.txt",
        "--object-dir",
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
fn stage_symbol_map_status_preflights_new_dll_builds() {
    for required in [
        "check-stage-symbol-map.sh",
        "SSH_HOST",
        "MODULE",
        "SYMBOL_MODULE_DIR",
        "MODULE_PATH",
        "Get-FileHash",
        "symbol-maps/$SYMBOL_MODULE_DIR/$module_hash.json",
        "stage_supported=true",
        "stage_supported=false",
        "validate private RVAs and object layouts",
    ] {
        assert!(
            STAGE_MAP_STATUS.contains(required),
            "stage map status helper should contain {required}"
        );
    }

    for required in [
        "DLL Build Updates",
        "Export capture is not locked to the current DLL build",
        "Internal stage capture is intentionally hash-locked",
        "check-stage-symbol-map.sh",
        "future build should produce an unmapped preflight failure",
    ] {
        assert!(
            LAB_README.contains(required),
            "lab README should document new DLL build handling: {required}"
        );
    }

    for required in [
        "fixture extraction system is reusable across future Windows",
        "one validated symbol map per",
        "Run `nix develop -c lab/frida/check-stage-symbol-map.sh`",
        "Hash changed but no validated replacement map",
    ] {
        assert!(
            FRIDA_SYSTEM_DOC.contains(required),
            "Frida system doc should document new DLL build handling: {required}"
        );
    }
}

#[test]
fn frida_stage_oracle_fails_closed_and_normalizes_cli_metadata() {
    let stage_runtime = [STAGE_READER, STAGE_CLI_MANAGED, STAGE_AGENT].join("\n");
    for required in [
        "FridaStageCapture",
        "MSDELTA_STAGE_ORACLE_SYMBOL_MAP",
        "MSDELTA_STAGE_READER",
        "MSDELTA_STAGE_CAPTURE_ADAPTERS",
        "registerStageCaptureAdapter",
        "stageReaderRuntime",
        "MSDELTA_STAGE_ORACLE_SELECTED_SHA256",
        "MSDELTA_STAGE_ORACLE_OBJECT_DIR",
        "MSDELTA_STAGE_ORACLE_BLOB_DIR",
        "MSDELTA_STAGE_ORACLE_READY_FILE",
        "stage capture disabled",
        "selected module hash does not match symbol map",
        "mapped image size does not match symbol map",
        "RVA outside mapped image",
        "cli_metadata_internal_from_bitreader",
        "CliMetadataBitstreamRecord",
        "metadata_file_offset",
        "metadata_size",
        "metadata_rva",
        "stream_count",
        "stream_headers_end",
        "heap_widths",
        "valid_table_mask",
        "row_counts",
        "reader-bitstream",
        "reader_read",
        "activeReaderTracesByThread",
        "buildReaderWindowFromTrace",
        "buildStandaloneBitstreamFromWindowBits",
        "cli_map_from_bitreader",
        "CliMapBitstreamRecord",
        "readCliMapRecord",
        "readRiftTableRecord",
        "readS64Value",
        "cli_map_coded_token_call",
        "CliCodedTokenMapCallRecord",
        "readCliCodedTokenMapCallRecord",
        "nativePointerU32",
        "STAGE_CAPTURE_ADAPTERS",
        "captureAdapter",
        "captureReaderInputs",
        "captureCliCodedTokenInputs",
        "captureCliBlobGetContentState",
        "captureCliBlobGetContentInputs",
        "captureInputs",
        "captureState",
        "callContext.state",
        "cli_blob_get_content_call",
        "CliBlobCompressedIntegerCallRecord",
        "decodeCompressedIntegerPrefix",
        "pointerDistance",
        "readCliBlobGetContentCallRecord",
        "unsupported capture adapter",
        "cli_compression_rift_generate",
        "CliCompressionRiftRecord",
        "captureCliCompressionRiftGenerateInputs",
        "readCliCompressionRiftGenerateRecord",
        "source_widening_fill_offset",
        "readPlan:",
        "readPlanForObject",
        "replayed reader state does not match native exit state",
        "standalone BitReader stream copied from the native reader window",
        "type: \"object\"",
        "type: \"blob\"",
        "file_sink_path",
    ] {
        assert!(
            stage_runtime.contains(required),
            "stage runtime should contain {required}"
        );
    }
}

#[test]
fn win26100_msdelta_symbol_map_names_first_managed_atom() {
    for required in [
        "\"schema\": 1",
        "\"module\": \"msdelta.dll\"",
        "\"sha256\": \"ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb\"",
        "\"file_size\": 595360",
        "\"image_size\": 585728",
        "\"reader_read\"",
        "\"name\": \"BitReader::Read\"",
        "\"rva\": \"0x1af80\"",
        "\"atom\": \"CliMapBitstream\"",
        "\"name\": \"compo::CliMap::FromBitReader\"",
        "\"legacy_name\": \"CliMap::FromBitReader\"",
        "\"rva\": \"0x1a160\"",
        "\"capture\": \"cli_map_from_bitreader\"",
        "\"name\": \"msdelta-win26100-compo-cli-map-v1\"",
        "\"strings_offset\": 16",
        "\"user_strings_offset\": 64",
        "\"blob_offset\": 112",
        "\"guid_offset\": 160",
        "\"tables_offset\": 208",
        "\"table_stride\": 48",
        "\"table_count\": 64",
        "\"name\": \"msdelta-win26100-compo-rift-table-v1\"",
        "\"entry_size\": 16",
        "\"atom\": \"CliMetadataBitstream\"",
        "\"name\": \"compo::CliMetadata::InternalFromBitReader\"",
        "\"legacy_name\": \"CliMetadata::FromBitReader\"",
        "\"rva\": \"0x1cba0\"",
        "\"abi\": \"ms-x64-thiscall\"",
        "\"capture\": \"cli_metadata_internal_from_bitreader\"",
        "\"reader_layout\"",
        "\"name\": \"msdelta-win26100-bitreader-read-v1\"",
        "\"tail_bits_offset\": 24",
        "\"word_cursor_offset\": 32",
        "\"word_end_offset\": 40",
        "\"accumulator_offset\": 48",
        "\"available_bits_offset\": 56",
        "\"max_window_bits\": 1048576",
        "\"name\": \"msdelta-win26100-compo-cli-metadata-v1\"",
        "\"base_offset\": 16",
        "\"valid_table_mask_offset\": 80",
        "\"row_counts_offset\": 88",
        "\"strings\": 76",
        "\"guid\": 77",
        "\"blob\": 78",
        "\"atom\": \"CliCodedTokenMap\"",
        "\"name\": \"compo::CliMap::MapCoded\"",
        "\"legacy_name\": \"CliMap::MapCoded\"",
        "\"rva\": \"0x22578\"",
        "\"name\": \"compo::CliMap::MapCodedExact\"",
        "\"legacy_name\": \"CliMap::MapCodedExact\"",
        "\"rva\": \"0x499c0\"",
        "\"capture\": \"cli_map_coded_token_call\"",
        "\"name\": \"msdelta-win26100-compo-cli-map-coded-token-v1\"",
        "\"exact\": true",
        "\"exact\": false",
        "\"atom\": \"CliBlobCompressedInteger\"",
        "\"name\": \"compo::CliMetadata::GetBlobContent\"",
        "\"legacy_name\": \"CliMetadata::GetBlobContent\"",
        "\"rva\": \"0x1f5cc\"",
        "\"capture\": \"cli_blob_get_content_call\"",
        "\"name\": \"msdelta-win26100-compo-cli-metadata-get-blob-content-v1\"",
        "\"blob_stream_offset_offset\": 52",
        "\"blob_stream_size_offset\": 56",
        "\"max_prefix_bytes\": 4",
        "\"atom\": \"CliCompressionRift\"",
        "\"name\": \"CompressionRiftTableFromCliMap::Generate\"",
        "\"legacy_name\": \"CompressionRiftTableCli::FromCliMap\"",
        "\"rva\": \"0x1da60\"",
        "\"capture\": \"cli_compression_rift_generate\"",
        "\"name\": \"msdelta-win26100-compression-rift-from-cli-map-v1\"",
        "\"source_buffer_data_offset\": 56",
        "\"source_buffer_size_offset\": 64",
        "\"source_fill_offset_offset\": 72",
        "\"result_rift_table_ptr_offset\": 80",
    ] {
        assert!(
            WIN26100_MSDELTA_STAGE_MAP.contains(required),
            "stage symbol map should contain {required}"
        );
    }
}

#[test]
fn win26100_msdelta_symbol_map_json_is_structural() {
    let map: serde_json::Value =
        serde_json::from_str(WIN26100_MSDELTA_STAGE_MAP).expect("valid stage symbol map JSON");
    assert_eq!(map["schema"], 1);
    assert_eq!(map["module"], "msdelta.dll");

    let functions = map["functions"]
        .as_array()
        .expect("symbol map functions are an array");
    let mut hooks = std::collections::HashSet::new();
    for function in functions {
        let name = function["name"].as_str().expect("function has a name");
        let rva = function["rva"].as_str().expect("function has an rva");
        assert!(
            hooks.insert((name, rva)),
            "duplicate stage hook for {name} at {rva}"
        );
    }

    let cli_compression_rift = functions
        .iter()
        .find(|function| function["capture"] == "cli_compression_rift_generate")
        .expect("CliCompressionRift stage hook is present");
    assert_eq!(cli_compression_rift["atom"], "CliCompressionRift");
    assert_eq!(cli_compression_rift["rva"], "0x1da60");
    assert_eq!(
        cli_compression_rift["object_layout"]["source_buffer_data_offset"],
        56
    );
    assert_eq!(
        cli_compression_rift["object_layout"]["source_buffer_size_offset"],
        64
    );
    assert_eq!(
        cli_compression_rift["object_layout"]["source_fill_offset_offset"],
        72
    );
    assert_eq!(
        cli_compression_rift["object_layout"]["result_rift_table_ptr_offset"],
        80
    );
    assert_eq!(
        cli_compression_rift["object_layout"]["rift_table_layout"]["entry_size"],
        16
    );
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
    for required in [
        "\"schema\"",
        "\"FridaExportOracle\"",
        "\"FridaStageCapture\"",
        "\"target_atom\"",
        "\"objects\"",
    ] {
        assert!(
            CAPTURE_SCHEMA.contains(required),
            "capture schema should contain {required}"
        );
    }

    for required in [
        "\"schema\"",
        "\"FridaExportOracle\"",
        "\"ApplyDeltaB\"",
        "\"ApplyDeltaGetReverseB\"",
        "\"CreateDeltaB\"",
    ] {
        assert!(
            RUN_SCHEMA.contains(required),
            "run schema should contain {required}"
        );
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
        "\"objects\"",
        "\"FridaStageCapture\"",
        "\"target_atom\"",
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
