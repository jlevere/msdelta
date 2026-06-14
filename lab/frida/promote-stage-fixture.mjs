#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import process from "node:process";

const MODE_CLI_BLOB_COMPRESSED_INTEGER = "cli-blob-compressed-integer";

function usage() {
  return `usage:
  node promote-stage-fixture.mjs --mode cli-blob-compressed-integer --normalized <normalized-dir> --source-case <id> --out <fixture-dir> --case-id <id> [--force]

The normalized directory should contain run.json and cases/<source-case>/capture.json
from import-inject-capture.mjs. The current mode promotes successful
CliBlobCompressedInteger GetBlobContent call records, selecting one stable
representative per encoded-width/decoded-length/encoded-prefix tuple.`;
}

function parseArgs(argv) {
  const options = {
    mode: null,
    normalizedDir: null,
    sourceCase: null,
    outDir: null,
    caseId: null,
    fixtureSource: "lab/frida/capture-managed-corpus.sh",
    force: false,
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "--") {
      i += 1;
      continue;
    }
    if (arg === "--mode") {
      options.mode = argv[++i];
    } else if (arg === "--normalized") {
      options.normalizedDir = argv[++i];
    } else if (arg === "--source-case") {
      options.sourceCase = argv[++i];
    } else if (arg === "--out") {
      options.outDir = argv[++i];
    } else if (arg === "--case-id") {
      options.caseId = argv[++i];
    } else if (arg === "--fixture-source") {
      options.fixtureSource = argv[++i];
    } else if (arg === "--force") {
      options.force = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}\n${usage()}`);
    }
    i += 1;
  }

  for (const [name, value] of Object.entries(options)) {
    if (name === "force") {
      continue;
    }
    if (!value) {
      throw new Error(`--${name.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)} is required\n${usage()}`);
    }
  }
  if (options.mode !== MODE_CLI_BLOB_COMPRESSED_INTEGER) {
    throw new Error(`unsupported --mode ${options.mode}; expected ${MODE_CLI_BLOB_COMPRESSED_INTEGER}`);
  }
  for (const [name, value] of [
    ["--source-case", options.sourceCase],
    ["--case-id", options.caseId],
  ]) {
    if (!/^[A-Za-z0-9_.-]+$/.test(value)) {
      throw new Error(`${name} must be a non-empty file-safe identifier`);
    }
  }

  return options;
}

function resolveExistingPath(value) {
  if (path.isAbsolute(value)) {
    return value;
  }

  const cwdPath = path.resolve(value);
  if (fsSync.existsSync(cwdPath)) {
    return cwdPath;
  }

  if (process.env.INIT_CWD) {
    const initPath = path.resolve(process.env.INIT_CWD, value);
    if (fsSync.existsSync(initPath)) {
      return initPath;
    }
  }

  return cwdPath;
}

function resolveOutputPath(value) {
  if (path.isAbsolute(value)) {
    return value;
  }

  if (process.env.INIT_CWD) {
    const initPath = path.resolve(process.env.INIT_CWD, value);
    if (fsSync.existsSync(path.dirname(initPath))) {
      return initPath;
    }
  }

  return path.resolve(value);
}

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(text)).digest("hex");
}

function readJson(filePath) {
  return fs.readFile(filePath, "utf8").then(text => JSON.parse(text));
}

function cleanPrefix(prefix) {
  return {
    bytes: prefix.bytes,
    decode: prefix.decode,
  };
}

function stableInputs(objectValue) {
  return {
    blob_offset: objectValue.blob_offset,
    blob_stream: objectValue.blob_stream,
    encoded_prefix: cleanPrefix(objectValue.encoded_prefix),
  };
}

function stableModule(event) {
  return {
    name: event.module.name,
    sha256: event.module.sha256,
  };
}

function stableFunction(event) {
  return {
    rva: event.function.rva,
    abi: event.function.abi,
    capture: event.function.capture,
  };
}

function stableCliBlobObject(objectValue) {
  return {
    type: objectValue.type,
    native_layout: objectValue.native_layout,
    blob_offset: objectValue.blob_offset,
    blob_stream: objectValue.blob_stream,
    encoded_prefix: cleanPrefix(objectValue.encoded_prefix),
    result: {
      success: objectValue.result.success,
      decoded_length: objectValue.result.decoded_length,
      encoded_width: objectValue.result.encoded_width,
    },
  };
}

function moduleImageSize(run, moduleName) {
  const module = (run.modules || []).find(entry => entry.name === moduleName);
  return module && Number.isInteger(module.size) ? module.size : null;
}

function selectCliBlobCompressedIntegerCalls(sourceCaseDir, capture) {
  const sourceStageEvents = capture.events.filter(event => event.target_atom === "CliBlobCompressedInteger");
  const leaves = sourceStageEvents.filter(event => event.phase === "leave");
  const selectedByKey = new Map();

  for (const leave of leaves) {
    const objectRef = leave.objects && leave.objects[0];
    if (!objectRef) {
      continue;
    }
    const objectPath = path.join(sourceCaseDir, objectRef.path);
    const objectValue = JSON.parse(fsSync.readFileSync(objectPath, "utf8"));
    if (
      objectValue.type !== "CliBlobCompressedIntegerCallRecord" ||
      !objectValue.result ||
      objectValue.result.success !== true
    ) {
      continue;
    }

    const width = objectValue.result.encoded_width;
    const length = objectValue.result.decoded_length;
    const prefix = objectValue.encoded_prefix.bytes.slice(0, width).join(",");
    const key = `${width}:${length}:${prefix}`;
    if (!selectedByKey.has(key)) {
      selectedByKey.set(key, { leave, objectValue });
    }
  }

  const selected = Array.from(selectedByKey.values());
  selected.sort((a, b) => {
    const widthDelta = a.objectValue.result.encoded_width - b.objectValue.result.encoded_width;
    if (widthDelta !== 0) {
      return widthDelta;
    }
    const lengthDelta = a.objectValue.result.decoded_length - b.objectValue.result.decoded_length;
    if (lengthDelta !== 0) {
      return lengthDelta;
    }
    return a.objectValue.blob_offset - b.objectValue.blob_offset;
  });

  return { sourceStageEvents, selected };
}

function buildCliBlobCaptureEvents(selected) {
  const events = [];
  const objectWrites = [];
  let seq = 0;

  for (const { leave, objectValue } of selected) {
    seq += 1;
    const suffix = String(seq).padStart(3, "0");
    const callId = `cli-blob-compressed-integer-${suffix}`;
    const objectName = `${callId}.json`;
    const stableObj = stableCliBlobObject(objectValue);
    const objectText = `${JSON.stringify(stableObj, null, 2)}\n`;
    const objectHash = sha256Text(objectText);

    const base = {
      call_id: callId,
      seq,
      atom: "FridaStageCapture",
      target_atom: "CliBlobCompressedInteger",
      symbol: leave.symbol,
      module: stableModule(leave),
      function: stableFunction(leave),
      inputs: stableInputs(objectValue),
    };

    events.push({
      event_id: `${callId}-enter`,
      ...base,
      phase: "enter",
      objects: [],
      blobs: [],
    });
    events.push({
      event_id: `${callId}-leave`,
      ...base,
      phase: "leave",
      objects: [
        {
          slot: "normalized",
          path: `objects/${objectName}`,
          size: Buffer.byteLength(objectText),
          sha256: objectHash,
          note: "",
          type: stableObj.type,
        },
      ],
      blobs: [],
    });
    objectWrites.push({ name: objectName, text: objectText, sha256: objectHash });
  }

  return { events, objectWrites };
}

function tomlStringValue(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function buildCliBlobCaseToml(options, run, capture, sourceStageEvents, selected, objectWrites) {
  const first = selected[0];
  if (!first) {
    throw new Error("no successful CliBlobCompressedInteger call records found");
  }

  const { leave } = first;
  const imageSize = moduleImageSize(run, leave.module.name);
  if (imageSize === null) {
    throw new Error(`run.json is missing image size for ${leave.module.name}`);
  }

  const widthCounts = new Map();
  const decodedLengths = new Set();
  for (const item of selected) {
    const width = item.objectValue.result.encoded_width;
    widthCounts.set(width, (widthCounts.get(width) || 0) + 1);
    decodedLengths.add(item.objectValue.result.decoded_length);
  }

  const lines = [
    ["atom", "FridaStageCapture"],
    ["case", options.caseId],
    ["source_case", options.sourceCase],
    ["module", leave.module.name],
    ["module_sha256", leave.module.sha256],
    ["module_image_size", imageSize],
    ["symbol", leave.symbol],
    ["legacy_symbol", "CliMetadata::GetBlobContent"],
    ["rva", leave.function.rva],
    ["abi", leave.function.abi],
    ["capture_adapter", leave.function.capture],
    ["call_layout", first.objectValue.native_layout],
    ["target_atom", "CliBlobCompressedInteger"],
    ["transport", "frida-inject"],
    ["capture_mode", "file_sink"],
    ["fixture_source", options.fixtureSource],
    [
      "selection",
      "one representative per encoded-width/decoded-length/encoded-prefix tuple observed in the managed corpus",
    ],
    ["coverage_note", "current managed corpus covers successful one-byte compressed integer prefixes only"],
    ["export_event_count", capture.events.filter(event => event.atom === "FridaExportOracle").length],
    ["source_stage_event_count", sourceStageEvents.length],
    ["stage_event_count", selected.length * 2],
    ["stage_leave_object_count", selected.length],
    ["stage_leave_blob_count", 0],
    ["distinct_object_hash_count", new Set(objectWrites.map(write => write.sha256)).size],
    ["native_success_count", selected.length],
    ["native_failure_count", 0],
    ["one_byte_width_count", widthCounts.get(1) || 0],
    ["two_byte_width_count", widthCounts.get(2) || 0],
    ["four_byte_width_count", widthCounts.get(4) || 0],
    ["distinct_decoded_length_count", decodedLengths.size],
    ["normalization_error_count", (run.errors || []).length],
    ["reader_window_error_count", 0],
  ];

  return `${lines
    .map(([key, value]) => `${key} = ${typeof value === "string" ? tomlStringValue(value) : value}`)
    .join("\n")}\n`;
}

async function promoteCliBlobCompressedInteger(options, run, sourceCaseDir, capture, outDir) {
  const { sourceStageEvents, selected } = selectCliBlobCompressedIntegerCalls(sourceCaseDir, capture);
  const { events, objectWrites } = buildCliBlobCaptureEvents(selected);
  const first = selected[0];
  if (!first) {
    throw new Error("no successful CliBlobCompressedInteger call records found");
  }

  const promotedCapture = {
    schema: 1,
    atom: "FridaStageCapture",
    case_id: options.caseId,
    source_case_id: options.sourceCase,
    module_sha256: first.leave.module.sha256,
    target_atom: "CliBlobCompressedInteger",
    selection: "one representative per encoded-width/decoded-length/encoded-prefix tuple observed in the managed corpus",
    events,
  };

  const objectDir = path.join(outDir, "objects");
  await fs.mkdir(objectDir, { recursive: true });
  for (const objectWrite of objectWrites) {
    await fs.writeFile(path.join(objectDir, objectWrite.name), objectWrite.text);
  }
  await fs.writeFile(path.join(outDir, "capture.json"), `${JSON.stringify(promotedCapture, null, 2)}\n`);
  await fs.writeFile(
    path.join(outDir, "case.toml"),
    buildCliBlobCaseToml(options, run, capture, sourceStageEvents, selected, objectWrites)
  );

  return {
    fixture: outDir,
    selected: selected.length,
    source_stage_events: sourceStageEvents.length,
    widths: {
      one_byte: selected.filter(item => item.objectValue.result.encoded_width === 1).length,
      two_byte: selected.filter(item => item.objectValue.result.encoded_width === 2).length,
      four_byte: selected.filter(item => item.objectValue.result.encoded_width === 4).length,
    },
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const normalizedDir = resolveExistingPath(options.normalizedDir);
  const sourceCaseDir = path.join(normalizedDir, "cases", options.sourceCase);
  const outDir = resolveOutputPath(options.outDir);

  if (fsSync.existsSync(outDir)) {
    if (!options.force) {
      throw new Error(`output directory already exists: ${outDir}; pass --force to replace it`);
    }
    await fs.rm(outDir, { recursive: true, force: true });
  }
  await fs.mkdir(outDir, { recursive: true });

  const run = await readJson(path.join(normalizedDir, "run.json"));
  const capture = await readJson(path.join(sourceCaseDir, "capture.json"));

  let summary;
  if (options.mode === MODE_CLI_BLOB_COMPRESSED_INTEGER) {
    summary = await promoteCliBlobCompressedInteger(options, run, sourceCaseDir, capture, outDir);
  } else {
    throw new Error(`unsupported --mode ${options.mode}`);
  }
  console.log(JSON.stringify(summary, null, 2));
}

main().catch(error => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
