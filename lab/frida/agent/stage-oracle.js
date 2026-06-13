"use strict";

(() => {
"use strict";

const POINTER_SIZE = Process.pointerSize;
const SUPPORTED_ARCH = Process.arch === "x64" && POINTER_SIZE === 8;
const SYMBOL_MAP =
  typeof globalThis.MSDELTA_STAGE_ORACLE_SYMBOL_MAP === "object"
    ? globalThis.MSDELTA_STAGE_ORACLE_SYMBOL_MAP
    : null;
const SELECTED_SHA256 =
  typeof globalThis.MSDELTA_STAGE_ORACLE_SELECTED_SHA256 === "string"
    ? globalThis.MSDELTA_STAGE_ORACLE_SELECTED_SHA256.toLowerCase()
    : null;
const OBJECT_SINK_DIR =
  typeof globalThis.MSDELTA_STAGE_ORACLE_OBJECT_DIR === "string"
    ? globalThis.MSDELTA_STAGE_ORACLE_OBJECT_DIR
    : null;
const READY_FILE =
  typeof globalThis.MSDELTA_STAGE_ORACLE_READY_FILE === "string"
    ? globalThis.MSDELTA_STAGE_ORACLE_READY_FILE
    : null;

const hooked = new Set();
const reportedModules = new Set();
let readyReported = false;
let disabled = false;
let sequence = 0;

function log(level, message, detail) {
  send({ type: "log", level, message, detail: detail || null });
}

function nextEventId(symbol) {
  sequence += 1;
  return `${Date.now()}-${Process.id}-stage-${sequence}-${sanitizePart(symbol)}`;
}

function sanitizePart(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]/g, "_");
}

function joinPath(dir, fileName) {
  const sep = dir.indexOf("\\") !== -1 ? "\\" : "/";
  return dir.replace(/[\\/]+$/, "") + sep + fileName;
}

function writeTextFile(filePath, text) {
  const file = new File(filePath, "w");
  try {
    file.write(text);
  } finally {
    file.close();
  }
}

function moduleByName(name) {
  const lower = name.toLowerCase();
  return Process.enumerateModules().find(moduleInfo => moduleInfo.name.toLowerCase() === lower);
}

function reportModule(moduleInfo) {
  const key = `${moduleInfo.name}:${moduleInfo.path}`;
  if (reportedModules.has(key)) {
    return;
  }
  reportedModules.add(key);
  send({
    type: "module",
    module: {
      name: moduleInfo.name,
      path: moduleInfo.path,
      base: moduleInfo.base.toString(),
      size: moduleInfo.size,
    },
  });
}

function parseRva(value) {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return value;
  }
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error(`invalid RVA: ${value}`);
  }
  const parsed = Number.parseInt(value.slice(2), 16);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`invalid RVA: ${value}`);
  }
  return parsed;
}

function readU64Hex(address) {
  const value = address.readU64();
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function readCliMetadataRecord(thisPtr, layout) {
  const baseOffset = layout.base_offset;
  const rowCountsOffset = layout.row_counts_offset;
  const fields = layout.fields.map(field => ({
    name: field.name,
    value: thisPtr.add(baseOffset + field.offset).readU32(),
  }));

  const byName = new Map(fields.map(field => [field.name, field.value]));
  const rowCounts = [];
  for (let tableId = 0; tableId < 64; tableId += 1) {
    rowCounts.push(thisPtr.add(rowCountsOffset + tableId * 4).readU32());
  }

  const validTableMask = readU64Hex(thisPtr.add(layout.valid_table_mask_offset));
  const present =
    byName.get("metadata_size") !== 0 ||
    byName.get("metadata_file_offset") !== 0 ||
    validTableMask !== "0x0000000000000000" ||
    rowCounts.some(count => count !== 0);

  return {
    type: "CliMetadataBitstreamRecord",
    native_layout: layout.name,
    present,
    metadata_file_offset: byName.get("metadata_file_offset"),
    metadata_size: byName.get("metadata_size"),
    metadata_rva: byName.get("metadata_rva"),
    stream_count: byName.get("stream_count"),
    stream_headers_end: byName.get("stream_headers_end"),
    streams: {
      strings: {
        offset: byName.get("strings_offset"),
        size: byName.get("strings_size"),
      },
      user_strings: {
        offset: byName.get("user_strings_offset"),
        size: byName.get("user_strings_size"),
      },
      blob: {
        offset: byName.get("blob_offset"),
        size: byName.get("blob_size"),
      },
      guid: {
        offset: byName.get("guid_offset"),
        size: byName.get("guid_size"),
      },
      tables: {
        offset: byName.get("tables_offset"),
        size: byName.get("tables_size"),
      },
    },
    heap_widths: {
      strings: thisPtr.add(layout.heap_widths.strings).readU8() !== 0,
      guid: thisPtr.add(layout.heap_widths.guid).readU8() !== 0,
      blob: thisPtr.add(layout.heap_widths.blob).readU8() !== 0,
    },
    valid_table_mask: validTableMask,
    row_counts: rowCounts,
  };
}

function normalizeObject(fn, thisPtr) {
  if (fn.capture === "cli_metadata_internal_from_bitreader") {
    return readCliMetadataRecord(thisPtr, fn.object_layout);
  }
  throw new Error(`unsupported stage capture adapter: ${fn.capture}`);
}

function writeObject(eventId, slot, objectValue) {
  const json = `${JSON.stringify(objectValue, null, 2)}\n`;
  if (!OBJECT_SINK_DIR) {
    send({
      type: "object",
      event_id: eventId,
      slot,
      note: "not captured: MSDELTA_STAGE_ORACLE_OBJECT_DIR is not set",
    });
    return;
  }

  const fileName = `${sanitizePart(eventId)}-${sanitizePart(slot)}.json`;
  const filePath = joinPath(OBJECT_SINK_DIR, fileName);
  writeTextFile(filePath, json);
  send({
    type: "object",
    event_id: eventId,
    slot,
    file_sink_path: filePath,
    note: "",
  });
}

function beginEvent(fn, moduleInfo, phase, callId, fields) {
  return {
    event_id: `${callId}-${phase}`,
    call_id: callId,
    seq: sequence,
    atom: "FridaStageCapture",
    target_atom: fn.atom,
    symbol: fn.name,
    phase,
    module: {
      name: moduleInfo.name,
      path: moduleInfo.path,
      base: moduleInfo.base.toString(),
      sha256: SYMBOL_MAP.sha256,
    },
    function: {
      rva: fn.rva,
      abi: fn.abi,
      capture: fn.capture,
    },
    thread_id: Process.getCurrentThreadId(),
    timestamp_ms: Date.now(),
    ...fields,
  };
}

function sendEvent(event) {
  send({ type: "event", event });
}

function allStageHooksInstalled() {
  if (!SYMBOL_MAP || !Array.isArray(SYMBOL_MAP.functions)) {
    return false;
  }
  return SYMBOL_MAP.functions.every(fn => hooked.has(`${SYMBOL_MAP.module}:${fn.name}:${fn.rva}`));
}

function maybeReportReady() {
  if (!READY_FILE || readyReported || !allStageHooksInstalled()) {
    return;
  }
  writeTextFile(READY_FILE, "ready\n");
  readyReported = true;
  log("info", "stage ready file written", {
    path: READY_FILE,
    hooks: Array.from(hooked).sort(),
  });
}

function validateMap() {
  if (!SYMBOL_MAP) {
    log("info", "stage capture disabled: no symbol map supplied");
    disabled = true;
    return false;
  }
  if (SYMBOL_MAP.schema !== 1 || typeof SYMBOL_MAP.module !== "string") {
    log("error", "stage capture disabled: malformed symbol map header", { symbol_map: SYMBOL_MAP });
    disabled = true;
    return false;
  }
  if (typeof SYMBOL_MAP.sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(SYMBOL_MAP.sha256)) {
    log("error", "stage capture disabled: symbol map is missing sha256", { module: SYMBOL_MAP.module });
    disabled = true;
    return false;
  }
  if (SELECTED_SHA256 && SYMBOL_MAP.sha256.toLowerCase() !== SELECTED_SHA256) {
    log("error", "stage capture disabled: selected module hash does not match symbol map", {
      selected_sha256: SELECTED_SHA256,
      map_sha256: SYMBOL_MAP.sha256,
      module: SYMBOL_MAP.module,
    });
    disabled = true;
    return false;
  }
  if (!Array.isArray(SYMBOL_MAP.functions) || SYMBOL_MAP.functions.length === 0) {
    log("error", "stage capture disabled: symbol map has no functions", { module: SYMBOL_MAP.module });
    disabled = true;
    return false;
  }
  return true;
}

function installStageHook(moduleInfo, fn) {
  const key = `${SYMBOL_MAP.module}:${fn.name}:${fn.rva}`;
  if (hooked.has(key)) {
    return;
  }

  if (!SUPPORTED_ARCH || fn.abi !== "ms-x64-thiscall") {
    log("error", "stage hook skipped: unsupported ABI or process architecture", {
      arch: Process.arch,
      pointer_size: POINTER_SIZE,
      symbol: fn.name,
      abi: fn.abi,
    });
    return;
  }

  if (Number.isInteger(SYMBOL_MAP.image_size) && moduleInfo.size !== SYMBOL_MAP.image_size) {
    log("error", "stage hook skipped: mapped image size does not match symbol map", {
      module: moduleInfo.name,
      expected_image_size: SYMBOL_MAP.image_size,
      actual_image_size: moduleInfo.size,
      sha256: SYMBOL_MAP.sha256,
    });
    return;
  }

  let rva;
  try {
    rva = parseRva(fn.rva);
  } catch (error) {
    log("error", "stage hook skipped: invalid RVA", {
      symbol: fn.name,
      rva: fn.rva,
      error: String(error),
    });
    return;
  }
  const address = moduleInfo.base.add(rva);
  Interceptor.attach(address, {
    onEnter(args) {
      this.fn = fn;
      this.moduleInfo = moduleInfo;
      this.callId = nextEventId(fn.name);
      this.thisPtr = args[0];
      this.readerPtr = args[1];
      sendEvent(
        beginEvent(fn, moduleInfo, "enter", this.callId, {
          inputs: {
            this_ptr: this.thisPtr.toString(),
            reader_ptr: this.readerPtr.toString(),
          },
        })
      );
    },
    onLeave(retval) {
      const fields = {
        retval: retval.toString(),
        outputs: {
          this_ptr: this.thisPtr.toString(),
        },
      };
      let objectValue = null;
      try {
        objectValue = normalizeObject(this.fn, this.thisPtr);
        fields.objects = { normalized: "pending" };
      } catch (error) {
        fields.error = {
          type: "object_normalization_failed",
          message: String(error && error.stack ? error.stack : error),
        };
      }
      const event = beginEvent(this.fn, this.moduleInfo, "leave", this.callId, fields);
      sendEvent(event);
      if (objectValue) {
        writeObject(event.event_id, "normalized", objectValue);
      }
    },
  });
  hooked.add(key);
  reportModule(moduleInfo);
  log("info", "hooked stage function", {
    module: moduleInfo.name,
    sha256: SYMBOL_MAP.sha256,
    symbol: fn.name,
    rva: fn.rva,
    address: address.toString(),
  });
}

function installAvailableStageHooks() {
  if (disabled || !validateMap()) {
    return;
  }
  const moduleInfo = moduleByName(SYMBOL_MAP.module);
  if (!moduleInfo) {
    return;
  }
  for (const fn of SYMBOL_MAP.functions) {
    installStageHook(moduleInfo, fn);
  }
  maybeReportReady();
}

installAvailableStageHooks();
const hookTimer = setInterval(installAvailableStageHooks, 250);
setTimeout(() => {
  clearInterval(hookTimer);
  if (SYMBOL_MAP && !allStageHooksInstalled()) {
    log("error", "stage hook polling stopped before all hooks were installed", {
      module: SYMBOL_MAP.module,
      hooked: Array.from(hooked).sort(),
      expected: SYMBOL_MAP.functions.map(fn => `${SYMBOL_MAP.module}:${fn.name}:${fn.rva}`),
    });
  } else {
    log("info", "stopped stage hook polling", { hooked: Array.from(hooked).length });
  }
}, 30000);
})();
