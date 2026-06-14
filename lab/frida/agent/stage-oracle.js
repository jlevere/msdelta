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
const BLOB_SINK_DIR =
  typeof globalThis.MSDELTA_STAGE_ORACLE_BLOB_DIR === "string"
    ? globalThis.MSDELTA_STAGE_ORACLE_BLOB_DIR
    : null;
const READY_FILE =
  typeof globalThis.MSDELTA_STAGE_ORACLE_READY_FILE === "string"
    ? globalThis.MSDELTA_STAGE_ORACLE_READY_FILE
    : null;

const hooked = new Set();
const reportedModules = new Set();
const activeReaderTracesByThread = new Map();
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

function writeBlobFile(eventId, slot, bytes) {
  const fileName = `${sanitizePart(eventId)}-${sanitizePart(slot)}.bin`;
  const filePath = joinPath(BLOB_SINK_DIR, fileName);
  const file = new File(filePath, "wb");
  try {
    file.write(bytes);
  } finally {
    file.close();
  }
  return filePath;
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

const STAGE_CAPTURE_ADAPTERS = globalThis.MSDELTA_STAGE_CAPTURE_ADAPTERS || Object.freeze({});

function stageReaderRuntime() {
  const runtime = globalThis.MSDELTA_STAGE_READER;
  if (!runtime) {
    throw new Error("MSDELTA_STAGE_READER runtime is not loaded");
  }
  return runtime;
}

function sendBlobFromBytes(eventId, slot, bytes, size, note) {
  const payload = {
    type: "blob",
    event_id: eventId,
    slot,
    ptr: "standalone",
    size,
    note: note || "",
  };
  if (!BLOB_SINK_DIR) {
    payload.size = 0;
    payload.note = "not captured: MSDELTA_STAGE_ORACLE_BLOB_DIR is not set";
    send(payload);
    return;
  }
  payload.file_sink_path = writeBlobFile(eventId, slot, bytes);
  send(payload);
}

function captureAdapter(fn) {
  const adapter = STAGE_CAPTURE_ADAPTERS[fn.capture];
  if (!adapter) {
    throw new Error(`unsupported stage capture adapter: ${fn.capture}`);
  }
  return adapter;
}

function normalizeObject(fn, callContext, retval) {
  return captureAdapter(fn).readObject(fn, callContext, retval);
}

function captureInputs(fn, args) {
  return captureAdapter(fn).captureInputs(fn, args);
}

function readPlanForObject(fn, objectValue) {
  if (!objectValue) {
    return null;
  }
  return captureAdapter(fn).readPlan(fn, objectValue);
}

function captureCallContext(fn, args) {
  return {
    this_ptr: args[0],
    reader_ptr: fn.reader_layout ? args[1] : null,
    inputs: captureInputs(fn, args),
  };
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

function captureReaderSnapshot(readerPtr, layout) {
  if (!layout) {
    return { skipped: true, value: null };
  }
  try {
    return { skipped: false, value: stageReaderRuntime().snapshotBitReader(readerPtr, layout) };
  } catch (error) {
    return {
      skipped: false,
      value: null,
      error: String(error && error.stack ? error.stack : error),
    };
  }
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
  if (!SYMBOL_MAP.functions.every(fn => hooked.has(`${SYMBOL_MAP.module}:${fn.name}:${fn.rva}`))) {
    return false;
  }
  if (SYMBOL_MAP.reader_read) {
    return hooked.has(`${SYMBOL_MAP.module}:${SYMBOL_MAP.reader_read.name}:${SYMBOL_MAP.reader_read.rva}`);
  }
  return true;
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

function threadTraceStack(threadId) {
  const key = String(threadId);
  let stack = activeReaderTracesByThread.get(key);
  if (!stack) {
    stack = [];
    activeReaderTracesByThread.set(key, stack);
  }
  return stack;
}

function pushReaderTrace(threadId, trace) {
  threadTraceStack(threadId).push(trace);
}

function popReaderTrace(threadId, trace) {
  const stack = threadTraceStack(threadId);
  const popped = stack.pop();
  if (stack.length === 0) {
    activeReaderTracesByThread.delete(String(threadId));
  }
  if (popped !== trace) {
    trace.error = "reader trace stack mismatch";
  }
}

function currentReaderTrace(threadId, readerPtr) {
  const stack = activeReaderTracesByThread.get(String(threadId));
  if (!stack || stack.length === 0) {
    return null;
  }
  const trace = stack[stack.length - 1];
  if (trace.reader_ptr !== readerPtr.toString()) {
    return null;
  }
  return trace;
}

function installReaderReadHook(moduleInfo) {
  if (!SYMBOL_MAP.reader_read) {
    return;
  }

  const fn = SYMBOL_MAP.reader_read;
  const key = `${SYMBOL_MAP.module}:${fn.name}:${fn.rva}`;
  if (hooked.has(key)) {
    return;
  }
  if (!SUPPORTED_ARCH || fn.abi !== "ms-x64-thiscall") {
    log("error", "reader hook skipped: unsupported ABI or process architecture", {
      arch: Process.arch,
      pointer_size: POINTER_SIZE,
      symbol: fn.name,
      abi: fn.abi,
    });
    return;
  }

  let rva;
  try {
    rva = parseRva(fn.rva);
  } catch (error) {
    log("error", "reader hook skipped: invalid RVA", {
      symbol: fn.name,
      rva: fn.rva,
      error: String(error),
    });
    return;
  }

  const address = moduleInfo.base.add(rva);
  Interceptor.attach(address, {
    onEnter(args) {
      this.trace = null;
      this.index = null;
      const threadId = Process.getCurrentThreadId();
      const readerPtr = args[0];
      const trace = currentReaderTrace(threadId, readerPtr);
      if (!trace) {
        return;
      }

      const width = args[1].toInt32();
      const index = trace.reads.length;
      if (width < 0 || width > 32) {
        trace.error = `reader trace saw unsupported read width ${width}`;
        return;
      }
      trace.reads.push({
        index,
        width,
        value: null,
      });
      this.trace = trace;
      this.index = index;
    },
    onLeave(retval) {
      if (!this.trace || this.index === null) {
        return;
      }
      this.trace.reads[this.index].value = BigInt(retval.toString()) & 0xffffffffn;
    },
  });

  hooked.add(key);
  reportModule(moduleInfo);
  log("info", "hooked reader function", {
    module: moduleInfo.name,
    sha256: SYMBOL_MAP.sha256,
    symbol: fn.name,
    rva: fn.rva,
    address: address.toString(),
  });
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

  try {
    captureAdapter(fn);
  } catch (error) {
    log("error", "stage hook skipped: unsupported capture adapter", {
      symbol: fn.name,
      capture: fn.capture,
      error: String(error),
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
      this.callContext = captureCallContext(fn, args);
      this.traceThreadId = Process.getCurrentThreadId();
      this.readerTrace = null;
      this.readerBefore = captureReaderSnapshot(this.callContext.reader_ptr, fn.reader_layout);
      if (fn.reader_layout && SYMBOL_MAP.reader_read) {
        this.readerTrace = {
          reader_ptr: this.callContext.reader_ptr.toString(),
          reads: [],
          error: null,
        };
        pushReaderTrace(this.traceThreadId, this.readerTrace);
      }
      sendEvent(
        beginEvent(fn, moduleInfo, "enter", this.callId, {
          inputs: this.callContext.inputs,
        })
      );
    },
    onLeave(retval) {
      const fields = {
        retval: retval.toString(),
        inputs: this.callContext.inputs,
        outputs: {
          this_ptr: this.callContext.this_ptr.toString(),
        },
      };
      let objectValue = null;
      let readerWindow = null;
      if (this.readerTrace) {
        popReaderTrace(this.traceThreadId, this.readerTrace);
      }
      try {
        objectValue = normalizeObject(this.fn, this.callContext, retval);
        if (objectValue) {
          fields.objects = { normalized: "pending" };
        }
      } catch (error) {
        fields.error = {
          type: "object_normalization_failed",
          message: String(error && error.stack ? error.stack : error),
        };
      }
      if (this.fn.reader_layout) {
        const readerAfter = captureReaderSnapshot(this.callContext.reader_ptr, this.fn.reader_layout);
        if (this.readerBefore.error || readerAfter.error) {
          fields.reader_window = {
            native_layout: this.fn.reader_layout.name,
            error: this.readerBefore.error || readerAfter.error,
          };
        } else {
          try {
            if (this.readerTrace && this.readerTrace.reads.length > 0) {
              readerWindow = stageReaderRuntime().buildReaderWindowFromTrace(
                this.readerBefore.value,
                readerAfter.value,
                this.fn.reader_layout,
                this.readerTrace
              );
            } else {
              readerWindow = stageReaderRuntime().buildReaderWindow(
                this.readerBefore.value,
                readerAfter.value,
                this.fn.reader_layout,
                readPlanForObject(this.fn, objectValue)
              );
            }
            if (readerWindow) {
              fields.reader_window = readerWindow.metadata;
              fields.blobs = { reader_bitstream: "pending" };
            }
          } catch (error) {
            fields.reader_window = {
              native_layout: this.fn.reader_layout.name,
              error: String(error && error.stack ? error.stack : error),
            };
          }
        }
      }
      const event = beginEvent(this.fn, this.moduleInfo, "leave", this.callId, fields);
      sendEvent(event);
      if (objectValue) {
        writeObject(event.event_id, "normalized", objectValue);
      }
      if (readerWindow) {
        sendBlobFromBytes(
          event.event_id,
          "reader-bitstream",
          readerWindow.bytes,
          readerWindow.size,
          "standalone BitReader stream copied from the native reader window"
        );
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
  installReaderReadHook(moduleInfo);
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
