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

function readU64Hex(address) {
  const value = address.readU64();
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function readU64Number(address, label) {
  const value = Number.parseInt(address.readU64().toString(10), 10);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} is outside JavaScript's safe integer range`);
  }
  return value;
}

function readU64BigInt(address) {
  return BigInt(address.readU64().toString(10));
}

function readS64Number(address, label) {
  const value = Number.parseInt(address.readS64().toString(10), 10);
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} is outside JavaScript's safe integer range`);
  }
  return value;
}

function readS64Value(address) {
  const text = address.readS64().toString(10);
  const value = Number.parseInt(text, 10);
  if (Number.isSafeInteger(value)) {
    return value;
  }
  return text;
}

function pointerNumber(value, label) {
  const text = value.toString();
  const parsed = Number.parseInt(text.startsWith("0x") ? text.slice(2) : text, text.startsWith("0x") ? 16 : 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} pointer is outside JavaScript's safe integer range: ${text}`);
  }
  return parsed;
}

function pointerDelta(start, end, label) {
  const startValue = pointerNumber(start, `${label} start`);
  const endValue = pointerNumber(end, `${label} end`);
  const value = endValue - startValue;
  if (value < 0) {
    throw new Error(
      `${label} pointer range is negative: start=${start.toString()} end=${end.toString()}`
    );
  }
  return value;
}

function snapshotBitReader(readerPtr, layout) {
  if (!layout) {
    return null;
  }
  if (readerPtr.isNull()) {
    throw new Error("reader pointer is null");
  }

  const tailBits = readU64Number(readerPtr.add(layout.tail_bits_offset), "tail bits");
  const availableBits = readerPtr.add(layout.available_bits_offset).readU32();
  const wordCursor = readerPtr.add(layout.word_cursor_offset).readPointer();
  const wordEnd = readerPtr.add(layout.word_end_offset).readPointer();
  const wordBytes = pointerDelta(wordCursor, wordEnd, "reader word cursor");
  const accumulator = readU64BigInt(readerPtr.add(layout.accumulator_offset));

  if (tailBits > 31) {
    throw new Error(`reader tail bits out of range: ${tailBits}`);
  }
  if (availableBits > 63) {
    throw new Error(`reader available bits out of range: ${availableBits}`);
  }
  if (wordBytes % 4 !== 0) {
    throw new Error(`reader word cursor range is not 32-bit aligned: ${wordBytes}`);
  }

  const remainingBits = availableBits + wordBytes * 8 + tailBits;
  if (remainingBits < 0 || remainingBits > layout.max_remaining_bits) {
    throw new Error(`reader remaining bits out of range: ${remainingBits}`);
  }

  return {
    native_layout: layout.name,
    accumulator,
    word_cursor: wordCursor,
    word_end: wordEnd,
    available_bits: availableBits,
    tail_bits: tailBits,
    word_bytes: wordBytes,
    remaining_bits: remainingBits,
  };
}

function setBit(bytes, bitIndex, bit) {
  if (bit !== 0) {
    bytes[Math.floor(bitIndex / 8)] |= 1 << (bitIndex % 8);
  }
}

function bitMask(width) {
  return (1n << BigInt(width)) - 1n;
}

function readTailValue(address, tailBits) {
  let value = 0n;
  const byteCount = Math.ceil(tailBits / 8);
  for (let i = 0; i < byteCount; i += 1) {
    value |= BigInt(address.add(i).readU8()) << BigInt(i * 8);
  }
  return value;
}

function cloneReaderState(snapshot) {
  return {
    native_layout: snapshot.native_layout,
    accumulator: snapshot.accumulator,
    word_cursor: snapshot.word_cursor,
    word_end: snapshot.word_end,
    available_bits: snapshot.available_bits,
    tail_bits: snapshot.tail_bits,
  };
}

function replayNativeRead(state, width) {
  if (width < 0 || width > 32) {
    throw new Error(`unsupported native read width: ${width}`);
  }
  if (width > state.available_bits) {
    throw new Error(`native read width ${width} exceeds available bits ${state.available_bits}`);
  }

  const value = width === 0 ? 0n : state.accumulator & bitMask(width);
  state.accumulator >>= BigInt(width);
  state.available_bits -= width;

  if (state.available_bits < 32) {
    if (state.word_cursor.compare(state.word_end) !== 0) {
      const word = BigInt(state.word_cursor.readU32());
      state.word_cursor = state.word_cursor.add(4);
      state.accumulator |= word << BigInt(state.available_bits);
      state.available_bits += 32;
    } else if (state.tail_bits !== 0) {
      const tailBits = state.tail_bits;
      const tail = readTailValue(state.word_end, tailBits);
      state.accumulator |= tail << BigInt(state.available_bits);
      state.available_bits += tailBits;
      state.tail_bits = 0;
    }
  }

  return value;
}

function finishStandaloneBitstream(out, bitCount) {
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  out[0] = (out[0] & 0xf8) | (paddingBits & 7);
  return {
    bytes: out.buffer,
    padding_bits: paddingBits,
    size: out.byteLength,
  };
}

function buildStandaloneBitstreamFromReadPlan(before, readPlan) {
  const bitCount = readPlan.reduce((total, width) => total + width, 0);
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (const width of readPlan) {
    const value = replayNativeRead(replay, width);
    for (let i = 0; i < width; i += 1) {
      setBit(out, outBit, Number((value >> BigInt(i)) & 1n));
      outBit += 1;
    }
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function buildStandaloneBitstreamFromReadTrace(before, readTrace) {
  if (!readTrace || !Array.isArray(readTrace.reads) || readTrace.reads.length === 0) {
    throw new Error("reader trace has no native reads");
  }

  const bitCount = readTrace.reads.reduce((total, read) => total + read.width, 0);
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (const read of readTrace.reads) {
    const replayed = replayNativeRead(replay, read.width);
    if (read.value === null || read.value === undefined) {
      throw new Error(`reader trace read ${read.index} has no return value`);
    }
    if (replayed !== read.value) {
      throw new Error(
        `reader trace read ${read.index} value mismatch: native=${read.value.toString()} replay=${replayed.toString()} width=${read.width}`
      );
    }
    for (let i = 0; i < read.width; i += 1) {
      setBit(out, outBit, Number((read.value >> BigInt(i)) & 1n));
      outBit += 1;
    }
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function buildStandaloneBitstreamFromWindowBits(before, bitCount) {
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (let i = 0; i < bitCount; i += 1) {
    const value = replayNativeRead(replay, 1);
    setBit(out, outBit, Number(value & 1n));
    outBit += 1;
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function cliMetadataReadPlan(record) {
  const widths = [1];
  if (!record.present) {
    return widths;
  }

  for (let i = 0; i < 15; i += 1) {
    widths.push(32);
  }
  widths.push(1, 1, 1, 32, 32);

  const validMask = BigInt(record.valid_table_mask);
  for (let tableId = 0; tableId < 64; tableId += 1) {
    if ((validMask & (1n << BigInt(tableId))) !== 0n) {
      widths.push(32);
    }
  }
  return widths;
}

function readPlanForObject(fn, objectValue) {
  if (!objectValue) {
    return null;
  }
  if (fn.capture === "cli_metadata_internal_from_bitreader") {
    return cliMetadataReadPlan(objectValue);
  }
  return null;
}

function replayMatchesSnapshot(replay, after) {
  return (
    replay.word_cursor.compare(after.word_cursor) === 0 &&
    replay.word_end.compare(after.word_end) === 0 &&
    replay.available_bits === after.available_bits &&
    replay.tail_bits === after.tail_bits &&
    replay.accumulator === after.accumulator
  );
}

function buildReaderWindow(before, after, layout, readPlan) {
  if (!before || !after) {
    return null;
  }
  if (before.native_layout !== after.native_layout) {
    throw new Error("reader layout changed during call");
  }
  if (!readPlan || readPlan.length === 0) {
    throw new Error("reader capture has no read plan");
  }

  const bitCount = before.remaining_bits - after.remaining_bits;
  if (bitCount === 0) {
    throw new Error("reader did not consume any bits");
  }
  if (bitCount < 0) {
    throw new Error("reader remaining bits increased during call");
  }
  if (bitCount > layout.max_window_bits) {
    throw new Error(`reader window is larger than max_window_bits: ${bitCount}`);
  }

  const plannedBits = readPlan.reduce((total, width) => total + width, 0);
  if (plannedBits !== bitCount) {
    throw new Error(`reader read-plan bits ${plannedBits} do not match native consumption ${bitCount}`);
  }

  const { standalone, replay } = buildStandaloneBitstreamFromReadPlan(before, readPlan);
  if (!replayMatchesSnapshot(replay, after)) {
    throw new Error("replayed reader state does not match native exit state");
  }

  return {
    metadata: {
      native_layout: layout.name,
      bit_count: bitCount,
      read_count: readPlan.length,
      remaining_bits_before: before.remaining_bits,
      remaining_bits_after: after.remaining_bits,
      standalone_size: standalone.size,
      standalone_padding_bits: standalone.padding_bits,
    },
    bytes: standalone.bytes,
    size: standalone.size,
  };
}

function buildReaderWindowFromTrace(before, after, layout, readTrace) {
  if (!before || !after) {
    return null;
  }
  if (before.native_layout !== after.native_layout) {
    throw new Error("reader layout changed during call");
  }
  if (readTrace.error) {
    throw new Error(readTrace.error);
  }

  const bitCount = before.remaining_bits - after.remaining_bits;
  if (bitCount === 0) {
    throw new Error("reader did not consume any bits");
  }
  if (bitCount < 0) {
    throw new Error("reader remaining bits increased during call");
  }
  if (bitCount > layout.max_window_bits) {
    throw new Error(`reader window is larger than max_window_bits: ${bitCount}`);
  }

  const tracedBits = readTrace.reads.reduce((total, read) => total + read.width, 0);
  if (tracedBits > bitCount) {
    throw new Error(`reader trace bits ${tracedBits} exceed native consumption ${bitCount}`);
  }

  const completeTrace = tracedBits === bitCount;
  const { standalone, replay } = completeTrace
    ? buildStandaloneBitstreamFromReadTrace(before, readTrace)
    : buildStandaloneBitstreamFromWindowBits(before, bitCount);
  if (!replayMatchesSnapshot(replay, after)) {
    throw new Error("replayed reader window state does not match native exit state");
  }

  return {
    metadata: {
      native_layout: layout.name,
      trace_source: completeTrace ? "BitReader::Read" : "reader-window",
      bit_count: bitCount,
      read_count: readTrace.reads.length,
      traced_bit_count: tracedBits,
      remaining_bits_before: before.remaining_bits,
      remaining_bits_after: after.remaining_bits,
      standalone_size: standalone.size,
      standalone_padding_bits: standalone.padding_bits,
    },
    bytes: standalone.bytes,
    size: standalone.size,
  };
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

function readRiftTableRecord(tablePtr, layout, label) {
  const initialized = tablePtr.add(layout.initialized_offset).readU8() !== 0;
  if (!initialized) {
    throw new Error(`${label} RiftTable is not initialized`);
  }

  const count = readU64Number(tablePtr.add(layout.count_offset), `${label} RiftTable count`);
  const capacity = readU64Number(tablePtr.add(layout.capacity_offset), `${label} RiftTable capacity`);
  const entriesPtr = tablePtr.add(layout.entries_offset).readPointer();
  const sorted = tablePtr.add(layout.sorted_offset).readU8() !== 0;
  if (count > layout.max_entries) {
    throw new Error(`${label} RiftTable count ${count} exceeds max_entries ${layout.max_entries}`);
  }
  if (count > capacity) {
    throw new Error(`${label} RiftTable count ${count} exceeds capacity ${capacity}`);
  }
  if (count > 0 && entriesPtr.isNull()) {
    throw new Error(`${label} RiftTable has entries but a null entries pointer`);
  }

  const entries = [];
  for (let i = 0; i < count; i += 1) {
    const entryPtr = entriesPtr.add(i * layout.entry_size);
    entries.push({
      source: readS64Value(entryPtr.add(layout.entry_source_offset)),
      target: readS64Value(entryPtr.add(layout.entry_target_offset)),
    });
  }

  return {
    entries,
    sorted,
  };
}

function readCliMapRecord(thisPtr, layout) {
  const riftLayout = layout.rift_table_layout;
  const tables = [];
  for (let tableId = 0; tableId < layout.table_count; tableId += 1) {
    tables.push(
      readRiftTableRecord(
        thisPtr.add(layout.tables_offset + tableId * layout.table_stride),
        riftLayout,
        `tables[${tableId}]`
      )
    );
  }

  return {
    type: "CliMapBitstreamRecord",
    native_layout: layout.name,
    strings: readRiftTableRecord(thisPtr.add(layout.strings_offset), riftLayout, "strings"),
    user_strings: readRiftTableRecord(thisPtr.add(layout.user_strings_offset), riftLayout, "user_strings"),
    blob: readRiftTableRecord(thisPtr.add(layout.blob_offset), riftLayout, "blob"),
    guid: readRiftTableRecord(thisPtr.add(layout.guid_offset), riftLayout, "guid"),
    tables,
  };
}

function readCliCodedTokenMapCallRecord(fn, callContext, retval) {
  const exact = fn.call_layout && fn.call_layout.exact === true;
  return {
    type: "CliCodedTokenMapCallRecord",
    native_layout: fn.call_layout ? fn.call_layout.name : "msdelta-cli-coded-token-map-call-v1",
    operation: exact ? "MapCodedExact" : "MapCoded",
    kind: callContext.inputs.kind,
    raw: callContext.inputs.raw,
    result: nativePointerU32(retval, "coded-token return"),
    map: readCliMapRecord(callContext.this_ptr, fn.object_layout),
  };
}

function normalizeObject(fn, callContext, retval) {
  if (fn.capture === "cli_metadata_internal_from_bitreader") {
    return readCliMetadataRecord(callContext.this_ptr, fn.object_layout);
  }
  if (fn.capture === "cli_map_from_bitreader") {
    return readCliMapRecord(callContext.this_ptr, fn.object_layout);
  }
  if (fn.capture === "cli_map_coded_token_call") {
    return readCliCodedTokenMapCallRecord(fn, callContext, retval);
  }
  if (fn.capture === "reader_bitstream_only") {
    return null;
  }
  throw new Error(`unsupported stage capture adapter: ${fn.capture}`);
}

function nativePointerU32(value, label) {
  const raw = BigInt(value.toString());
  const masked = raw & 0xffffffffn;
  const parsed = Number(masked);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${label} is not a uint32: ${value.toString()}`);
  }
  return parsed;
}

function captureInputs(fn, args) {
  if (fn.capture === "cli_map_coded_token_call") {
    return {
      this_ptr: args[0].toString(),
      kind: nativePointerU32(args[1], "coded-token kind"),
      raw: nativePointerU32(args[2], "coded-token raw value"),
    };
  }
  return {
    this_ptr: args[0].toString(),
    reader_ptr: args[1].toString(),
  };
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
    return { skipped: false, value: snapshotBitReader(readerPtr, layout) };
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
              readerWindow = buildReaderWindowFromTrace(
                this.readerBefore.value,
                readerAfter.value,
                this.fn.reader_layout,
                this.readerTrace
              );
            } else {
              readerWindow = buildReaderWindow(
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
