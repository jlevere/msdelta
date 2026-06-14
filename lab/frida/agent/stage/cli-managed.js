"use strict";

(() => {
"use strict";

const STAGE_CAPTURE_ADAPTERS = globalThis.MSDELTA_STAGE_CAPTURE_ADAPTERS || Object.create(null);
globalThis.MSDELTA_STAGE_CAPTURE_ADAPTERS = STAGE_CAPTURE_ADAPTERS;

function registerStageCaptureAdapter(name, adapter) {
  if (STAGE_CAPTURE_ADAPTERS[name]) {
    throw new Error(`duplicate stage capture adapter: ${name}`);
  }
  STAGE_CAPTURE_ADAPTERS[name] = adapter;
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

function readS64Value(address) {
  const text = address.readS64().toString(10);
  const value = Number.parseInt(text, 10);
  if (Number.isSafeInteger(value)) {
    return value;
  }
  return text;
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

function captureReaderInputs(_fn, args) {
  return {
    this_ptr: args[0].toString(),
    reader_ptr: args[1].toString(),
  };
}

function captureCliCodedTokenInputs(_fn, args) {
  return {
    this_ptr: args[0].toString(),
    kind: nativePointerU32(args[1], "coded-token kind"),
    raw: nativePointerU32(args[2], "coded-token raw value"),
  };
}

registerStageCaptureAdapter("cli_metadata_internal_from_bitreader", {
  captureInputs: captureReaderInputs,
  readObject: (fn, callContext) => readCliMetadataRecord(callContext.this_ptr, fn.object_layout),
  readPlan: (_fn, objectValue) => cliMetadataReadPlan(objectValue),
});

registerStageCaptureAdapter("cli_map_from_bitreader", {
  captureInputs: captureReaderInputs,
  readObject: (fn, callContext) => readCliMapRecord(callContext.this_ptr, fn.object_layout),
  readPlan: () => null,
});

registerStageCaptureAdapter("cli_map_coded_token_call", {
  captureInputs: captureCliCodedTokenInputs,
  readObject: readCliCodedTokenMapCallRecord,
  readPlan: () => null,
});

registerStageCaptureAdapter("reader_bitstream_only", {
  captureInputs: captureReaderInputs,
  readObject: () => null,
  readPlan: () => null,
});
})();
