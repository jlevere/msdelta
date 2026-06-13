"use strict";

const POINTER_SIZE = Process.pointerSize;
const SUPPORTED_ARCH = Process.arch === "x64" && POINTER_SIZE === 8;
const MAX_BLOB_SIZE = 256 * 1024 * 1024;

const MODULES = ["msdelta.dll", "UpdateCompression.dll", "mspatcha.dll"];
const EXPORTS = ["ApplyDeltaB", "ApplyDeltaGetReverseB", "CreateDeltaB"];
const FILE_SINK_DIR =
  typeof globalThis.MSDELTA_EXPORT_ORACLE_BLOB_DIR === "string"
    ? globalThis.MSDELTA_EXPORT_ORACLE_BLOB_DIR
    : null;

const hooked = new Set();
const reportedModules = new Set();
let sequence = 0;

function log(level, message, detail) {
  send({ type: "log", level, message, detail: detail || null });
}

function nextEventId(symbol) {
  sequence += 1;
  return `${Date.now()}-${Process.id}-${sequence}-${symbol}`;
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

function readSizeT(address) {
  return Number(address.readU64());
}

function readDeltaInput(inputPtr) {
  if (inputPtr.isNull()) {
    return { ptr: "0x0", size: 0, editable: 0, valid: false };
  }
  const dataPtr = inputPtr.readPointer();
  const size = readSizeT(inputPtr.add(POINTER_SIZE));
  const editable = inputPtr.add(POINTER_SIZE * 2).readS32();
  return {
    ptr: dataPtr.toString(),
    size,
    editable,
    valid: true,
  };
}

function readDeltaOutput(outputPtr) {
  if (outputPtr.isNull()) {
    return { ptr: "0x0", size: 0, valid: false };
  }
  const dataPtr = outputPtr.readPointer();
  const size = readSizeT(outputPtr.add(POINTER_SIZE));
  return {
    ptr: dataPtr.toString(),
    size,
    valid: true,
  };
}

function stackArg(context, argIndex) {
  return context.rsp.add(0x28 + (argIndex - 4) * POINTER_SIZE).readPointer();
}

function stackU32(context, argIndex) {
  return context.rsp.add(0x28 + (argIndex - 4) * POINTER_SIZE).readU32();
}

function sanitizePart(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]/g, "_");
}

function joinPath(dir, fileName) {
  const sep = dir.indexOf("\\") !== -1 ? "\\" : "/";
  return dir.replace(/[\\/]+$/, "") + sep + fileName;
}

function writeBlobFile(eventId, slot, bytes) {
  const fileName = `${sanitizePart(eventId)}-${sanitizePart(slot)}.bin`;
  const filePath = joinPath(FILE_SINK_DIR, fileName);
  const file = new File(filePath, "wb");
  try {
    file.write(bytes);
  } finally {
    file.close();
  }
  return filePath;
}

function sendEvent(event) {
  send({ type: "event", event });
}

function sendBlob(eventId, slot, pointerText, size, note) {
  if (size === 0 || pointerText === "0x0") {
    send({
      type: "blob",
      event_id: eventId,
      slot,
      ptr: pointerText,
      size,
      note: note || "empty",
    });
    return;
  }
  if (size < 0 || size > MAX_BLOB_SIZE) {
    send({
      type: "blob",
      event_id: eventId,
      slot,
      ptr: pointerText,
      size,
      note: `not captured: size outside 0..${MAX_BLOB_SIZE}`,
    });
    return;
  }
  const bytes = ptr(pointerText).readByteArray(size);
  const payload = {
    type: "blob",
    event_id: eventId,
    slot,
    ptr: pointerText,
    size,
    note: note || "",
  };
  if (FILE_SINK_DIR) {
    payload.file_sink_path = writeBlobFile(eventId, slot, bytes);
    send(payload);
  } else {
    send(payload, bytes);
  }
}

function beginEvent(symbol, moduleInfo, phase, callId, fields) {
  return {
    event_id: `${callId}-${phase}`,
    call_id: callId,
    seq: sequence,
    atom: "FridaExportOracle",
    symbol,
    phase,
    module: {
      name: moduleInfo.name,
      path: moduleInfo.path,
      base: moduleInfo.base.toString(),
    },
    thread_id: Process.getCurrentThreadId(),
    timestamp_ms: Date.now(),
    ...fields,
  };
}

function hookApplyDeltaB(moduleInfo, address) {
  Interceptor.attach(address, {
    onEnter(args) {
      this.callId = nextEventId("ApplyDeltaB");
      this.outputPtr = args[3];
      const source = readDeltaInput(args[1]);
      const delta = readDeltaInput(args[2]);
      sendEvent(
        beginEvent("ApplyDeltaB", moduleInfo, "enter", this.callId, {
          apply_flags: args[0].toString(),
          inputs: { source, delta },
          outputs: { target: this.outputPtr.toString() },
        })
      );
      sendBlob(`${this.callId}-enter`, "source", source.ptr, source.size);
      sendBlob(`${this.callId}-enter`, "delta", delta.ptr, delta.size);
    },
    onLeave(retval) {
      const success = retval.toInt32() !== 0;
      const target = success ? readDeltaOutput(this.outputPtr) : null;
      sendEvent(
        beginEvent("ApplyDeltaB", moduleInfo, "leave", this.callId, {
          success,
          retval: retval.toString(),
          outputs: { target },
        })
      );
      if (target) {
        sendBlob(`${this.callId}-leave`, "target", target.ptr, target.size);
      }
    },
  });
}

function hookApplyDeltaGetReverseB(moduleInfo, address) {
  Interceptor.attach(address, {
    onEnter(args) {
      this.callId = nextEventId("ApplyDeltaGetReverseB");
      this.targetOutputPtr = stackArg(this.context, 4);
      this.reverseOutputPtr = stackArg(this.context, 5);
      const source = readDeltaInput(args[1]);
      const delta = readDeltaInput(args[2]);
      sendEvent(
        beginEvent("ApplyDeltaGetReverseB", moduleInfo, "enter", this.callId, {
          apply_flags: args[0].toString(),
          target_file_time: args[3].toString(),
          inputs: { source, delta },
          outputs: {
            target: this.targetOutputPtr.toString(),
            reverse_delta: this.reverseOutputPtr.toString(),
          },
        })
      );
      sendBlob(`${this.callId}-enter`, "source", source.ptr, source.size);
      sendBlob(`${this.callId}-enter`, "delta", delta.ptr, delta.size);
    },
    onLeave(retval) {
      const success = retval.toInt32() !== 0;
      const target = success ? readDeltaOutput(this.targetOutputPtr) : null;
      const reverseDelta = success ? readDeltaOutput(this.reverseOutputPtr) : null;
      sendEvent(
        beginEvent("ApplyDeltaGetReverseB", moduleInfo, "leave", this.callId, {
          success,
          retval: retval.toString(),
          outputs: { target, reverse_delta: reverseDelta },
        })
      );
      if (target) {
        sendBlob(`${this.callId}-leave`, "target", target.ptr, target.size);
      }
      if (reverseDelta) {
        sendBlob(`${this.callId}-leave`, "reverse-delta", reverseDelta.ptr, reverseDelta.size);
      }
    },
  });
}

function hookCreateDeltaB(moduleInfo, address) {
  Interceptor.attach(address, {
    onEnter(args) {
      this.callId = nextEventId("CreateDeltaB");
      this.deltaOutputPtr = stackArg(this.context, 10);
      const source = readDeltaInput(args[3]);
      const target = readDeltaInput(stackArg(this.context, 4));
      const sourceOptions = readDeltaInput(stackArg(this.context, 5));
      const targetOptions = readDeltaInput(stackArg(this.context, 6));
      const globalOptions = readDeltaInput(stackArg(this.context, 7));
      sendEvent(
        beginEvent("CreateDeltaB", moduleInfo, "enter", this.callId, {
          file_type_set: args[0].toString(),
          set_flags: args[1].toString(),
          reset_flags: args[2].toString(),
          target_file_time: stackArg(this.context, 8).toString(),
          hash_alg_id: stackU32(this.context, 9),
          inputs: {
            source,
            target,
            source_options: sourceOptions,
            target_options: targetOptions,
            global_options: globalOptions,
          },
          outputs: { delta: this.deltaOutputPtr.toString() },
        })
      );
      sendBlob(`${this.callId}-enter`, "source", source.ptr, source.size);
      sendBlob(`${this.callId}-enter`, "target", target.ptr, target.size);
      sendBlob(`${this.callId}-enter`, "source-options", sourceOptions.ptr, sourceOptions.size);
      sendBlob(`${this.callId}-enter`, "target-options", targetOptions.ptr, targetOptions.size);
      sendBlob(`${this.callId}-enter`, "global-options", globalOptions.ptr, globalOptions.size);
    },
    onLeave(retval) {
      const success = retval.toInt32() !== 0;
      const delta = success ? readDeltaOutput(this.deltaOutputPtr) : null;
      sendEvent(
        beginEvent("CreateDeltaB", moduleInfo, "leave", this.callId, {
          success,
          retval: retval.toString(),
          outputs: { delta },
        })
      );
      if (delta) {
        sendBlob(`${this.callId}-leave`, "delta", delta.ptr, delta.size);
      }
    },
  });
}

function installHook(moduleInfo, exportName) {
  const key = `${moduleInfo.path}:${exportName}`;
  if (hooked.has(key)) {
    return;
  }
  const address = moduleInfo.findExportByName(exportName);
  if (address === null) {
    return;
  }
  hooked.add(key);
  reportModule(moduleInfo);

  if (!SUPPORTED_ARCH) {
    log("error", "unsupported process architecture for export oracle", {
      arch: Process.arch,
      pointer_size: POINTER_SIZE,
      export: exportName,
    });
    return;
  }

  if (exportName === "ApplyDeltaB") {
    hookApplyDeltaB(moduleInfo, address);
  } else if (exportName === "ApplyDeltaGetReverseB") {
    hookApplyDeltaGetReverseB(moduleInfo, address);
  } else if (exportName === "CreateDeltaB") {
    hookCreateDeltaB(moduleInfo, address);
  }
  log("info", "hooked export", { module: moduleInfo.name, export: exportName, address: address.toString() });
}

function installAvailableHooks() {
  for (const moduleName of MODULES) {
    const moduleInfo = moduleByName(moduleName);
    if (!moduleInfo) {
      continue;
    }
    for (const exportName of EXPORTS) {
      installHook(moduleInfo, exportName);
    }
  }
}

installAvailableHooks();
const hookTimer = setInterval(installAvailableHooks, 250);
setTimeout(() => {
  clearInterval(hookTimer);
  log("info", "stopped export hook polling", { hooked: Array.from(hooked).length });
}, 30000);
