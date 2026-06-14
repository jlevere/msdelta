#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import frida from "frida";

const DEFAULT_AGENT = new URL("./agent/export-oracle.js", import.meta.url);
const EXPORTS = ["ApplyDeltaB", "ApplyDeltaGetReverseB", "CreateDeltaB"];

function usage() {
  return `usage:
  node capture-export-oracle.mjs --out <dir> --case-id <id> [--remote host:port] -- <command> [args...]
  node capture-export-oracle.mjs --out <dir> --case-id <id> [--remote host:port] --attach <pid>

Examples:
  pnpm capture:export -- --out out/raw --case-id raw -- powershell.exe -NoProfile -File harness.ps1
  pnpm capture:export -- --remote 127.0.0.1:27042 --out out/raw --case-id raw -- powershell.exe -NoProfile -File harness.ps1
`;
}

function parseArgs(argv) {
  const options = {
    outDir: null,
    caseId: "export-capture",
    agentPath: path.normalize(fileURLToPath(DEFAULT_AGENT)),
    attachPid: null,
    remote: null,
    command: [],
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "--") {
      options.command = argv.slice(i + 1);
      break;
    }
    if (arg === "--out") {
      options.outDir = argv[++i];
    } else if (arg === "--case-id") {
      options.caseId = argv[++i];
    } else if (arg === "--agent") {
      options.agentPath = argv[++i];
    } else if (arg === "--remote") {
      options.remote = argv[++i];
    } else if (arg === "--attach") {
      options.attachPid = Number(argv[++i]);
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}\n${usage()}`);
    }
    i += 1;
  }

  if (!options.outDir) {
    throw new Error(`--out is required\n${usage()}`);
  }
  if (!options.caseId || !/^[A-Za-z0-9_.-]+$/.test(options.caseId)) {
    throw new Error("--case-id must be a non-empty file-safe identifier");
  }
  if (options.attachPid !== null && options.command.length !== 0) {
    throw new Error("--attach and command spawning are mutually exclusive");
  }
  if (options.attachPid === null && options.command.length === 0) {
    throw new Error(`target command is required after --\n${usage()}`);
  }
  return options;
}

async function openDevice(remote) {
  if (!remote) {
    return {
      device: await frida.getLocalDevice(),
      close: async () => {},
      kind: "local",
      address: null,
    };
  }

  const manager = frida.getDeviceManager();
  const device = await manager.addRemoteDevice(remote);
  return {
    device,
    close: async () => manager.removeRemoteDevice(remote),
    kind: "remote",
    address: remote,
  };
}

function sanitizePart(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]/g, "_");
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

async function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  const stream = fsSync.createReadStream(filePath);
  await new Promise((resolve, reject) => {
    stream.on("data", chunk => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}

function nowIsoCompact() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(options.outDir);
  const caseDir = path.join(outDir, "cases", options.caseId);
  const blobDir = path.join(caseDir, "blobs");
  await fs.mkdir(blobDir, { recursive: true });

  const startedAt = new Date().toISOString();
  const runId = `${nowIsoCompact()}-${options.caseId}`;
  const events = [];
  const eventById = new Map();
  const modules = new Map();
  const errors = [];
  const pendingWrites = [];

  const openedDevice = await openDevice(options.remote);
  const device = openedDevice.device;
  let pid;
  let spawned = false;
  if (options.attachPid !== null) {
    pid = options.attachPid;
  } else {
    pid = await device.spawn(options.command);
    spawned = true;
  }

  const session = await device.attach(pid);
  const agentSource = await fs.readFile(options.agentPath, "utf8");
  const script = await session.createScript(agentSource, {
    name: "msdelta-export-oracle",
  });

  script.message.connect((message, data) => {
    try {
      handleMessage({
        message,
        data,
        events,
        eventById,
        modules,
        errors,
        pendingWrites,
        blobDir,
      });
    } catch (error) {
      errors.push({
        type: "host_message_error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

  const detached = new Promise(resolve => {
    session.detached.connect((reason, crash) => {
      resolve({ reason, crash: crash ? String(crash) : null });
    });
  });

  process.on("SIGINT", async () => {
    try {
      await session.detach();
    } finally {
      process.exit(130);
    }
  });

  await script.load();
  if (spawned) {
    await device.resume(pid);
  }

  const detachInfo = await detached;
  await Promise.all(pendingWrites);
  await openedDevice.close();

  const moduleList = [];
  for (const moduleInfo of modules.values()) {
    const entry = { ...moduleInfo };
    if (entry.path) {
      try {
        entry.sha256 = await sha256File(entry.path);
      } catch (error) {
        entry.sha256 = null;
        entry.sha256_error = error instanceof Error ? error.message : String(error);
      }
    }
    moduleList.push(entry);
  }
  moduleList.sort((a, b) => `${a.name}:${a.path}`.localeCompare(`${b.name}:${b.path}`));

  const endedAt = new Date().toISOString();
  const run = {
    schema: 1,
    atom: "FridaExportOracle",
    run_id: runId,
    started_at: startedAt,
    ended_at: endedAt,
    host: {
      platform: process.platform,
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
    },
    frida: {
      device: openedDevice.kind,
      remote: openedDevice.address,
    },
    target: {
      pid,
      spawned,
      command: options.command,
      detach: detachInfo,
    },
    exports: EXPORTS,
    modules: moduleList,
    cases: [options.caseId],
    errors,
  };

  const capture = {
    schema: 1,
    atom: "FridaExportOracle",
    case_id: options.caseId,
    events,
  };

  await fs.writeFile(path.join(outDir, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  await fs.writeFile(path.join(caseDir, "capture.json"), `${JSON.stringify(capture, null, 2)}\n`);
}

function handleMessage(ctx) {
  const { message, data } = ctx;
  if (message.type === "error") {
    ctx.errors.push({
      type: "agent_error",
      description: message.description,
      stack: message.stack,
    });
    return;
  }

  const payload = message.payload;
  if (!payload || typeof payload !== "object") {
    ctx.errors.push({ type: "unknown_message", message });
    return;
  }

  if (payload.type === "event") {
    const event = { ...payload.event, blobs: [] };
    ctx.events.push(event);
    ctx.eventById.set(event.event_id, event);
    return;
  }

  if (payload.type === "blob") {
    const write = writeBlob(ctx, payload, data);
    ctx.pendingWrites.push(write);
    return;
  }

  if (payload.type === "module") {
    const key = `${payload.module.name}:${payload.module.path}`;
    ctx.modules.set(key, payload.module);
    return;
  }

  if (payload.type === "log") {
    if (payload.level === "error") {
      ctx.errors.push({ type: "agent_log", message: payload.message, detail: payload.detail });
    }
    return;
  }

  ctx.errors.push({ type: "unhandled_payload", payload });
}

async function writeBlob(ctx, payload, data) {
  const event = ctx.eventById.get(payload.event_id);
  if (!event) {
    ctx.errors.push({
      type: "orphan_blob",
      event_id: payload.event_id,
      slot: payload.slot,
    });
    return;
  }

  const slot = sanitizePart(payload.slot);
  const eventId = sanitizePart(payload.event_id);
  const rel = path.join("blobs", `${eventId}-${slot}.bin`).replaceAll("\\", "/");
  const abs = path.join(ctx.blobDir, `${eventId}-${slot}.bin`);
  const bytes = data ? Buffer.from(data) : Buffer.alloc(0);
  await fs.writeFile(abs, bytes);

  event.blobs.push({
    slot: payload.slot,
    path: rel,
    ptr: payload.ptr,
    requested_size: payload.size,
    size: bytes.length,
    sha256: sha256Bytes(bytes),
    note: payload.note || "",
  });
}

main().catch(error => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
