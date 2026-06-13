#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const EXPORTS = ["ApplyDeltaB", "ApplyDeltaGetReverseB", "CreateDeltaB"];
const ANSI_ESCAPE = /\x1b\[[0-9;]*m/g;

function usage() {
  return `usage:
  node import-inject-capture.mjs --stdout <frida-out.txt> --blob-dir <dir> --out <dir> --case-id <id>

The input stdout file should be the line-oriented JSON output from
frida-inject.exe. The blob directory should contain files written by
MSDELTA_EXPORT_ORACLE_BLOB_DIR.`;
}

function parseArgs(argv) {
  const options = {
    stdoutPath: null,
    blobDir: null,
    outDir: null,
    caseId: "export-capture",
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "--") {
      i += 1;
      continue;
    }
    if (arg === "--stdout") {
      options.stdoutPath = argv[++i];
    } else if (arg === "--blob-dir") {
      options.blobDir = argv[++i];
    } else if (arg === "--out") {
      options.outDir = argv[++i];
    } else if (arg === "--case-id") {
      options.caseId = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}\n${usage()}`);
    }
    i += 1;
  }

  for (const [name, value] of Object.entries(options)) {
    if (!value) {
      throw new Error(`--${name.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)} is required\n${usage()}`);
    }
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(options.caseId)) {
    throw new Error("--case-id must be a non-empty file-safe identifier");
  }

  return options;
}

function sanitizePart(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]/g, "_");
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
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

function nowIsoCompact() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseMessageLine(line) {
  const clean = line.replace(ANSI_ESCAPE, "");
  const jsonStart = clean.indexOf("{");
  if (jsonStart === -1) {
    return null;
  }

  try {
    return JSON.parse(clean.slice(jsonStart));
  } catch {
    return null;
  }
}

function fileSinkBasename(fileSinkPath) {
  return path.win32.basename(String(fileSinkPath));
}

function eventTimeBounds(events) {
  const timestamps = events
    .map(event => event.timestamp_ms)
    .filter(value => Number.isInteger(value));
  if (timestamps.length === 0) {
    const now = new Date().toISOString();
    return { startedAt: now, endedAt: now };
  }

  return {
    startedAt: new Date(Math.min(...timestamps)).toISOString(),
    endedAt: new Date(Math.max(...timestamps)).toISOString(),
  };
}

function inferPid(events) {
  for (const event of events) {
    const parts = String(event.call_id || "").split("-");
    if (parts.length >= 2) {
      const pid = Number(parts[1]);
      if (Number.isInteger(pid)) {
        return pid;
      }
    }
  }
  return null;
}

async function readSinkBlob(options, payload) {
  if (payload.file_sink_path) {
    const sourceName = fileSinkBasename(payload.file_sink_path);
    const sourcePath = path.join(options.resolvedBlobDir, sourceName);
    return fs.readFile(sourcePath);
  }

  if (payload.size === 0) {
    return Buffer.alloc(0);
  }

  throw new Error(
    `blob ${payload.event_id}:${payload.slot} has no file_sink_path and requested ${payload.size} bytes`
  );
}

async function importBlob(options, ctx, payload) {
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
  const bytes = await readSinkBlob(options, payload);
  await fs.writeFile(abs, bytes);

  if (Number.isInteger(payload.size) && payload.size !== bytes.length) {
    ctx.errors.push({
      type: "blob_size_mismatch",
      event_id: payload.event_id,
      slot: payload.slot,
      requested_size: payload.size,
      actual_size: bytes.length,
      file_sink_path: payload.file_sink_path || null,
    });
  }

  event.blobs.push({
    slot: payload.slot,
    path: rel,
    ptr: payload.ptr,
    requested_size: payload.size,
    size: bytes.length,
    sha256: sha256Bytes(bytes),
    file_sink_path: payload.file_sink_path || "",
    note: payload.note || "",
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  options.resolvedStdoutPath = resolveExistingPath(options.stdoutPath);
  options.resolvedBlobDir = resolveExistingPath(options.blobDir);

  const outDir = resolveOutputPath(options.outDir);
  const caseDir = path.join(outDir, "cases", options.caseId);
  const blobDir = path.join(caseDir, "blobs");
  await fs.mkdir(blobDir, { recursive: true });

  const events = [];
  const eventById = new Map();
  const modules = new Map();
  const logs = [];
  const errors = [];
  let ignoredLines = 0;

  const stdout = await fs.readFile(options.resolvedStdoutPath, "utf8");
  const messages = stdout.split(/\r?\n/).map(parseMessageLine);

  for (const message of messages) {
    if (!message) {
      ignoredLines += 1;
      continue;
    }

    if (message.type === "error") {
      errors.push({
        type: "agent_error",
        description: message.description,
        stack: message.stack,
      });
      continue;
    }

    const payload = message.payload;
    if (!payload || typeof payload !== "object") {
      errors.push({ type: "unknown_message", message });
      continue;
    }

    if (payload.type === "event") {
      const event = { ...payload.event, blobs: [] };
      events.push(event);
      eventById.set(event.event_id, event);
    } else if (payload.type === "blob") {
      await importBlob(options, { blobDir, eventById, errors }, payload);
    } else if (payload.type === "module") {
      const key = `${payload.module.name}:${payload.module.path}`;
      modules.set(key, payload.module);
    } else if (payload.type === "log") {
      logs.push({
        level: payload.level,
        message: payload.message,
        detail: payload.detail || null,
      });
      if (payload.level === "error") {
        errors.push({ type: "agent_log", message: payload.message, detail: payload.detail });
      }
    } else {
      errors.push({ type: "unhandled_payload", payload });
    }
  }

  events.sort((a, b) => {
    const seq = (a.seq || 0) - (b.seq || 0);
    if (seq !== 0) {
      return seq;
    }
    return String(a.event_id).localeCompare(String(b.event_id));
  });

  const { startedAt, endedAt } = eventTimeBounds(events);
  const run = {
    schema: 1,
    atom: "FridaExportOracle",
    run_id: `${nowIsoCompact()}-${options.caseId}`,
    started_at: startedAt,
    ended_at: endedAt,
    host: {
      platform: process.platform,
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
    },
    frida: {
      device: "inject",
      remote: null,
    },
    target: {
      pid: inferPid(events),
      spawned: false,
      command: [],
      detach: { reason: "imported-frida-inject-stdout" },
    },
    exports: EXPORTS,
    modules: Array.from(modules.values()).sort((a, b) =>
      `${a.name}:${a.path}`.localeCompare(`${b.name}:${b.path}`)
    ),
    cases: [options.caseId],
    logs,
    errors,
    import: {
      stdout: options.resolvedStdoutPath,
      blob_dir: options.resolvedBlobDir,
      ignored_lines: ignoredLines,
    },
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

main().catch(error => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
