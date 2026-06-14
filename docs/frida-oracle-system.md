# Frida Oracle System

Frida should be the repeatable lab path for collecting native behavior from
`msdelta.dll`, `mspatcha.dll`, and `UpdateCompression.dll`. Final output bytes
are useful, but they are not enough for this project. The hard bugs are usually
inside a specific atom: preprocess parsing, rift algebra, transform source
rewrites, CLI metadata maps, or create-side map generation.

The Frida system should therefore capture stage-level oracles and promote the
smallest useful cases into fixture packets.

## Goals

1. Run the real Windows implementation against controlled inputs.
2. Capture inputs and outputs at atom boundaries.
3. Normalize native objects into stable data formats.
4. Promote captures into `tests/fixtures/atoms/...`.
5. Re-run the same capture set across Windows builds and DLL versions.
6. Report compatibility drift by atom, not just as a final hash mismatch.

This is both an implementation accelerator and a regression system. If a future
Windows update changes behavior, the report should say which atom changed:
`CliMapBitstream`, `RiftTableReverse`, `TransformCliMetadata`,
`PdataARM64`, and so on.

## Capture Tiers

Use tiers so the lab can start useful and become more precise over time.

| Tier | What it captures | Use |
|---|---|---|
| 1. Export | `ApplyDeltaB`, `ApplyDeltaGetReverseB`, `CreateDeltaB` inputs and outputs | End-to-end oracle and smoke validation |
| 2. Stage | Known internal function entry/exit buffers and return objects | Atom fixture generation |
| 3. Object | Logical object state such as `RiftTable`, `CliMetadata`, `CliMap`, PE info | Stable comparison against Rust models |
| 4. Trace | Ordered transform execution and selected branch decisions | Dispatch and feature-gate validation |

Tier 1 is enough to prove final compatibility. Tier 2 and 3 are what make the
system useful for implementation work.

## Current First Atom

`FridaExportOracle` is the first implemented lab atom. It wraps an arbitrary
target process, hooks the public MSDelta-compatible exports, and writes a run
manifest plus captured binary buffers. The intended first target is the existing
PowerShell harness in `crates/oracle/lab/oracle_harness.ps1`; that keeps the
Frida layer focused on observation instead of also becoming a native API driver.

This atom answers a narrow question:

> For this Windows build and DLL hash, what exact buffers crossed
> `ApplyDeltaB`, `ApplyDeltaGetReverseB`, or `CreateDeltaB`, and what did the
> export return?

It does not answer which preprocess, rift, metadata, or transform atom produced
the result. Those require stage hooks and object normalizers.

Current implementation:

| Area | Status |
|---|---|
| Target shape | Spawn a command or attach to an existing PID |
| DLLs | `msdelta.dll`, `UpdateCompression.dll`, `mspatcha.dll` |
| Exports | `ApplyDeltaB`, `ApplyDeltaGetReverseB`, `CreateDeltaB` |
| ABI | Windows x64 only |
| Output | `run.json`, `capture.json`, and `blobs/*.bin` |
| Provenance | Module name, path, base, size, and SHA-256 when readable |
| Inject import | Normalize `frida-inject.exe` stdout plus file-sink blobs |
| Not included | x86 ABI, internal RVAs, object normalization, fixture promotion |

Transport status from the first lab attempt:

- Local Nix-controlled Node/pnpm works for syntax checks and host-side tooling.
- `ssh jackson-dev` reaches the Windows lab VM through the configured jump host.
- `frida-inject.exe` works locally on the Windows VM and can run agent scripts.
- `frida-inject.exe` plus the agent file-sink mode is the stable live-capture
  path on the current Windows Server 2025 lab VM.
- Remote `frida-server` transport is scaffolded in `capture-export-oracle.mjs`
  with `--remote`, but `frida-server` currently exits on attach/spawn on this
  VM. Keep it as an alternate transport for hosts where it is stable.

The important ABI lesson from this first atom is that export-level capture is
not the same as reading the C declarations. On Windows x64, `DELTA_INPUT` is
larger than eight bytes, so the ABI passes it by pointer to a caller-provided
temporary. The hook must read that temporary on entry and copy the source/delta
or source/target bytes immediately. `DELTA_OUTPUT` is read on return before the
caller frees the returned native buffer with `DeltaFree`.

The first live lab run captured `ApplyDeltaB` for the tiny RAW
`cmd.exe` to `where.exe` fixture. The source and delta blobs matched the input
fixtures, and the target blob matched the known `where.exe` hash. Promote that
case only as an export oracle fixture. It should not be treated as proof for any
internal feature atom.

The first promoted packet is:

```text
tests/fixtures/atoms/FridaExportOracle/raw-apply-delta-b/
```

It proves only the export-level ABI and file-sink capture path for a RAW
`ApplyDeltaB` call. Its `case.toml` explicitly lists what it does not prove so
future work does not accidentally treat it as evidence for preprocess, rift, PE,
or managed CLI atoms.

Lessons from that run:

1. Treat transport as part of the oracle contract. The remote Frida server path
   was useful to scaffold but unstable on this VM; local inject plus a file sink
   is the current repeatable path.
2. Separate hook setup from behavior. The harness should load the DLL first,
   wait while hooks are installed, and only then call the export.
3. Never depend on `frida-inject.exe` stdout for binary payloads. Use stdout for
   event metadata and write bytes through the agent file sink.
4. Normalize immediately. The checked-in importer converts inject output into
   the same shape as the Node Frida wrapper, so downstream fixture promotion does
   not care which transport produced the capture.

## Lab Shape

```text
lab/frida/
  README.md
  package.json
  capture-export-oracle.mjs
  import-inject-capture.mjs
  agent/
    export-oracle.js
  schemas/
    export-capture.schema.json
    run.schema.json
    capture.schema.json
    symbol-map.schema.json
  symbols/
    windows-<build>/
      msdelta.<sha256>.json
      mspatcha.<sha256>.json
      updateCompression.<sha256>.json
  cases/
    <case>.toml
  out/
    <run-id>/
      run.json
      cases/
        <case-id>/
          capture.json
          blobs/
```

The checked-in scaffold currently contains the export oracle files. The generic
`capture.ts`, hook modules, symbol maps, cases, and internal capture schemas are
future structure for the stage/object tiers.

The repo does not need to commit every lab output. Curated captures should be
promoted into `tests/fixtures/atoms/...`; bulk lab output can stay local or in a
separate artifact store.

## Run Manifest

Every run needs provenance precise enough to reproduce or explain differences.

```json
{
  "schema": 1,
  "run_id": "2026-06-13T18-42-10Z-win26100-msdelta",
  "host": {
    "os_build": "10.0.26100.7309",
    "arch": "amd64"
  },
  "modules": [
    {
      "name": "msdelta.dll",
      "path": "C:\\Windows\\System32\\msdelta.dll",
      "file_version": "10.0.26100.7309",
      "sha256": "<hex>",
      "image_base": "0x180000000"
    }
  ],
  "symbol_map": "symbols/windows-26100/msdelta.<sha256>.json",
  "cases": ["case-id"]
}
```

The `sha256` is mandatory. Function RVAs are only meaningful relative to the
exact module image.

## Symbol Map

Internal hooks should be declared data, not hard-coded in a script. The same
script can then run against multiple Windows builds by selecting the symbol map
for the loaded module hash.

```json
{
  "schema": 1,
  "module": "msdelta.dll",
  "sha256": "<hex>",
  "image_size": 585728,
  "functions": [
    {
      "atom": "CliMetadataBitstream",
      "name": "compo::CliMetadata::InternalFromBitReader",
      "legacy_name": "CliMetadata::FromBitReader",
      "rva": "0x1cba0",
      "abi": "ms-x64-thiscall",
      "capture": "cli_metadata_internal_from_bitreader",
      "reader_layout": {
        "name": "msdelta-win26100-bitreader-read-v1"
      },
      "object_layout": {
        "name": "msdelta-win26100-compo-cli-metadata-v1"
      }
    }
  ]
}
```

The `name` is a local label for humans. The hook is keyed by module hash plus
RVA. If a build changes enough that the RVA or object layout no longer matches,
the lab should fail closed and mark the capture as unmapped.

This means the fixture extraction system is reusable across future Windows
builds, but internal stage hooks are not build-agnostic. Public export capture
can continue by export name. Stage capture requires one validated symbol map per
DLL hash because private function addresses and C++ object layouts are not part
of Microsoft's stable API contract.

The repeatable update workflow for a new DLL build is:

1. Run `nix develop -c lab/frida/check-stage-symbol-map.sh` against the lab VM.
2. If the reported hash already has a map, run the normal managed-corpus capture.
3. If the hash is unknown, create a candidate map for that exact SHA-256 only
   after checking private RVAs and native object layouts in the disassembly.
4. Smoke-capture one small case and verify reader replay, normalized objects,
   and native apply controls before promoting any new fixtures.
5. Keep the old map in place so older fixture provenance remains reproducible.

There are two managed metadata implementations in the research corpus. The
older DPX/`UpdateCompression.dll` path exposes labels like
`CliMetadata::FromBitReader`. The Win26100 `msdelta.dll` loaded by the managed
corpus uses the `compo::*` object model; its equivalent first metadata
bitstream boundary is `compo::CliMetadata::InternalFromBitReader` at RVA
`0x1cba0` for SHA-256
`ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb`.

## Capture Format

Each case capture should be stage-oriented:

```json
{
  "schema": 1,
  "case_id": "managed-classic-small-method-token",
  "inputs": {
    "reference": "blobs/reference.bin",
    "delta": "blobs/delta.pa30",
    "target": "blobs/target.bin"
  },
  "header": {
    "file_type_set": "0xf",
    "file_type": "0x2",
    "flags": "0xe63e"
  },
  "events": [
    {
      "seq": 1,
      "atom": "CliMetadataBitstream",
      "symbol": "CliMetadata::FromBitReader",
      "phase": "leave",
      "data": "objects/target-cli-metadata.json"
    },
    {
      "seq": 2,
      "atom": "CliMapBitstream",
      "symbol": "CliMap::FromBitReader",
      "phase": "leave",
      "data": "objects/cli-map.json"
    }
  ]
}
```

Binary buffers go under `blobs/`. Logical objects go under `objects/`.

## Normalized Objects

Do not store raw C++ object memory as the fixture contract. It contains
pointers, allocator state, capacity slack, ref-count artifacts, and build-local
layout noise. Use Frida to read the native object and emit logical data.

### RiftTable

```json
{
  "type": "RiftTable",
  "entries": [
    { "source": 0, "target": 0 },
    { "source": 4096, "target": 8192 }
  ]
}
```

### CliMetadata

```json
{
  "type": "CliMetadata",
  "branch": "classic",
  "metadata_file_offset": 8192,
  "metadata_size": 1234,
  "metadata_rva": 8192,
  "streams": {
    "strings": { "offset": 100, "size": 200 },
    "user_strings": { "offset": 300, "size": 40 },
    "blob": { "offset": 340, "size": 500 },
    "guid": { "offset": 840, "size": 16 },
    "tables": { "offset": 856, "size": 378 }
  },
  "heap_widths": {
    "strings": false,
    "guid": false,
    "blob": true
  },
  "valid_table_mask": "0x0000000900001547",
  "row_counts": [1, 0, 3]
}
```

### CliMap

```json
{
  "type": "CliMap",
  "heaps": {
    "strings": { "entries": [] },
    "user_strings": { "entries": [] },
    "blob": { "entries": [] },
    "guid": { "entries": [] }
  },
  "tables": [
    { "table": 0, "entries": [] },
    { "table": 1, "entries": [{ "source": 1, "target": 1 }] }
  ]
}
```

### CliCodedTokenMap

```json
{
  "type": "CliCodedTokenMapCallRecord",
  "native_layout": "msdelta-win26100-compo-cli-map-coded-token-v1",
  "operation": "MapCodedExact",
  "kind": 2,
  "raw": 46,
  "result": 4294967295,
  "map": {
    "type": "CliMapBitstreamRecord",
    "tables": []
  }
}
```

Keep these schemas aligned with the Rust model types once those exist. The
normalizer should be stricter than the hook: if an object cannot be read
coherently, emit a capture error rather than a partial object.

## Fixture Promotion

Promotion converts a raw lab capture into a small test fixture:

```text
tests/fixtures/atoms/<atom>/<case>/
  source.bin
  target.bin
  delta.pa30
  native/
    run.json
    capture.json
    blobs/
      <event-id>-source.bin
      <event-id>-delta.bin
      <event-id>-target.bin
    objects/
      target-cli-metadata.json
      cli-map.json
      cli-rift.json
  case.toml
```

`case.toml` should name exactly what the fixture proves:

```toml
atom = "CliMapBitstream"
case = "managed-classic-empty-map"
windows_build = "10.0.26100.7309"
module = "msdelta.dll"
module_sha256 = "<hex>"
file_type = "0x2"
flags = "0xe63e"
expected_atoms = ["CliMetadataBitstream", "CliMapBitstream"]
primary_artifacts = ["native/objects/cli-map.json"]
```

Do not promote huge or redundant captures. Promote one fixture per behavior
shape: empty map, non-empty heap map, table row widening, IL token remap,
signature blob remap, and so on.

For `FridaExportOracle`, promotion should start with the smallest API-level
fixture:

1. Run one RAW `native_to_native` case through a harness that loads the DLL,
   waits for hooks, then calls the native export.
2. Verify `capture.json` contains enter/leave pairs for the expected export.
3. Copy only the minimal source, target, delta, `run.json`, and `capture.json`
   into the curated fixture packet.
4. Record the Windows build, module hash, DLL name, file type set, flags, and
   hash algorithm in `case.toml`.

Do not promote large raw `lab/frida/out` runs. Keep those as local lab output or
external artifacts.

## Version Matrix

The lab should run the same cases across a matrix:

```text
Windows build x architecture x DLL hash x case set
```

The report should group results by atom:

```text
CliMetadataBitstream
  win26100 msdelta <sha>: match
  win26200 msdelta <sha>: match

CliTableRift
  win26100 msdelta <sha>: match
  win26200 msdelta <sha>: changed: row-width gap at table 0x06
```

The Rust compatibility claim should be tied to this matrix. A final target hash
mismatch should be the last line of defense, not the first diagnostic.

The matrix is expected to grow by adding symbol maps and fixture provenance for
new DLL hashes, not by weakening the stage hook checks. If a future binary has a
new hash but unchanged private layouts, it still gets a new map file after
validation. If the layouts changed, the corresponding atom should be marked as
unmapped until its normalizer and Rust model are updated.

## Hook Strategy

Start with stable boundaries:

| Atom | Native hook |
|---|---|
| `Pa30HeaderParse` | `ApplyDeltaB` export, before internal dispatch |
| `PePreprocessNative` | `PortableExecutableInfo::FromBitReader` |
| `PePreprocessManagedClassic` | `PortableExecutableInfo::FromBitReader` with managed source |
| `PePreprocessManagedCli4` | `PortableExecutableInfoCli4::FromBitReader` |
| `CliMetadataBitstream` | `CliMetadata::FromBitReader` |
| `CliMapBitstream` | `CliMap::FromBitReader` |
| `CliCodedTokenMap` | `CliMap::MapCoded`, `CliMap::MapCodedExact` |
| `CliCompressionRift` | `CompressionRiftTableCli::FromCliMap` |
| `Cli4CompressionRift` | `CompressionRiftTableCli4::FromCli4Map` |
| `TransformCliDisasm` | `TransformCliDisasm::Run` entry/exit PE bytes |
| `TransformCliMetadata` | `TransformCliMetadata::Run` entry/exit PE bytes |
| `CreateCliMapFromPEs` | `CliMapFromPEs::Run` |
| `CreateCli4MapFromPEs` | `Cli4MapFromPEs::Run` |

For transforms, capture both the input PE buffer and output PE buffer at the
transform boundary. For object-returning functions, capture normalized logical
objects on leave.

## Failure Policy

The lab should fail closed:

- Unknown module hash: no internal hooks.
- Missing symbol map in export-only mode: export capture allowed, stage capture
  disabled.
- Missing symbol map in managed-corpus mode: wrapper failure before the oracle
  run starts.
- Hash changed but no validated replacement map: no stage fixture collection.
- Object layout mismatch: capture error, no fixture promotion.
- Truncated or incoherent object: capture error, no fixture promotion.
- Final native API failure: preserve error code and inputs for triage.

This prevents bad fixtures from encoding wrong assumptions.

## Adapter Modularity

Stage hooks use a capture-adapter registry. A new internal atom should add one
adapter that owns:

- stable call input capture,
- optional normalized object extraction,
- whether the native function consumes a `BitReader`,
- any atom-specific return-value normalization.

The generic hook lifecycle should stay independent of atom details: attach by
symbol map, capture enter/leave events, manage optional reader windows, write
objects/blobs, and fail closed on adapter errors. If a new atom needs custom
transport, custom fixture promotion, or special native state lifetime handling,
record that as a lab atom or split the hook boundary. Do not hide it inside a
large transform-specific adapter.

## Clean-Room Boundary

The capture output should contain behavior, not copied implementation text.
Allowed fixture data:

- Input and output buffers.
- Normalized object fields.
- Integer flags, sizes, offsets, and rift entries.
- Function labels and local atom names.

Do not commit decompiler output, disassembly snippets, or copied proprietary
source text into fixtures, comments, or reports.

## Current Oracle Plan

The first export-capture loop is complete enough to support atom work:
`frida-inject.exe` file-sink transport is repeatable, export captures normalize
into fixture-shaped buffers, and internal hooks are selected by module hash.
The managed corpus wrapper now selects the Win26100 `msdelta.dll` symbol map
with `Get-FileHash`, waits for both export and stage Frida agents, and captures
these internal atoms:

| Atom | Native boundary | Fixture shape |
|---|---|---|
| `CliMetadataBitstream` | `compo::CliMetadata::InternalFromBitReader` | normalized object plus replay-checked reader window |
| `CliMapBitstream` | `compo::CliMap::FromBitReader` | normalized object plus replay-checked reader window |
| `CliCodedTokenMap` | `compo::CliMap::MapCoded` / `MapCodedExact` | call input, return value, and normalized `CliMap` snapshot |

The lab lane should now optimize for repeatability and smaller atom fixtures:

1. Turn the current ad hoc fixture promotion steps into a reusable promotion
   command for stage objects, reader-window blobs, and call records.
2. Add `NativeOracleDiff`, a normalized-object comparator that can replay Rust
   output against promoted native captures without a full apply run.
3. Add targeted call/object harnesses for evidence gaps such as non-identity
   `MapCoded` and compressed-integer edge cases.
4. Add object normalizers for PE info, CLI4 metadata/map, and CLI compression
   rift builders.
5. Run the same capture set on a second Windows/DLL build and record drift by
   atom, not by whole corpus result.

New hooks should be chosen by the managed phase they unblock. For the current
plan, prefer `CliMetadata::Init`, `CliBlobTransformer::GetNumber`, CLI4
metadata/map readers, and `CompressionRiftTableCli[4]::FromCliMap` before IL or
metadata transform entry/exit hooks.

## Managed Corpus

The managed lane needs real .NET PE pairs before internal hooks are useful.
`lab/frida/managed-corpus.ps1` is the Windows-side seed corpus generator. It
compiles a small set of source/target assemblies with the .NET Framework
compiler, writes a normal oracle `job.json`, and requests both
`native_to_ours` and `native_to_native`.

Use `lab/frida/capture-managed-corpus.sh` from the repo's Nix shell to run the
full loop against `jackson-dev`: stage the corpus generator, symbol maps, export
agent, and stage agent; run native `msdelta.dll` controls; attach
`frida-inject.exe`; pull the raw artifacts; and normalize export buffers plus
stage object JSON.

The first corpus intentionally covers different metadata surfaces instead of
many copies of one shape:

- `cli-const-string`: user string and method body changes.
- `cli-add-method`: metadata row growth and method-token pressure.
- `cli-generics-signature`: generic signature blob and member reference changes.
- `cli-custom-attribute`: custom attribute table and blob changes.
- `cli-resource`: manifest resource plus method body changes.
- `cli-platform-x64`: x64 managed PE coverage.

This corpus is not a replacement for internal object fixtures. It gives the
project repeatable native managed deltas and native apply controls, which are
then reused as the input set for `CliMetadataBitstream`, `CliMapBitstream`, and
CLI rift object capture.

The current lab compiler is the .NET Framework `csc.exe`, which does not accept
Roslyn deterministic-output flags. Regenerated managed PE bytes can differ from
the committed fixture snapshot; the native `native_to_native` control is the
validity signal for each fresh run.

For managed work, start the internal-hook lane with the current module's
metadata bitstream boundary. On Win26100 `msdelta.dll` that is
`compo::CliMetadata::InternalFromBitReader`; on older DPX/
`UpdateCompression.dll` research material it is labeled
`CliMetadata::FromBitReader`. It is the earliest missing managed parser after
PE info and the preprocess rift, and its normalized object gives
`CliMapBitstream`, heap/table rifts, IL token remapping, and metadata-table
rewriting a stable source/target metadata contract. The hook should emit a
logical metadata-record object on return; do not promote captures that only dump
raw native object memory.
