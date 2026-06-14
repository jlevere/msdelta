# Frida Lab

This lab captures native MSDelta behavior from live Windows DLLs. The first
implemented atom is `FridaExportOracle`: export-level capture for
`ApplyDeltaB`, `ApplyDeltaGetReverseB`, and `CreateDeltaB`.

The capture wrapper runs any target command under Frida. That command can be
the existing PowerShell oracle harness at
`crates/oracle/lab/oracle_harness.ps1`, a small custom test program, or a
future fixture generator. The Frida layer observes native export calls and
writes stable capture artifacts.

## Setup

Use the repo's Nix shell for local controller tooling. Do not install Node or
pnpm globally for this lab:

```sh
nix develop
pnpm --dir lab/frida run check
```

Run live captures against the Windows lab host or another Windows machine that
can load the target DLLs. The usual lab entry point is:

```sh
ssh jackson-dev
```

The stable setup on `jackson-dev` keeps Node and pnpm local in the Nix shell,
but runs `frida-inject.exe` on the Windows VM and imports its stdout plus
file-sink blobs afterward. This path avoids the current remote
`frida-server.exe` attach/spawn crash on that VM.

Remote `frida-server.exe` support remains scaffolded for Windows hosts where it
is stable:

```sh
ssh jackson-dev 'C:\Users\localuser\tools\frida-server.exe --version'
ssh jackson-dev 'powershell -NoProfile -Command "Start-Process C:\Users\localuser\tools\frida-server.exe -ArgumentList ''-l'', ''127.0.0.1:27042'' -WindowStyle Hidden"'
ssh -N -L 127.0.0.1:27042:127.0.0.1:27042 jackson-dev
```

`pnpm run check` only verifies JavaScript syntax. Live capture requires the Frida
runtime to support the target process architecture. The Node package is pinned
to the Frida runtime used by the lab tools.

## Export Capture

The wrapper launches a command, injects `agent/export-oracle.js`, and writes a
run directory:

```powershell
pnpm capture:export -- `
  --remote 127.0.0.1:27042 `
  --out out\raw-smoke `
  --case-id raw-smoke `
  -- powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File ..\..\crates\oracle\lab\oracle_harness.ps1 `
    -Dir C:\oracle-run `
    -Dll msdelta.dll `
    -Out C:\oracle-run\result.msdelta.json
```

Any process that calls the exported native APIs works. The output layout is:

```text
out/raw-smoke/
  run.json
  cases/
    raw-smoke/
      capture.json
      blobs/
        <call-id>-source.bin
        <call-id>-delta.bin
        <call-id>-target.bin
```

`run.json` records the target command, host OS, Frida target PID, and loaded
DLL modules with SHA-256 hashes where the host can read the module files.
`capture.json` records call events and points to binary blobs.

## Inject Capture

On `jackson-dev`, local `frida-inject.exe` works even when remote
`frida-server` attach/spawn is unstable. The agent supports an optional file
sink for that path: prepend a small definition before `agent/export-oracle.js`
and inject the combined script.

```javascript
globalThis.MSDELTA_EXPORT_ORACLE_BLOB_DIR = "C:\\\\oracle-run\\\\blobs";
```

With the file sink set, event messages still print to `frida-inject` stdout and
blob messages include `file_sink_path`; the binary bytes are written by the
agent inside the target process.

After copying `frida-out.txt` and the blob directory back to the repo-local
machine, normalize them into the same output layout as the Node Frida wrapper:

```sh
pnpm --dir lab/frida import:inject -- \
  --stdout out/raw-smoke/inject/frida-out.txt \
  --blob-dir out/raw-smoke/inject/blobs \
  --out out/raw-smoke/normalized \
  --case-id raw-smoke
```

The importer also accepts repo-root-relative paths when invoked through pnpm;
it resolves existing input files against the original shell directory when
`INIT_CWD` is present.

## Managed Corpus

`managed-corpus.ps1` is the repeatable entry point for creating real managed
PE source/target pairs on a Windows lab host. It uses the .NET Framework
compiler already present on Windows and writes a normal oracle `job.json`.
For normal lab use, run the host-side wrapper from the repo's Nix shell:

```sh
nix develop -c lab/frida/capture-managed-corpus.sh
```

The wrapper stages the generator, oracle harness, export agent, stage agent, and
symbol maps on `jackson-dev`; selects the `msdelta.dll` stage map with
`Get-FileHash`; runs native `CreateDeltaB`/`ApplyDeltaB` controls; pulls the
corpus back under `lab/frida/out/managed-corpus`; and normalizes the Frida
file-sink capture. Override `SSH_HOST`, `REMOTE_ROOT`, `OUT_DIR`, or `CASE_ID`
when using another lab host or output directory.

The underlying Windows-side commands are:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\managed-corpus.ps1 `
  -OutDir C:\msdelta-managed-corpus

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\oracle_harness.ps1 `
  -Dir C:\msdelta-managed-corpus `
  -Dll msdelta.dll `
  -Out C:\msdelta-managed-corpus\result.msdelta.json
```

The initial corpus is deliberately small but diverse: string/user-string
changes, metadata row growth, generic signature blobs, custom attributes,
manifest resources, and one x64 managed PE. Each case requests
`native_to_ours` and `native_to_native`, so the lab emits native `.gold` deltas
and proves those deltas apply back to the expected target before we use them as
fixtures.

The .NET Framework compiler on the current lab host does not support Roslyn's
deterministic-output flag, so rerunning the generator can produce different PE
bytes and different native deltas. Treat `tests/fixtures/atoms/ManagedNativeCorpus`
as a curated snapshot and treat fresh `lab/frida/out/managed-corpus` output as a
new validated sample set.

## Current Scope

Supported now:

- Windows x64 only.
- `msdelta.dll`, `UpdateCompression.dll`, and `mspatcha.dll` export hooks.
- `ApplyDeltaB` source/delta input and target output capture.
- `ApplyDeltaGetReverseB` source/delta input, target output, and reverse-delta
  output capture.
- `CreateDeltaB` source/target input and delta output capture.
- Module provenance: path, base, size, and SHA-256 when readable.
- Local `frida-inject.exe` file-sink mode for Windows hosts where remote
  `frida-server` transport is unstable.
- Local import of `frida-inject.exe` stdout plus file-sink blobs into
  `run.json`, `capture.json`, and `blobs/*.bin`.
- Repeatable Windows-side managed corpus generation for native executable
  delta controls.
- Internal stage hooks: hash-selected, module-specific Frida hooks from
  `lab/frida/symbol-maps`.
- Logical object normalization for managed metadata and CLI map bitstream records.
- Replay-checked native reader-window blob capture for stage parser atoms.
- Pure method call records for stage algebra atoms: stable call inputs, native
  return values, and normalized object snapshots.
- `CliMetadataBitstream` object and reader-bitstream capture for Win26100 `msdelta.dll`
  (`compo::CliMetadata::InternalFromBitReader`, RVA `0x1cba0` for
  `ac96e0c3...f4358eb`).
- `CliMapBitstream` object and reader-bitstream capture for Win26100 `msdelta.dll`
  (`compo::CliMap::FromBitReader`, RVA `0x1a160` for
  `ac96e0c3...f4358eb`).
- `CliCodedTokenMap` call-record capture for Win26100 `msdelta.dll`
  (`compo::CliMap::MapCoded`, RVA `0x22578`, and
  `compo::CliMap::MapCodedExact`, RVA `0x499c0`, for
  `ac96e0c3...f4358eb`).
- Local import of stage object JSON into `objects/*.json` and standalone reader
  inputs into `blobs/*.bin`.

Not supported yet:

- x86 process ABI.
- Automatic fixture promotion.
- CLI compression-rift object normalization.

## Contract Notes

On Windows x64, `DELTA_INPUT` is larger than eight bytes, so the native ABI
passes it by pointer to a caller-provided temporary. The export oracle reads
those temporary structures on function entry, copies the input buffers
immediately, and reads `DELTA_OUTPUT` buffers on function return before the
caller can release them with `DeltaFree`.

Do not treat export captures as atom-complete fixtures. They prove API-level
behavior and provide raw material for fixture promotion, but internal atoms
still need stage oracles once their hooks exist.
