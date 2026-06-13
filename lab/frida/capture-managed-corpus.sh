#!/usr/bin/env bash
# Capture a repeatable managed/.NET corpus from a Windows lab host.
#
# Produces:
#   lab/frida/out/managed-corpus/remote/corpus/{job.json,result.msdelta.json,*.gold,inputs/...}
#   lab/frida/out/managed-corpus/remote/frida/{frida-out.txt,blobs/...}
#   lab/frida/out/managed-corpus/normalized/{run.json,cases/...}
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SSH_HOST="${SSH_HOST:-jackson-dev}"
REMOTE_ROOT="${REMOTE_ROOT:-C:/msdelta-managed-lab}"
OUT_DIR="${OUT_DIR:-$ROOT/lab/frida/out/managed-corpus}"
CASE_ID="${CASE_ID:-managed-corpus-msdelta}"

log() {
  printf '[managed-corpus] %s\n' "$*" >&2
}

ps_encoded() {
  iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'
}

run_ps() {
  local script encoded
  script="$(cat)"
  script="${script//__REMOTE_ROOT__/$REMOTE_ROOT}"
  encoded="$(printf '%s' "$script" | ps_encoded)"
  ssh -o BatchMode=yes "$SSH_HOST" "powershell -NoProfile -EncodedCommand $encoded"
}

log "preparing $REMOTE_ROOT on $SSH_HOST"
run_ps <<'PS'
$ErrorActionPreference = "Stop"
$root = "__REMOTE_ROOT__"
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root | Out-Null
PS

log "staging generator, oracle harness, and Frida agent"
scp -q \
  "$ROOT/lab/frida/managed-corpus.ps1" \
  "$ROOT/crates/oracle/lab/oracle_harness.ps1" \
  "$ROOT/lab/frida/agent/export-oracle.js" \
  "$ROOT/lab/frida/agent/stage-oracle.js" \
  "$SSH_HOST:$REMOTE_ROOT/"
scp -q -r "$ROOT/lab/frida/symbol-maps" "$SSH_HOST:$REMOTE_ROOT/"

log "building managed source/target pairs and native gold deltas"
run_ps <<'PS'
$ErrorActionPreference = "Stop"
$root = "__REMOTE_ROOT__"
$corpus = Join-Path $root "corpus"
& (Join-Path $root "managed-corpus.ps1") -OutDir $corpus
& (Join-Path $root "oracle_harness.ps1") -Dir $corpus -Dll msdelta.dll -Out (Join-Path $corpus "result.msdelta.json")
PS

log "capturing export-level CreateDeltaB/ApplyDeltaB traffic with frida-inject"
run_ps <<'PS'
$ErrorActionPreference = "Continue"
$root = "__REMOTE_ROOT__"
$runRoot = Join-Path $root "frida"
$blobDir = Join-Path $runRoot "blobs"
$objectDir = Join-Path $runRoot "objects"
$readyPath = Join-Path $runRoot "agent-ready.txt"
$stageReadyPath = Join-Path $runRoot "stage-agent-ready.txt"
Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $blobDir | Out-Null
New-Item -ItemType Directory -Force $objectDir | Out-Null

$modulePath = Join-Path $env:WINDIR "System32\msdelta.dll"
$moduleHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $modulePath).Hash.ToLowerInvariant()
$symbolMapPath = Join-Path $root "symbol-maps\msdelta\$moduleHash.json"
if (-not (Test-Path -LiteralPath $symbolMapPath)) {
    throw "missing Frida stage symbol map for $modulePath hash $moduleHash at $symbolMapPath"
}
$symbolMapJson = Get-Content -LiteralPath $symbolMapPath -Raw

$agentPath = Join-Path $root "agent-combined.js"
$blobLiteral = $blobDir.Replace('\', '\\')
$objectLiteral = $objectDir.Replace('\', '\\')
$readyLiteral = $readyPath.Replace('\', '\\')
$stageReadyLiteral = $stageReadyPath.Replace('\', '\\')
$prelude = @"
globalThis.MSDELTA_EXPORT_ORACLE_BLOB_DIR = "$blobLiteral";
globalThis.MSDELTA_EXPORT_ORACLE_READY_FILE = "$readyLiteral";
globalThis.MSDELTA_STAGE_ORACLE_OBJECT_DIR = "$objectLiteral";
globalThis.MSDELTA_STAGE_ORACLE_BLOB_DIR = "$blobLiteral";
globalThis.MSDELTA_STAGE_ORACLE_READY_FILE = "$stageReadyLiteral";
globalThis.MSDELTA_STAGE_ORACLE_SELECTED_SHA256 = "$moduleHash";
globalThis.MSDELTA_STAGE_ORACLE_SYMBOL_MAP = $symbolMapJson;
"@
$agent = @(
    Get-Content -LiteralPath (Join-Path $root "export-oracle.js") -Raw
    Get-Content -LiteralPath (Join-Path $root "stage-oracle.js") -Raw
) -join ([Environment]::NewLine)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($agentPath, $prelude + [Environment]::NewLine + $agent, $utf8NoBom)

$corpus = Join-Path $root "corpus"
$harness = Join-Path $root "oracle_harness.ps1"
$fridaResult = Join-Path $corpus "frida-result.msdelta.json"
$targetOut = Join-Path $runRoot "target-process-out.txt"
$targetErr = Join-Path $runRoot "target-process-err.txt"
$fridaOut = Join-Path $runRoot "frida-out.txt"
$child = @"
`$ErrorActionPreference = "Stop"
`$loadLibrarySrc = @'
using System;
using System.Runtime.InteropServices;

public static class NativeLoader {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
}
'@
Add-Type -TypeDefinition `$loadLibrarySrc
if ([NativeLoader]::LoadLibrary("msdelta.dll") -eq [IntPtr]::Zero) {
    throw "LoadLibrary(msdelta.dll) failed"
}
`$readyPath = "$readyPath"
`$stageReadyPath = "$stageReadyPath"
`$deadline = (Get-Date).AddSeconds(60)
foreach (`$path in @(`$readyPath, `$stageReadyPath)) {
    while (-not (Test-Path -LiteralPath `$path)) {
        if ((Get-Date) -gt `$deadline) { throw "timed out waiting for Frida agent readiness marker: `$path" }
        Start-Sleep -Milliseconds 100
    }
}
Start-Sleep -Milliseconds 500
& "$harness" -Dir "$corpus" -Dll msdelta.dll -Out "$fridaResult"
Start-Sleep -Seconds 2
"@
$childEnc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
$powershell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$proc = Start-Process -FilePath $powershell -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $childEnc) -RedirectStandardOutput $targetOut -RedirectStandardError $targetErr -PassThru
Start-Sleep -Milliseconds 500
$fridaInject = $env:MSDELTA_FRIDA_INJECT
if (-not $fridaInject) { $fridaInject = "C:\Users\localuser\tools\frida-inject.exe" }
& $fridaInject -p $proc.Id -s $agentPath *> $fridaOut
$fridaExit = $LASTEXITCODE
$proc.WaitForExit()
if ($fridaExit -ne 0) { exit $fridaExit }
if ($proc.ExitCode -ne 0) { exit $proc.ExitCode }
PS

log "pulling artifacts to $OUT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/remote"
scp -q -r "$SSH_HOST:$REMOTE_ROOT/corpus" "$OUT_DIR/remote/"
scp -q -r "$SSH_HOST:$REMOTE_ROOT/frida" "$OUT_DIR/remote/"

log "normalizing frida-inject stdout and file-sink blobs"
pnpm --dir "$ROOT/lab/frida" import:inject -- \
  --stdout "$OUT_DIR/remote/frida/frida-out.txt" \
  --blob-dir "$OUT_DIR/remote/frida/blobs" \
  --object-dir "$OUT_DIR/remote/frida/objects" \
  --out "$OUT_DIR/normalized" \
  --case-id "$CASE_ID"

log "done"
printf '%s\n' "$OUT_DIR"
