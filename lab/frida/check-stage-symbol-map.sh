#!/usr/bin/env bash
# lab/frida/check-stage-symbol-map.sh
# Report whether a Windows lab host has a checked-in stage symbol map for a DLL.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SSH_HOST="${SSH_HOST:-jackson-dev}"
MODULE="${MODULE:-msdelta.dll}"
SYMBOL_MODULE_DIR="${SYMBOL_MODULE_DIR:-msdelta}"
MODULE_PATH="${MODULE_PATH:-}"

ps_encoded() {
  iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'
}

run_ps() {
  local script encoded
  script="$(cat)"
  script="${script//__MODULE__/$MODULE}"
  script="${script//__MODULE_PATH__/$MODULE_PATH}"
  encoded="$(printf '%s' "$script" | ps_encoded)"
  ssh -o BatchMode=yes "$SSH_HOST" "powershell -NoProfile -NonInteractive -EncodedCommand $encoded"
}

module_info="$(
  run_ps <<'PS'
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$moduleName = "__MODULE__"
$explicitPath = "__MODULE_PATH__"
if ($explicitPath.Length -gt 0) {
    $modulePath = $explicitPath
} else {
    $modulePath = Join-Path $env:WINDIR "System32\$moduleName"
}
$item = Get-Item -LiteralPath $modulePath
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
"module=$moduleName"
"path=$($item.FullName)"
"file_version=$($item.VersionInfo.FileVersion)"
"sha256=$hash"
"file_size=$($item.Length)"
PS
)"

module_name=""
module_path=""
file_version=""
module_hash=""
file_size=""
while IFS='=' read -r key value; do
  key="${key//$'\r'/}"
  value="${value//$'\r'/}"
  case "$key" in
    module) module_name="$value" ;;
    path) module_path="$value" ;;
    file_version) file_version="$value" ;;
    sha256) module_hash="$value" ;;
    file_size) file_size="$value" ;;
  esac
done <<<"$module_info"

if [[ -z "$module_hash" ]]; then
  printf 'failed to read module hash from %s\n' "$SSH_HOST" >&2
  exit 1
fi

symbol_map="$ROOT/lab/frida/symbol-maps/$SYMBOL_MODULE_DIR/$module_hash.json"

printf 'ssh_host=%s\n' "$SSH_HOST"
printf 'module=%s\n' "$module_name"
printf 'path=%s\n' "$module_path"
printf 'file_version=%s\n' "$file_version"
printf 'sha256=%s\n' "$module_hash"
printf 'file_size=%s\n' "$file_size"
printf 'symbol_map=%s\n' "$symbol_map"

if [[ -f "$symbol_map" ]]; then
  printf 'stage_supported=true\n'
else
  printf 'stage_supported=false\n'
  printf 'next_action=validate private RVAs and object layouts, then add %s\n' "$symbol_map"
fi
