#!/usr/bin/env bash
# Differential-oracle lab orchestrator.
#
# Given a local job directory (produced by `oracle gen`), push it to the
# Windows reference host, run oracle_harness.ps1 against each reference DLL, and
# pull back result.<dll>.json plus any <id>.<dll>.gold files. Decoding the
# golds and scoring happen back on the mac (phases 0d/0e), not here.
#
# Transport hops:  mac --(P620_KEY)--> p620 --(JD_KEY)--> jackson-dev (Windows)
#
# Lab coordinates come from the environment; the defaults match the current
# Ludus lab. Authentication is key-based only -- never put passwords here.
#
# Usage:
#   lab/run.sh <local-job-dir> [dll ...]
#   DLLS default to: msdelta.dll UpdateCompression.dll
set -euo pipefail

JOB_DIR="${1:?usage: run.sh <local-job-dir> [dll ...]}"
shift || true
if [[ $# -gt 0 ]]; then DLLS=("$@"); else DLLS=(msdelta.dll UpdateCompression.dll); fi

P620="${P620:-root@100.123.247.127}"
P620_KEY="${P620_KEY:-$HOME/.ssh/azvpn-p620}"
JD_USER="${JD_USER:-Administrator}"
JD_HOST="${JD_HOST:-10.1.10.10}"
JD_KEY="${JD_KEY:-/root/.ssh/jd_key}"             # path ON p620
P620_DIR="${P620_DIR:-/tmp/oracle-run}"
VM_DIR="${VM_DIR:-C:/oracle-run}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$HERE/oracle_harness.ps1"

log() { printf '[run] %s\n' "$*" >&2; }
ssh_p620() { ssh -i "$P620_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$P620" "$@"; }
scp_p620() { scp -O -i "$P620_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$@"; }

[[ -f "$JOB_DIR/job.json" ]] || { echo "no job.json in $JOB_DIR" >&2; exit 1; }
[[ -f "$HARNESS" ]] || { echo "missing harness $HARNESS" >&2; exit 1; }

# 1. Package the job locally into a temp tarball OUTSIDE the job dir (taring a
#    dir into itself races with its own output). Only ship the inputs, never
#    stale result.*.json / *.gold from a previous run.
log "packaging $JOB_DIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
tar czf "$STAGE/job.tgz" -C "$JOB_DIR" \
    --exclude='result.*.json' --exclude='*.gold' --exclude='.*.tgz' .

# 2. Stage on p620.
log "staging on p620 ($P620)"
ssh_p620 "rm -rf '$P620_DIR' && mkdir -p '$P620_DIR'"
scp_p620 "$STAGE/job.tgz" "$P620:$P620_DIR/.job.tgz"
scp_p620 "$HARNESS" "$P620:$P620_DIR/"

# 3. Push to the VM, extract, run the harness per DLL, collect results -- all
#    driven from p620 (the VM is not reachable from the mac directly).
log "pushing to VM ($JD_USER@$JD_HOST) and running ${DLLS[*]}"
DLLS_STR="${DLLS[*]}"
ssh_p620 bash -s -- "$P620_DIR" "$VM_DIR" "$JD_USER@$JD_HOST" "$JD_KEY" "$DLLS_STR" <<'REMOTE'
set -euo pipefail
# ssh flattens the command line, so the space-separated DLL list arrives as
# multiple positional args (5, 6, ...), not one. Collect them all.
P620_DIR="$1"; VM_DIR="$2"; VM="$3"; JD_KEY="$4"; DLLS="${*:5}"
# -n is REQUIRED: this script is itself fed to `bash -s` over ssh stdin, so an
# ssh without -n would consume the rest of the script as its own stdin.
ssh_vm()  { ssh -n -i "$JD_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no "$VM" "$@"; }
scp_vm()  { scp -O -i "$JD_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no "$@"; }

# Fresh VM dir, push payload, extract with the built-in tar.
ssh_vm "powershell -NoProfile -Command \"Remove-Item -Recurse -Force '$VM_DIR' -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force '$VM_DIR' | Out-Null\""
scp_vm "$P620_DIR/.job.tgz" "$P620_DIR/oracle_harness.ps1" "$VM:$VM_DIR/"
ssh_vm "powershell -NoProfile -Command \"Set-Location '$VM_DIR'; tar -xzf .job.tgz\""

for dll in $DLLS; do
  tag="${dll%.*}"
  echo "[p620] running harness for $dll"
  ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -File '$VM_DIR/oracle_harness.ps1' -Dir '$VM_DIR' -Dll '$dll' -Out '$VM_DIR/result.$tag.json'" || echo "[p620] harness for $dll exited nonzero"
done

# Pull results + gold deltas back to p620. A minimize run produces no golds, so
# the literal *.gold prints a harmless "couldn't visit" warning; bsdtar still
# archives the matched result.*.json into a valid out.tgz. Suppress that stderr
# at the ssh level (escaping a powershell redirect through all these shell
# layers is more trouble than it's worth).
ssh_vm "powershell -NoProfile -Command \"Set-Location '$VM_DIR'; tar -czf out.tgz result.*.json *.gold\"" 2>/dev/null || true
scp_vm "$VM:$VM_DIR/out.tgz" "$P620_DIR/out.tgz"
REMOTE

# 4. Pull results back to the mac, unpack into the job dir.
log "pulling results to $JOB_DIR"
scp_p620 "$P620:$P620_DIR/out.tgz" "$JOB_DIR/.out.tgz"
tar xzf "$JOB_DIR/.out.tgz" -C "$JOB_DIR"
rm -f "$JOB_DIR/.out.tgz" "$JOB_DIR/.job.tgz"

log "done. results in $JOB_DIR:"
ls -1 "$JOB_DIR"/result.*.json 2>/dev/null || log "(no result files -- check harness output above)"
