#!/usr/bin/env bash
#
# Seed the byte-parsing decoder corpora with real, format-correct fixtures so
# coverage-guided fuzzing starts from valid artifacts instead of rediscovering
# the file format from scratch. The round-trip targets take structured
# (Arbitrary) input, not raw bytes, so they need no seeds. Corpus dirs are
# gitignored; this script is idempotent and safe to re-run.
#
#   ./fuzz/seed_corpus.sh
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
fixtures="$root/tests/fixtures"
lzms_fx="$root/crates/lzms/tests/fixtures/lzms"

# copy <target> <src>...  -- copy each existing src into the target's corpus dir
copy() {
  local dir="$here/corpus/$1"; shift
  mkdir -p "$dir"
  local f
  for f in "$@"; do
    [ -e "$f" ] && cp -f "$f" "$dir/"
  done
}

# PA30 decoder + header parser: real deltas (cmd -> * share fuzz_apply's
# embedded cmd.exe reference) plus the recorded crash repros.
copy fuzz_apply       "$fixtures"/deltas/*.pa30 "$fixtures"/fuzz_crash_*.pa30
copy fuzz_pa30_header "$fixtures"/deltas/*.pa30 "$fixtures"/fuzz_crash_*.pa30

# LZMS WIM decode: genuine Microsoft solid WIM resources.
copy fuzz_lzms_wim "$lzms_fx"/*.resource

echo "Seeded:"
for d in "$here"/corpus/*/; do
  [ -d "$d" ] || continue
  printf '  %-22s %s files\n' "$(basename "$d")" "$(find "$d" -type f | wc -l | tr -d ' ')"
done
