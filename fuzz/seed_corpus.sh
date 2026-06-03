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

# Reverse-delta + XPRESS_HUFF decoders. Genuine reverse diffs are kept out of the
# repo (gitignored under notes/genuine-samples; MS-redistribution); seed from
# there when present so fuzz_apply reaches the reverse/PRSM/XPRESS path and
# fuzz_xpress starts from a real container. No-ops on a fresh clone.
gen="$root/notes/genuine-samples"
if [ -d "$gen" ]; then
  copy fuzz_apply "$gen"/corpus/*/reverse.pa31 "$gen"/sweep/*/reverse.pa31
  copy fuzz_xpress "$gen"/xpress/blob.bin
fi

# PA31-guided apply: the genuine Win11 LCU express PA31 deltas (baseless).
# x86 0xE8 transform: the genuine reconstructed PE images are ideal seeds for
# the header parser + CALL walker. Both dirs are gitignored (raw MS payload);
# no-ops on a fresh clone.
pa31="$root/notes/pa31-lcu-gaps"
if [ -d "$pa31" ]; then
  copy fuzz_pa31_apply "$pa31"/delta_*.bin
  copy fuzz_x86_e8     "$pa31"/truth_*.bin "$pa31"/delta_*.bin
  # fuzz_lzx peels the PA3x header at runtime to reach the real LZX payload.
  copy fuzz_lzx        "$pa31"/delta_*.bin
fi

echo "Seeded:"
for d in "$here"/corpus/*/; do
  [ -d "$d" ] || continue
  printf '  %-22s %s files\n' "$(basename "$d")" "$(find "$d" -type f | wc -l | tr -d ' ')"
done
