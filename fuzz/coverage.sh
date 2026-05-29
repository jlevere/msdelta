#!/usr/bin/env bash
#
# Render source-coverage for a fuzz target over its current corpus, so you can
# see which decode/encode branches the corpus never reaches -- that is where
# fuzzing is blind and where the next seed or harness should aim. Run from the
# .#fuzz devShell (needs cargo-fuzz, shipped there).
#
#   ./fuzz/coverage.sh fuzz_apply
#
set -euo pipefail

target="${1:?usage: fuzz/coverage.sh <fuzz-target> [extra cargo fuzz coverage args]}"
shift || true

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

# llvm-cov / llvm-profdata ship inside the nightly toolchain's llvm-tools
# component. We call them directly rather than via cargo-binutils' `cargo cov`
# wrapper, which panics on current clap (arg-action bug in cargo-binutils 0.4).
llvm_bin="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
[ -x "$llvm_bin/llvm-cov" ] || { echo "llvm-cov not found at $llvm_bin" >&2; exit 1; }

# 1. Build with source-coverage instrumentation and replay the whole corpus.
#    Use a dedicated target dir: `cargo fuzz build`/`run` produce sancov-only
#    binaries in fuzz/target, and sharing the cache makes `cargo fuzz coverage`
#    silently reuse a non-instrumented artifact (no covmap -> "no coverage data
#    found"). An isolated dir guarantees a real -Cinstrument-coverage build.
covtarget="$here/target-coverage"
cargo fuzz coverage "$target" --target-dir "$covtarget" "$@"

profdata="$here/coverage/$target/coverage.profdata"
[ -f "$profdata" ] || { echo "no profdata at $profdata" >&2; exit 1; }

# 2. Locate the instrumented binary: the hashed artifact under release/deps
#    (e.g. fuzz_apply-<hash>), not the plain top-level binary. A rebuild can
#    leave several stale hashes behind, so take the newest by mtime -- that is
#    the one the profdata we just generated corresponds to (an older hash would
#    mismatch and llvm-cov would silently report 0%).
bin="$(
  find "$covtarget" -type f -path '*/release/deps/*' -name "${target}-*" \
    ! -name '*.d' ! -name '*.o' ! -name '*.rcgu.*' -exec ls -t {} + 2>/dev/null | head -n1
)"
[ -n "$bin" ] || { echo "could not find instrumented binary for $target under $covtarget" >&2; exit 1; }

# Keep std / registry deps out of the picture; we only care about our own source.
ignore='/(\.cargo|registry|rustc|library/std|library/core|library/alloc)/'

# 3. HTML report, line-by-line.
"$llvm_bin/llvm-cov" show "$bin" \
  -instr-profile="$profdata" \
  -format=html \
  -show-line-counts-or-regions \
  -ignore-filename-regex="$ignore" \
  -output-dir="$here/coverage/$target/html"

# 4. Per-file summary. Scan for low Region% -- those files are under-exercised.
echo
echo "=== region coverage by file ($target) ==="
"$llvm_bin/llvm-cov" report "$bin" \
  -instr-profile="$profdata" \
  -ignore-filename-regex="$ignore"

echo
echo "HTML report: $here/coverage/$target/html/index.html"
