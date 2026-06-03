# PA31 decoder gaps — real Win11 24H2 LCU express deltas

Tracking 16 real-world PA31 deltas pulled from a full OS cumulative update that
`pa30::apply` could not reconstruct. The four bugs that fixed them, and the
differential-oracle method, are documented below.

## ⚠ POPULATION REGRESSION — read this first (2026-06-02)

The four fixes pass all 16 hard cases **but regressed the wider population.**
The original corpus held only the 16 known failures, so it couldn't see this.
Re-validated against **all 377** baseless PA31 deltas in the LCU (via `msu`):

| engine | reconstruct / 377 |
|---|---|
| before the PA31 fixes | **361 / 377** |
| after the PA31 fixes (HEAD `3e17126`) | **193 / 377** |

So the fixes fixed 16 and **broke ~184 deltas that previously worked.** All
regressions are:
- **`target hash mismatch`** (silent wrong output — decode completes, embedded
  hash rejects it), never a parse error;
- predominantly **`comctl32.dll.mui`** (and similar resource `.mui`) across
  *every locale*, small (~3.7–4 KB delta, ~12 KB target);
- **arch-independent** — the amd64 and x86 `.mui` for a locale are byte-identical
  and both regress.

Arch-independence **rules out** the x86-E8 filter fix (`x86_filter.rs`) and the
i386-only `undo_relative_calls_x86` PE transform as the cause — those touch
x86/amd64 *code*, and these are resource-only files with no code, equally broken
on both arches. That points the bisect at the two **arch-independent** changes:
1. the LZMS Huffman **rebuild-order** change (`adaptive.rs`, `build-then-dilute`)
   — fires on any stream long enough to trigger a rebuild (a ~12 KB `.mui`
   output does), or
2. the **LZMS-vs-bsdiff dispatch** change in `pa30/mod.rs` (use decompressed
   bytes directly when `uncompressed_total == target_size`).

Bisect by reverting each in isolation against the full corpus (below).

### Corpus + harness (the fix for the blind spot)

- **`tests/pa31_lcu_gaps.rs`** now applies the **full 377-delta population** (not
  just the 16) and gates `reconstruct >= 361` (no-regression floor; target 377).
  Each delta carries its embedded target SHA256, so `apply` returning `Ok` =
  bit-exact — no external hashing needed. HEAD currently fails it at 193/377.
- Corpus blobs: **`notes/pa31-lcu-gaps/*.bin`** (git-ignored MS payload) +
  `manifest.tsv` (blob → name, size, target SHA256, baseline ok/fail).
- Regenerate from the `.msu`:
  `cd ~/projects/msu && cargo run --release -- gaps <KB5089549.msu> --all -o ~/projects/msdelta/notes/pa31-lcu-gaps`
- Run: `cargo test --release --test pa31_lcu_gaps` (skips if the corpus is absent).

---

## Original 16 hard cases (now passing)

This section documents the four bugs that were fixed and the
differential-oracle method used to find them.

## Where these came from

- Package: **KB5089549**, Windows 11 24H2 x64 cumulative update (build
  26100.8457), the express PSF (`kb5089549-baseless.psf`) inside the `.msu`.
- The PSF's CIX (`express.psf.cix.xml`) is **baseless** — zero `<Basis>`
  elements — so every delta is reconstructed against a **null base**
  (`pa30::apply(&[], delta)`). Each delta carries its own embedded target
  SHA256, which is the ground-truth correctness oracle used throughout.
- Extracted with `~/projects/msu` (`msu gaps <msu> -o <dir>`).
- Of the **377** express deltas in this LCU, 361 always decoded; these 16 were
  the failures.

## The real taxonomy (corrected)

The original analysis lumped all 16 under "one LZMS root cause." That was wrong.
Splitting the pipeline (`pa30::parse` -> `patch_data` -> codec) shows **two
unrelated codec paths**, keyed on whether `patch_data` starts with the LZMS
Compression-API magic (`0A 51 E5 C0`):

| group | blobs | codec path | original symptom |
|---|---|---|---|
| **A — LZMS** | 00,02,03,04,07,09,11,14,15 | `lzms::decompress_compression_api` | LZ/delta "offset past start", or silent corruption (14) |
| **B — PseudoLzx** | 01,05,06,08,10,12,13 | `lzx::decompress_with_rift` | target hash mismatch |

Every "hash-mismatch" (x86) blob is **not** an LZMS stream — it never enters the
LZMS decoder. The amd64/msil-vs-x86 correlation the first pass noticed was a
proxy: amd64/msil components here ship as LZMS containers (header flags
`0x1a06xxxx`), x86 ones as PseudoLzx (`0x1806xxxx`).

For every LZMS-container blob the container's `uncompressed_total` **equals
target_size** — i.e. the LZMS payload IS the target image; there is no bsdiff
layer (a null-base bsdiff stream would be larger than the target).

## What was fixed (16/16, all verified against the embedded SHA256)

### Bug 1 — LZMS adaptive-Huffman rebuild order (`crates/lzms/src/adaptive.rs`)

The decoder diluted (halved) symbol frequencies **before** rebuilding the
Huffman code; msdelta/cabinet.dll/wimlib **build the next code from the
accumulated frequencies, then dilute**. This produces a different canonical code
at every rebuild, desyncing the bitstream after the first rebuild (every
`rebuild_freq` = 512-1024 symbols). It stayed latent because every prior fixture
is either tiny or hugely repetitive and never triggers a rebuild, and our own
round-trips share the bug so they stay self-consistent. Fix: build-then-dilute
(`rebuild_and_dilute`).

### Bug 1b — LZMS x86 filter lock-prefix mask (`crates/lzms/src/x86_filter.rs`)

The `0xF0` (lock) translation case tested `(data[i+2] & 0x07) == 0x05`; the real
filter requires the full byte `== 0x05`. The looser mask fired on bytes the
encoder never translated, corrupting the filter state for the rest of the
buffer. Invisible on resource-only / msil targets (no x86 code); broke large
native DLLs. Fixing it flipped gdiplus/comctl32 (07,09,11,15) to pass.

### Bug 3 — LZMS-vs-raw dispatch (`src/pa30/mod.rs`)

`apply()` unconditionally `bspatch`ed the LZMS output. For these baseless deltas
the decompressed bytes ARE the target. Now: if the LZMS payload decompresses to
exactly `target_size`, use it directly; otherwise fall back to bsdiff.

Result: **00, 02, 04, 07, 09, 11, 14, 15 reconstruct bit-exactly.**

### Bug 4 — missing x86 RelativeCallsX86 transform (`src/pe/transform.rs`)

The root cause of *every* remaining failure (delta_03 and all 7 LZX blobs) is
the same: MSDelta's `RelativeCallsX86` preprocessing was never undone. Genuine
`ApplyDeltaB` converts the 4-byte displacement after every `0xE8` (near CALL) in
an executable section from an absolute form back to PC-relative, but **only on
i386 PEs** (machine `0x14C`). That is exactly the failure pattern: the passing
LZMS blobs are amd64/msil (skipped), the failing ones are x86. Verified by
byte-diff against genuine output: `our_value - genuine == file_offset_of_E8`.

Added `undo_relative_calls_x86`, wired into `pa30::apply`, gated to i386 PEs and
skipping IL-only (.NET) images (managed assemblies are machine `0x14C` too but
must not be touched — `COMIMAGE_FLAGS_ILONLY`). This fixed **delta_03** (the lone
x86 LZMS blob) outright and slashed the LZX diffs (delta_01 1011->24, delta_08
3195->60, delta_12 8519->295).

## The oracle (key unblock)

`msdelta.dll` does **not** implement PA31 (zero `PA31` refs even at 26100.32370);
its `ApplyDeltaB` returns `ERROR_INVALID_DATA`. PA31 lives in
**`UpdateCompression.dll`** / **`dpx.dll`**, which export the same `ApplyDeltaB`.
`DllImport`ing `reference/UpdateCompression.dll` by full path on the lab VM and
applying baseless (empty source) yields the genuine target for all 16 (hashes
match the embedded SHA256). Truth bytes -> `notes/pa31-lcu-gaps/truth_*.bin`
(harness `/tmp/apply_uc.ps1`; pull large files with `scp -O`, the SFTP path
truncates at 200 KiB).

The exact translation was pinned with the oracle: dumping every `0xE8` site's
stored value and comparing translated-vs-not against the genuine output showed
`max(abs_translated) < target_size <= min(abs_untranslated)` for every blob, so
`translation_size == target_size` and the guard is `-i <= v < target_size`.
Gating uses a hand-rolled header read (machine `0x14C`, PE32, CLR/ILONLY check),
not a full `goblin` parse -- goblin over-validates and rejected some valid system
images (e.g. comctl32), which had left delta_13 untransformed.

This fixed the lone x86 LZMS blob (delta_03) and all seven LZX blobs, taking the
corpus to **16/16**. amd64/arm64 and managed (.NET) targets correctly skip the
transform.

## Reproduction

```sh
# regenerate the corpus (git-ignored raw MS payload)
cd ~/projects/msu
cargo run --release -- gaps /path/to/windows11.0-kb5089549-x64_*.msu \
  -o ~/projects/msdelta/notes/pa31-lcu-gaps

# run the gated regression test (skips when the corpus is absent)
cd ~/projects/msdelta
cargo nextest run --test pa31_lcu_gaps    # asserts 16/16 reconstruct
```

## Follow-ups

- `RelativeJmpsX86` (0xE9) and `SmashLockPrefixesX86` were not needed by this
  corpus (no residual diffs), but exist in genuine msdelta; add them if a future
  artifact needs them.
- Non-baseless (source-relative) deltas exercise the rift-driven form of these
  transforms, not the identity case handled here.
