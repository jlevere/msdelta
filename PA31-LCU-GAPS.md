# PA31 decoder gaps — real Win11 24H2 LCU express deltas

Tracking 16 real-world PA31 deltas pulled from a full OS cumulative update that
`pa30::apply` could not reconstruct. The four bugs that fixed them, and the
differential-oracle method, are documented below.

## POPULATION REGRESSION — diagnosed and contained (2026-06-02)

The four "16/16" fixes were validated only against the 16 known failures, and one
of them **regressed the wider population.** Re-validated against **all 377**
baseless PA31 deltas in the LCU (via `msu`), bisected by toggling the x86 0xE8
transform:

| engine | reconstruct / 377 |
|---|---|
| before the PA31 fixes | 361 / 377 |
| after the PA31 fixes, x86 E8 transform ON (HEAD `3e17126`) | **193 / 377** |
| after the PA31 fixes, x86 E8 transform OFF (current) | **369 / 377** |

**Root cause (confirmed by bisect): the x86 `0xE8` CALL transform
(`undo_x86_e8_translation`), not the LZMS changes.** Toggling only that call
flips 193 ↔ 369. The LZMS rebuild-order + dispatch fixes are sound and account
for 361 → 369. Current `main` **disables the E8 transform** (`pa30/mod.rs`), so
the population is back to a clean **369/377** with zero regression.

Why the earlier "arch-independent rules out x86" reasoning was wrong: a
`comctl32.dll.mui` is a **resource-only i386 PE** (machine `0x14C`) whether it
ships beside the amd64 or x86 DLL — the two `.mui` are byte-identical i386-PE
bytes. So the i386-gated E8 transform fires on *both*, identically. The bug is
the transform's **guard**: the whole-buffer form translates any `0xE8` whose
operand satisfies `-i <= v < target_size`, which matches resource bytes that are
not calls and corrupts them. Genuine `RelativeCallsX86` is **section/target-aware**
(it only translates when the computed call target lands in a real section), so it
leaves those resource bytes alone.

Decisive evidence it is a per-site *guard* problem, not a file-type one: both
`ug-cn` and `de-de` `comctl32.dll.mui` (same component, same version
`6.0.26100.8117`, resource-only) — **`ug-cn` NEEDS the E8 translation** (fails
without it) while **`de-de` must NOT get it** (the transform corrupts it). The
only difference is locale resource content, i.e. which `0xE8` operands form valid
call targets.

### The 8 still failing at 369/377 (need a correct E8 transform)

`delta_001` `sxsoa.dll` x86, `delta_005` `sxsoaps.dll` x86, `delta_342`/`343`
`comctl32.dll.mui` ug-cn, `delta_369`/`371` `gdiplus.dll` x86, `delta_373`/`374`
`comctl32.dll` x86. Six are x86 *code* DLLs; two are the ug-cn `.mui`. All need
the 0xE8 transform — with a guard that does **not** touch the ~184 resource `.mui`
the whole-buffer form broke.

### Handoff to the next msdelta pass

- **Reference**: genuine `RelativeCallsX86::Run` is decompiled at
  `~/projects/msu/reference/ghidra/decompiled_dpx/Run__180040a00.c` — it walks PE
  sections and validates the call target against `SizeOfImage`/section bounds.
  Reimplement that guard (clean-room) in place of the loose
  `-i <= v < target_size` in `undo_x86_e8_translation`.
- **Oracle**: `msdelta.dll` has no PA31; `UpdateCompression.dll` /`dpx.dll` do.
  `DllImport` `reference/UpdateCompression.dll` on the lab VM and apply baseless
  (empty source) for genuine truth bytes; byte-diff vs our decode to see exactly
  which `0xE8` sites genuine translates (it showed `our_value - genuine ==
  e8_file_offset` at every translated site). Pull large files with `scp -O`
  (SFTP truncates at 200 KiB).
- **Test**: `tests/pa31_lcu_gaps.rs` applies the **full 377-delta population** and
  gates `reconstruct >= 369` (no-regression floor; target 377). Validate any new
  E8 transform against the full corpus, NOT just the 8 — the whole point is to not
  re-break the resource `.mui`.
- **Re-enable**: the transform fn + its `fuzz_x86_e8` target are retained (marked
  not-wired); re-add the `pa30::apply` call once the guard is section/target-aware.

### Corpus + harness

- Corpus blobs: **`notes/pa31-lcu-gaps/*.bin`** (git-ignored MS payload) +
  `manifest.tsv` (blob → name, size, target SHA256, baseline ok/fail).
- Regenerate from the `.msu`:
  `cd ~/projects/msu && cargo run --release -- gaps <KB5089549.msu> --all -o ~/projects/msdelta/notes/pa31-lcu-gaps`
- Run: `cargo test --release --test pa31_lcu_gaps` (skips if the corpus is absent).

---

## Original 16 hard cases (diagnosis + history)

> Historical: this section describes the original 16-blob analysis. The LZMS
> fixes here stand; the x86 0xE8 transform described below is currently DISABLED
> pending the section/target-aware rework (see the regression section above).

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

## What was fixed (the original 16; see regression note for current state)

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

This passed the original 16-blob corpus 16/16 — but the whole-buffer guard was
later found to over-translate resource-only i386 PEs, regressing the full 377
population (see the regression section at the top). The transform is now
disabled pending a section/target-aware rewrite.

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
