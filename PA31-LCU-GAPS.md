# PA31 decoder gaps — real Win11 24H2 LCU express deltas

Tracking 16 real-world PA31 deltas that `pa30::apply` does **not** reconstruct
correctly. Found while validating the `msu` crate's express-extract pipeline
against a full OS cumulative update.

## Where these came from

- Package: **KB5089549**, Windows 11 24H2 x64 cumulative update (build
  26100.8457), the express PSF (`kb5089549-baseless.psf`) inside the `.msu`.
- The PSF's CIX (`express.psf.cix.xml`) is **baseless** — zero `<Basis>`
  elements — so every delta applies against a **null base**
  (`pa30::apply(&[], delta)`), per dpx's `ExpandFallback`. No on-image basis
  needed.
- Extracted with `~/projects/msu` (`msu gaps <msu> -o <dir>`), which applies
  every delta null-base and dumps the ones that fail.

## The result

Of the **377** express deltas in this LCU, **every one is `PA31`** (zero
`PA30`). `pa30::apply` handles **361 / 377 (95.8%)** bit-exactly (verified
against the CIX SHA256). The **16** below fail. So this is not "PA31 is
unsupported" — most PA31 decodes fine — it's a handful of PA31 encodings that
hit two distinct bugs.

> **Note on error text / msdelta version.** The categories below are from
> msdelta **HEAD** (the `tests/pa31_lcu_gaps.rs` run). The `msu` crate pins an
> older msdelta rev that reports the LZMS cases generically as
> `malformed stream: control value too large`; HEAD pinpoints them as LZMS
> errors, which is the actionable signal. Fix against HEAD.

### Failure mode A — LZMS decode error (8): `LZMS: LZ offset past start` (×6), `LZMS: delta offset/span past start` (×2)

The PA31 delta's payload is **LZMS-compressed**, and the LZMS decoder hits a
back-reference (LZ match or delta-match) that points **before the start of the
history window**. For a baseless delta the window starts empty, so this is most
likely an LZMS **window / initial-state** bug (preset-dictionary or
match-offset bounds), not a PA31-container issue. **Most actionable** — and it
points squarely at the `lzms` crate, not the PA30/PA31 framing.

### Failure mode B — `target hash mismatch` (7)

The decoder **runs to completion** but produces the wrong bytes, caught by the
delta's **own embedded target hash** (the PA3x header carries one), so msdelta
already knows it miscomputed. A silent divergence — quite possibly the *same*
LZMS bug, manifesting as corruption rather than an out-of-bounds reject.

### Failure mode C — `malformed stream: control value too large` (1)

One blob (`delta_14`, the .NET `baseapi.dll`) still hits the generic
control-value parse error even on HEAD.

## The 16 (full detail in `notes/pa31-lcu-gaps/manifest.tsv`)

All blobs are `PA31`. Sizes are `delta -> reconstructed target`.

| # | arch | mode (HEAD) | delta→target | target file |
|---|---|---|---|---|
| 00 | amd64 | LZMS LZ-offset | 20181 → 69632 | isolationautomation `sxsoa.dll` |
| 01 | x86 | hash-mismatch | 17463 → 36864 | isolationautomation `sxsoa.dll` |
| 02 | amd64 | LZMS delta-offset | 5296 → 36864 | isolationautomation.proxystub `sxsoaps.dll` |
| 03 | x86 | LZMS delta-offset | 3871 → 10752 | isolationautomation.proxystub `sxsoaps.dll` |
| 04 | msil | LZMS LZ-offset | 46683 → 121344 | `microsoft.updateservices.utils.dll` |
| 05 | amd64 | hash-mismatch | 3935 → 12800 | `comctl32.dll.mui` (ug-cn) |
| 06 | x86 | hash-mismatch | 3935 → 12800 | `comctl32.dll.mui` (ug-cn) |
| 07 | amd64 | LZMS LZ-offset | 825704 → 1929216 | `gdiplus.dll` 1.0 |
| 08 | x86 | hash-mismatch | 695640 → 1538048 | `gdiplus.dll` 1.0 |
| 09 | amd64 | LZMS LZ-offset | 825704 → 1929216 | `gdiplus.dll` 1.1 |
| 10 | x86 | hash-mismatch | 695640 → 1538048 | `gdiplus.dll` 1.1 |
| 11 | amd64 | LZMS LZ-offset | 322246 → 742904 | `comctl32.dll` 5.82 |
| 12 | x86 | hash-mismatch | 286647 → 584656 | `comctl32.dll` 5.82 |
| 13 | x86 | hash-mismatch | 972454 → 2251752 | `comctl32.dll` 6.0 |
| 14 | msil | control-too-large | 194508 → 742912 | `microsoft.updateservices.baseapi.dll` |
| 15 | amd64 | LZMS LZ-offset | 1061230 → 2692600 | `comctl32.dll` 6.0 .8457 |

### Patterns worth noting

- **amd64/msil → LZMS hard error; x86 → hash mismatch.** Almost every amd64
  (and the msil) blob hits an LZMS out-of-bounds reject, while every x86 blob
  decodes-but-corrupts. This strongly suggests **one LZMS root cause** that
  sometimes overruns (hard error) and sometimes silently produces wrong bytes.
- Heavy hitters are GDI/UI binaries with large resource sections (`gdiplus`,
  `comctl32`, `*.mui`) and the .NET/msil update-services DLLs.
- 05/06, 07/09, and 08/10 are byte-identical deltas (same offset/hash) shipped
  for multiple assembly identities — so there are ~13 *unique* failing deltas.

## Reproduction

Blobs live in `notes/pa31-lcu-gaps/` (git-ignored; raw MS payload). To
regenerate them from scratch you need the `.msu` (Microsoft Update Catalog,
KB5089549, 24H2 x64) and the `msu` crate:

```sh
# in ~/projects/msu
cargo run --release -- gaps /path/to/windows11.0-kb5089549-x64_*.msu \
  -o ~/projects/msdelta/notes/pa31-lcu-gaps
```

Inspect or reproduce a single failure with msdelta's own CLI (null base =
empty file; `/dev/null` works):

```sh
# in ~/projects/msdelta
cargo run -- info notes/pa31-lcu-gaps/delta_00.bin           # PA31 header
cargo run -- apply /dev/null notes/pa31-lcu-gaps/delta_00.bin -o /tmp/out
#   -> Error: malformed stream: control value too large
cargo run -- apply /dev/null notes/pa31-lcu-gaps/delta_01.bin -o /tmp/out
#   -> Error: target hash mismatch (...)
```

Or run the whole set as a gated test (skips when the corpus is absent):

```sh
cargo nextest run --test pa31_lcu_gaps    # or: cargo test --test pa31_lcu_gaps
```

## Next steps

1. **Start in the `lzms` crate, not PA31 framing.** Modes A and B both look like
   one LZMS decoder bug: `LZ offset past start` / `delta offset/span past start`
   = a match offset that reaches before the window start. Audit window/history
   init and the LZ + delta-match offset bounds for the baseless (empty-window)
   case. The x86 `hash-mismatch` blobs are the same bug failing silently —
   useful because they decode fully, so you can diff the wrong output against
   the expected bytes to localize where the stream diverges.
2. Reproduce minimally: `delta_03` (3871→10752, `delta-offset`) and `delta_05`
   (3935→12800, `hash-mismatch`) are the smallest of each mode — best for
   step-debugging the LZMS decoder.
3. `delta_14` (`control-too-large`) is the one non-LZMS reject; triage
   separately after the LZMS fix.
4. Re-run the gated test until 16/16 reconstruct; then `msu` extracts this LCU
   100% (currently 91710/91726).
