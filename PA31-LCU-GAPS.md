# PA31 decoder gaps — real Win11 24H2 LCU express deltas

Tracking 16 real-world PA31 deltas pulled from a full OS cumulative update that
`pa30::apply` could not reconstruct. **8 of 16 are now fixed**; the rest are
characterized below. Status as of the LZMS rebuild-order + x86-filter fixes.

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

## What was fixed (8/16, all verified against the embedded SHA256)

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

## What remains (8/16)

### delta_03 — residual LZMS divergence (1 blob)

`sxsoaps.dll` **x86**, 10752 bytes, the only delta-match-dominant LZMS blob.
Now decodes to the right length and a valid PE header but wrong middle bytes.
Confirmed **not** the x86 filter (hash identical with the filter bypassed) — a
genuine LZMS bitstream divergence, most likely in the delta-match path on a
case the eight passing blobs don't exercise.

### Group B — PseudoLzx/LZX decode bug (7 blobs: 01,05,06,08,10,12,13)

`lzx::decompress_with_rift` decodes to the correct length but wrong bytes.
Independent of LZMS. delta_05 (12800B, **single segment** per `LZX_SEG_DEBUG`)
is the minimal repro — so it is **not** a multi-segment/segment-transition bug.
A valid PE header decodes, so the Huffman construction is fundamentally right;
the divergence is content-specific and later in the stream.

## Why the oracle can't localize these yet

The remaining two bugs produce right-length/wrong-bytes output; the embedded
hash gives pass/fail but not the divergence offset. Ground-truth bytes from
genuine `msdelta.dll` would pinpoint it. The lab VM (`jackson-dev`) runs **RTM
26100.0**, whose `msdelta.dll` rejects these **26100.8457-era** deltas with
`ERROR_INVALID_DATA` regardless of source (null, empty, or large zero-filled) or
`ApplyFlags`. A `CreateDeltaB`+`ApplyDeltaB` self-test on the same box passes, so
the P/Invoke harness is correct — it is a build/format gate. Unblocking needs a
**build-matched (26100.8457) `msdelta.dll`**.

## Reproduction

```sh
# regenerate the corpus (git-ignored raw MS payload)
cd ~/projects/msu
cargo run --release -- gaps /path/to/windows11.0-kb5089549-x64_*.msu \
  -o ~/projects/msdelta/notes/pa31-lcu-gaps

# run the gated regression test (skips when the corpus is absent)
cd ~/projects/msdelta
cargo nextest run --test pa31_lcu_gaps    # asserts >= 8/16 reconstruct
```

## Next steps

1. **Source a 26100.8457 `msdelta.dll`** (or update the lab VM) to unblock the
   differential oracle; then byte-diff delta_03 and delta_05 to localize.
2. **delta_03**: audit the LZMS delta-match decode path against wimlib for the
   case it exercises that the eight passing blobs do not.
3. **Group B**: localize the PseudoLzx divergence with delta_05 (single-segment,
   12800B) once truth bytes are available.
4. Raise `KNOWN_GOOD` in `tests/pa31_lcu_gaps.rs` toward 16/16 as each lands.
