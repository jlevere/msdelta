# msdelta

Pure-Rust implementation of Microsoft's MSDelta binary patch format. Encodes and decodes PA30, PA31, and PA19 deltas — the format behind Windows Update, WinSxS manifest compression, MSP/MSU patches, and WSUSSCAN.cab.

No Windows dependencies. No C bindings. Just `&[u8]` in, `Vec<u8>` out.

## Usage

```rust
// Apply a delta
let target = msdelta::pa30::apply(&reference, &delta)?;

// Create a delta
let delta = msdelta::pa30::create(&old_file, &new_file)?;

// Decompress a DCM-wrapped WinSxS manifest
let pa30_data = msdelta::dcm::strip(&compressed_manifest)?;
let xml = msdelta::pa30::apply(&base_manifest, pa30_data)?;
```

### Encoder options

```rust
use msdelta::pa30::*;

let delta = CreateOptions::new()
    .codec(Codec::BsDiff)              // or Codec::PseudoLzx (default)
    .file_type(FileType::Auto)         // auto-detect PE, fall back to RAW
    .hash_algorithm(HASH_ALG_SHA256)   // embed integrity hash
    .version(FormatVersion::PA31)      // or FormatVersion::PA30 (default)
    .execute(&old_file, &new_file)?;
```

## Command-line tool

The crate ships an `msdelta` binary (enabled by default via the `cli` feature):

```sh
cargo install msdelta          # or: cargo build, then target/release/msdelta
```

```sh
# Decompress a WinSxS manifest (DCM wrapper and delta format auto-detected)
msdelta apply base_manifest.bin core.manifest -o core.xml

# Create a delta, with an embedded SHA-256 integrity hash
msdelta create old.bin new.bin -o patch.delta --hash sha256

# Apply a delta and also emit the reverse delta (target -> reference)
msdelta reverse old.bin patch.delta -o reverse.delta --target new.bin

# Inspect a delta header (works on raw PA30/PA31/PA19 or DCM)
msdelta info core.manifest

# Hash a buffer (--normalize zeroes volatile PE fields first)
msdelta signature mydll.dll --hash sha256 --normalize

# Shell completions
msdelta completions zsh > ~/.zsh/completions/_msdelta
```

Output goes to stdout when `-o` is omitted, so commands compose in pipelines;
the tool refuses to dump a binary delta onto an interactive terminal. Run
`msdelta <command> --help` for the full option set.

Library-only consumers can drop the clap/anyhow dependencies entirely:

```toml
msdelta = { version = "0.1", default-features = false }
```

## What's implemented

| | Decode | Encode (self round-trip) |
|-|--------|--------------------------|
| **PA30** (primary format) | yes | yes |
| **PA31** (extended header) | yes | yes |
| **PA19** (legacy LZX) | yes | - |
| **DCM** (manifest wrapper) | yes | yes |
| **PseudoLzx** codec | yes | yes |
| **BsDiff** codec | yes | yes |
| **LZMS** codec | yes | yes |
| **PE transforms** (offset/rift, timestamps) | yes | yes |
| **PE transforms** (byte-rewriting: CALL/JMP/disasm/CLI) | partial | partial |

PE delta encoding auto-detects x86/x86-64 binaries and generates rift tables from section layout, data directories, imports, exports, resources, and exception tables.

### PE transforms

MSDelta preprocesses PE targets through a pipeline of transforms (the decoder
undoes them). **Which transforms run is selected by a flag word in the delta
header** (set by the encoder), AND'd against a static transform table — it is
*not* re-derived from the machine type at apply time. Two layers gate them:

- `file_type == 1` (**RAW**) skips the PE pipeline entirely; only output
  post-processes that are flag-gated (e.g. the `0xE8`/`0xE9` x86 filter on
  header flag bit 0) apply.
- `file_type != 1` (**PE/CLI**) runs the full pipeline below, each transform
  enabled by its own header flag bit.

| Transform | Kind | Status |
|-----------|------|--------|
| PseudoLzx / LZMS / BsDiff payload + LRU/rift offset remap | offset | implemented |
| PE timestamp fixup (COFF / export / debug dirs) | offset | implemented |
| `RelativeCallsX86` / `RelativeJmpsX86` — `0xE8`/`0xE9` displacements | content | **implemented, header-flag-gated** (`0xE8` done; `0xE9` not yet) |
| `SmashLockPrefixesX86` — x86 lock-prefix IAT smash | content | not implemented |
| `TransformImports` / `Exports` / `Resources` | content + offset | partial — rift remaps offsets; RVA-rewrite half missing |
| `TransformRelocations` (HIGHLOW/DIR64 + inferred-x86) | content | partial — not wired into `apply()` |
| Instruction disasm — X64 / ARM / ARM64 | content | not implemented |
| CLI metadata / disasm (.NET) | content | not implemented |
| `.pdata` — X64 / ARM / ARM64 | content | not implemented |

**Decode status is honest by artifact class:**

- **RAW deltas** (the entire express-LCU class): verified bit-exact — MD5-identical
  to `msdelta.dll` across all bundled DCM/PE manifest fixtures, and **377/377**
  against a full Win11 24H2 LCU express PSF (baseless PA31), including the
  header-flag-gated `0xE8` x86 filter.
- **PE/CLI deltas** (`file_type != 1`): the transform pipeline above is
  **partial and largely unvalidated** — the express-LCU corpus contains no such
  deltas, so the import/export/resource/reloc/disasm/CLI/pdata transforms have no
  population oracle yet. This is the active frontier; each needs a per-transform
  inverse validated in isolation and PE-type fixtures (fetched per-architecture
  via the `uup` toolchain).

**Encoder ↔ Windows compatibility is partial and being closed.** Note that
`PA31` is **not** an `msdelta.dll` format at all — `msdelta.dll` (build 26100)
implements only PA30/PA19 and rejects PA31 with `ERROR_INVALID_DATA`. PA31 lives
in **`UpdateCompression.dll`** / **`dpx.dll`**, which expose the same
`ApplyDeltaB` and are the correct oracle for PA31 / SHA-256 deltas. A
differential cross-check passes for **RAW PseudoLzx** (PA30 against `msdelta.dll`,
PA31 against `UpdateCompression.dll`) at any size, with the identical-input and
empty-target edge cases. Still open: the **BsDiff** codec framing, and the
**byte-rewriting PE transforms** above. See
[Known limitations](#known-limitations).

## API surface

Equivalent to the core `msdelta.dll` exports:

| Win32 function | Rust equivalent |
|----------------|-----------------|
| `ApplyDeltaB` | `pa30::apply()` |
| `CreateDeltaB` | `pa30::create()` / `CreateOptions` |
| `ApplyDeltaGetReverseB` | `pa30::apply_get_reverse()` |
| `ApplyDeltaProvidedB` | `pa30::apply_into()` |
| `GetDeltaInfoB` | `pa30::get_info()` |
| `GetDeltaInfoExB` | `pa30::get_info_ex()` |
| `GetDeltaSignatureB` | `pa30::get_signature()` |
| `DeltaNormalizeProvidedB` | `pa30::normalize_for_signature()` |

## Building

```sh
cargo build                       # library + msdelta binary
cargo build --no-default-features # library only (no clap/anyhow)
cargo test
```

MSRV: 1.85

## Known limitations

- Encoder ↔ `msdelta.dll` compatibility is partial. A Windows cross-check
  (genuine `ApplyDeltaB`, build 26100) currently passes for RAW PseudoLzx/PA30
  at any size (the encoder emits the same "simple mode" framing as genuine
  deltas for small inputs and "complex mode" for large ones), with an MD5
  hash, and for identical/empty-target edges. Still open:
  - **BsDiff** codec: rejected with `ERROR_INVALID_DATA`; our LZMS-wrapped
    BsDiff container framing does not match `msdelta.dll`.
  - **PE rift transforms**: accepted structurally but decode to incorrect
    bytes; the rift/preprocess encoding does not match `msdelta.dll`'s
    interpretation. This is the largest open item.
  - **PA31** and **SHA-256**: `msdelta.dll` does not implement PA31 — it is a
    `UpdateCompression.dll` / `dpx.dll` format. Validate PA31/SHA-256 deltas
    against those, not `msdelta.dll`.
  - Genuine deltas stamp a creation FILETIME in the header (bytes 4-11) that
    this crate zeroes; not required for acceptance but a divergence.

  The in-crate round-trip tests pass because this crate's decoder mirrors its
  own encoder conventions; Windows is the only ground truth for the encoder.
- Byte-rewriting PE transforms (CALL/JMP/lock-prefix/disasm/CLI metadata) are
  incomplete — see the [PE transforms](#pe-transforms) table. The decoder
  reconstructs 369/377 of a real LCU express PA31 population; the rest need these.
- PA19 encoding not implemented (legacy format, the `lzxd` crate is decode-only). PA19 decode works.
- LZX encoder does not use rift tables during match finding (rift is written for the decoder but compression doesn't exploit it).

Decode is verified MD5-identical to `msdelta.dll` across all bundled DCM/PE
fixtures, including the multi-segment WOW64 proxystub manifest.

## License

MIT OR Apache-2.0
