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
| **PE transforms** — native x86 / x64 | yes (byte-exact) | reconstructs (not byte-exact) |
| **PE transforms** — managed (.NET / CLI) | no | no |

### PE transforms

MSDelta preprocesses PE targets through a pipeline of transforms before
compression; the decoder reproduces the transformed source (`T(source)`) and the
copy/literal stream resolves against it. **Which transforms run is selected by a
flag word in the delta header**, AND'd against a static transform table. Two
layers gate them:

- `file_type == 1` (**RAW**) skips the PE pipeline; only flag-gated output
  post-processes (e.g. the `0xE8` x86 filter on header bit 0) apply.
- `file_type != 1` (**PE**) runs the pipeline below, each transform enabled by
  its own header flag bit, in `g_transformsMap` order.

The implementation plan for making this tractable is tracked as feature atoms:
small state transitions with explicit contracts, oracles, and status. See
[`docs/feature-atoms.md`](docs/feature-atoms.md) and the machine-readable
registry in [`docs/feature-atoms.tsv`](docs/feature-atoms.tsv). Native
stage-oracle capture is planned in
[`docs/frida-oracle-system.md`](docs/frida-oracle-system.md).

**Decode** of native x86 / x64 PE deltas is complete and byte-exact (see status
below). **Encode** of native PE now reconstructs the target: all 659 genuine
targets in the corpus round-trip through this crate's decoder (0 broken), at
~1.34x genuine's size. The output is **not yet byte-exact-identical** to genuine
(matching genuine's exact preprocess rift and LZX parse is open work, tracked by
the encode oracle); the header is byte-exact.

| Transform (decode) | Status |
|--------------------|--------|
| PseudoLzx / LZMS / BsDiff payload + LRU/rift copy placement | implemented |
| Copy-rift composition (`Multiply`/`Reverse`/`Sum`, source re-anchor at breakpoints) | implemented (genuine-exact) |
| PE timestamp + ImageBase header fixups | implemented |
| `PeUnbinder` (reset bound imports, mark `.idata` writable) | implemented |
| `RelativeCallsX86` / `RelativeJmpsX86` (`0xE8`/`0xE9` + near→short collapse) | implemented |
| `0xE8` x86 whole-image filter (header bit 0) | implemented |
| `TransformImports` / `Exports` / `Resources` (RVA + thunk/offset rewrite) | implemented (x86 + x64) |
| `TransformRelocations` (HIGHLOW + DIR64, block rebuild) | implemented |
| `DisasmX64` (RIP-relative disp32) + `PdataX64` (RUNTIME_FUNCTION/unwind) | implemented |
| Instruction disasm / `.pdata` — ARM / ARM64 | not implemented |
| CLI metadata / disasm (.NET managed) | not implemented (rejected) |

**Decode status, by artifact class:**

- **RAW deltas** (express-LCU class): bit-exact — MD5-identical to `msdelta.dll`
  across all bundled DCM/PE manifest fixtures and **377/377** against a full
  Win11 24H2 LCU express PSF (baseless PA31).
- **Native PE deltas** (x86 / x64, `file_type != 1`): **byte-exact** — verified
  identical to genuine across a curated diverse WinSxS matrix (**25/26**: DLLs,
  EXEs, `.mui`, keyboard layouts; i386 + amd64), each cross-checked by dumping
  genuine's intermediate `T(source)` and composed rift. An architecture-diverse
  subset is committed and gated in CI (`tests/pe_decode.rs`); the broader matrix /
  rift corpora run locally. At scale, a **659-fixture** genuine-delta corpus
  decodes **651 byte-exact (98.8%)** hash-verified against genuine; the remaining
  8 are a documented long-tail (below).
- **Managed / .NET PE deltas**: detected via the reference's CLR header and
  **rejected** with `Error::Unsupported` rather than decoded wrong. The CLI
  metadata/disasm transform family is unimplemented.
- **Long-tail native edges** (8 of the 659): a few binaries carry operand /
  relocation relayout deltas (e.g. `.text` absolute-pointer and `.reloc` block
  remaps) genuine applies that this crate does not yet reproduce exactly — these
  surface as a **clean `HashMismatch` error** from `apply()` (which verifies the
  embedded SHA-256 target hash), never silent corruption. ARM/ARM64
  instruction/`.pdata` transforms are likewise unimplemented (no fixtures yet).

**Encoder ↔ Windows compatibility is partial.** Note that
`PA31` is **not** an `msdelta.dll` format at all — `msdelta.dll` (build 26100)
implements only PA30/PA19 and rejects PA31 with `ERROR_INVALID_DATA`. PA31 lives
in **`UpdateCompression.dll`** / **`dpx.dll`**, which expose the same
`ApplyDeltaB` and are the correct oracle for PA31 / SHA-256 deltas. A
differential cross-check passes for **RAW PseudoLzx** (PA30 against `msdelta.dll`,
PA31 against `UpdateCompression.dll`) at any size, with the identical-input and
empty-target edge cases. For **native PE**, the encoder now reconstructs every
genuine target (verified by re-decoding our own delta to the genuine bytes across
all 659 corpus deltas) with a byte-exact header, but the body is not yet
byte-identical to genuine — the open work is matching genuine's exact preprocess
rift and LZX parse. See
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

**Decode** (the primary use case) is complete for RAW and native x86 / x64 PE
deltas. Not yet supported:

- **Managed / .NET images**: deltas whose target carries a CLI metadata stream
  are rejected (`Error::Unsupported`) — the CLI metadata/disasm transform family
  is unimplemented. ARM / ARM64 instruction and `.pdata` transforms are likewise
  unimplemented (no fixtures yet).

**Encode ↔ Windows** compatibility is partial. A cross-check against genuine
`ApplyDeltaB` (`msdelta.dll` build 26100 for PA30, `UpdateCompression.dll` /
`dpx.dll` for PA31) passes for **RAW PseudoLzx** at any size, with MD5/SHA-256
hashes and identical/empty-target edges. Still open:

- **BsDiff** codec: our LZMS-wrapped container framing does not match genuine.
- **Byte-exact PE encode**: native PE encode reconstructs every genuine target
  (round-trip-verified across the 659-delta corpus; byte-exact header), but the
  delta body is not yet byte-identical to genuine — matching genuine's exact
  preprocess rift and LZX parse is open.
- `msdelta.dll` does not implement **PA31** — validate PA31 / SHA-256 against
  `UpdateCompression.dll` / `dpx.dll`. Genuine deltas also stamp a creation
  FILETIME (header bytes 4-11) this crate zeroes (a benign divergence).

In-crate round-trip tests prove self-consistency; Windows is the ground truth.

- **PA19 encoding** not implemented (legacy; `lzxd` is decode-only). Decode works.
- The LZX encoder uses the rift for offset selection (SOURCE_COPY / signed-delta
  anchoring) with cost-based lazy matching, but does not yet reproduce genuine's
  exact parse, so encoded deltas run ~1.34x genuine's size.

## License

MIT OR Apache-2.0
