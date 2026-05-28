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

## What's implemented

| | Decode | Encode |
|-|--------|--------|
| **PA30** (primary format) | yes | yes |
| **PA31** (extended header) | yes | yes |
| **PA19** (legacy LZX) | yes | - |
| **DCM** (manifest wrapper) | yes | yes |
| **PseudoLzx** codec | yes | yes |
| **BsDiff** codec | yes | yes |
| **LZMS** codec | yes | yes |
| **PE transforms** (rift tables, timestamps) | yes | yes |

PE delta encoding auto-detects x86/x86-64 binaries and generates rift tables from section layout, data directories, imports, exports, resources, and exception tables.

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
cargo build
cargo test
```

MSRV: 1.82

## Known limitations

- One multi-segment DCM fixture (WOW64 proxystub, 3.2MB output) has a decode divergence at byte 249 vs `msdelta.dll`. All other fixtures decode correctly. See `notes/blockers.md`.
- PA19 encoding not implemented (legacy format, `lxzd` crate is decode-only).
- LZX encoder does not use rift tables during match finding (rift is written for the decoder but compression doesn't exploit it).

## License

MIT OR Apache-2.0
