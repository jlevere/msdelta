# msdelta — implementation status

Comprehensive audit against msdelta.dll (Windows Server 2025, build 26100),
UpdateCompression.dll, mspatcha.dll, mspatchc.dll, cabinet.dll, and wcp.dll.

## Win32 API coverage

### msdelta.dll exports (16 functions)

| Export | Status | Notes |
|--------|--------|-------|
| `ApplyDeltaB` | **done** | `pa30::apply()` |
| `ApplyDeltaGetReverseB` | **done** | `pa30::apply_get_reverse()` |
| `ApplyDeltaProvidedB` | missing | caller-provided output buffer variant |
| `ApplyDeltaA` / `ApplyDeltaW` | n/a | ANSI/Unicode file-path wrappers, not relevant for a library |
| `CreateDeltaB` | **done** | `pa30::create()` / `CreateOptions` |
| `CreateDeltaA` / `CreateDeltaW` | n/a | ANSI/Unicode file-path wrappers |
| `GetDeltaInfoB` | **done** | `pa30::get_info()` |
| `GetDeltaInfoA` / `GetDeltaInfoW` | n/a | ANSI/Unicode wrappers |
| `GetDeltaSignatureB` | **done** | `pa30::get_signature()` |
| `GetDeltaSignatureA` / `GetDeltaSignatureW` | n/a | ANSI/Unicode wrappers |
| `DeltaFree` | n/a | Rust ownership handles this |
| `DeltaNormalizeProvidedB` | missing | normalize a buffer for signature computation |

### UpdateCompression.dll extras (1 additional)

| Export | Status | Notes |
|--------|--------|-------|
| `GetDeltaInfoExB` | missing | returns PA31 extended fields (field1/field2/field3 + extra hash) |

### mspatcha.dll / mspatchc.dll (PA19 legacy)

| Capability | Status | Notes |
|------------|--------|-------|
| PA19 decode | **done** | `pa19::apply()` via `lzxd` crate |
| PA19 encode | missing | would need `mspatchc.dll` parity; low priority (legacy format) |
| PA19 E8 transform | missing | call-instruction translation filter for x86 code sections |
| PA19 signature/normalize | missing | CRC-based, different from PA30's MD5/SHA |

### wcp.dll (DCM wrapper)

| Capability | Status | Notes |
|------------|--------|-------|
| `IsManifestCompressed` | **done** | `dcm::is_dcm()` |
| `DecompressManifest` | **done** | `dcm::strip()` + `pa30::apply()` |
| `CompressManifest` | **done** | `pa30::create()` + `dcm::wrap()` |
| Base manifest embedding | missing | wcp.dll embeds the base; we require caller to supply it |

---

## Format versions

| Format | Decode | Encode | Notes |
|--------|--------|--------|-------|
| PA19 | **done** | missing | legacy, standard LZX via `lzxd` crate |
| PA30 | **done** | **done** | primary format |
| PA31 | **done** (decode) | missing | extended header with 3 extra i32 fields + extra hash |
| DCM | **done** | **done** | 4-byte magic wrapper around PA30 |

---

## Compression codecs

| Codec | Decode | Encode | Notes |
|-------|--------|--------|-------|
| PseudoLzx | **done** | **done** | primary codec for PA30, custom LZX variant |
| LZMS | **done** | **done** | range coder + adaptive Huffman, via Compression API wrapper |
| BsDiff | **done** | **done** | suffix-array match + LZMS compression |
| PA19 LZX | **done** | missing | standard Microsoft LZX via `lzxd` crate |

### PseudoLzx details

| Feature | Decode | Encode | Notes |
|---------|--------|--------|-------|
| Literals | done | done | |
| LRU back-references (3 slots) | done | done | |
| Source-copy (rift-aware) | done | done | encoder doesn't do rift-aware match finding, but writes empty rift |
| Signed offsets (slots 0-2) | done | done | |
| Aligned-offset extra bits | done | done | |
| Multi-segment composite format | done | partial | encoder always writes 1 segment |
| Pre-tree delta/RLE encoding | done | **missing** | encoder writes raw symbols (valid but larger) |
| Rift table in patch bitstream | done | **missing** | encoder writes empty rift; PE rift goes in preprocess only |

### LZMS details

| Feature | Decode | Encode | Notes |
|---------|--------|--------|-------|
| LZ matches | done | done | |
| Delta matches | done | **missing** | encoder never emits delta matches |
| X86 E8/E9 filter | done | done | |
| Adaptive Huffman rebuild | done | done | |
| Compression API wrapper | done | done | 24-byte header format |
| Stored-data fallback | done | done | when compressed >= original |

---

## PE transform pipeline

### Decode (apply) side

| Transform | Status | Notes |
|-----------|--------|-------|
| Preprocess buffer parsing | **done** | image base, timestamp, 2 rift tables, CLI flags |
| Rift table decode | **done** | IntFormat Huffman + delta encoding |
| Rift-adjusted decompression | **done** | `decompress_with_rift()` |
| PE timestamp fixup | **done** | COFF header, export dir, debug dir, debug data scan |
| Inferred relocations (x86-32) | **partial** | function exists but not wired into apply() |
| Inferred relocations (x86-64) | missing | no AMD64 variant |
| CLI metadata handling | missing | errors if CLI flag set (affects .NET assemblies) |
| CLI map handling | missing | errors if CLI map flag set |

### Encode (create) side

| Transform | Status | Notes |
|-----------|--------|-------|
| PE auto-detection | **done** | `FileType::Auto` tries goblin parse |
| Preprocess buffer construction | **done** | `build_pe_preprocess()` |
| Rift table serialization | **done** | IntFormat write side |
| Timestamp normalization | **done** | replace target timestamps with source |
| Section rift generation | **done** | match by name, VA-1 entries |
| Data directory rift generation | **done** | match by fixed index |
| Import descriptor rift | **done** | match by DLL name (simplified) |
| Export table rift | missing | `RiftTableFromExportsFactory` |
| Resource section rift | missing | `RiftTableFromResourcesFactory` |
| Pdata/exception rift | missing | `RiftTableFromPdatasFactory` |
| Import thunk-level rift | missing | per-function IAT matching within each DLL |
| Rift-aware match finding | missing | encoder ignores rift during LZX compression |

---

## Known bugs

| Bug | Severity | Notes |
|-----|----------|-------|
| WOW64 proxystub fixture divergence | **high** | 1 of 7 DCM fixtures fails: output diverges at byte 249 of 3.2MB. Multi-segment complex-mode stream. Likely off-by-1 in bit consumption. Needs Frida instrumentation of msdelta.dll to debug. |

---

## Missing infrastructure

| Feature | Priority | Notes |
|---------|----------|-------|
| `ApplyDeltaProvidedB` equivalent | low | caller-provided output buffer to avoid allocation |
| `DeltaNormalizeProvidedB` equivalent | low | normalize buffer for cross-platform signature verification |
| `GetDeltaInfoExB` equivalent | low | PA31 extra fields already parsed, just needs pub wrapper |
| Configurable target size limit | low | currently hardcoded 64 MB |
| PA31 encoding | medium | header extension fields; decoder already handles it |
| `no_std` support | low | would need to feature-gate `std`, replace `Vec` allocations |
| Streaming API | low | current API is one-shot `&[u8]` → `Vec<u8>` |

---

## Testing gaps

| Area | Status | Notes |
|------|--------|-------|
| DCM manifest roundtrips | **done** | 6 of 7 fixtures pass (proxystub blocked) |
| RAW delta roundtrips | **done** | PseudoLzx + BsDiff |
| PE delta roundtrips | **done** | cmd→cmd_patched, advapi32_old→advapi32_new |
| PA19 decode | **done** | fixture from Windows |
| PA31 decode | missing | no PA31 test fixture |
| Fuzz: decoder robustness | **done** | 5 cargo-fuzz targets, 7 crash bugs found and fixed |
| Fuzz: roundtrip (LZX) | **done** | 183K+ iterations clean |
| Fuzz: roundtrip (BsDiff) | **done** | 183K+ iterations clean |
| Cross-validation with msdelta.dll | partial | manual only, no CI automation |
| Large file tests (>1MB) | missing | only the proxystub fixture (broken) exercises this |
