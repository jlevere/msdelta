# msdelta — implementation status

Comprehensive audit against msdelta.dll (Windows Server 2025, build 26100),
UpdateCompression.dll, mspatcha.dll, mspatchc.dll, cabinet.dll, and wcp.dll.

> **Governing strategy:** see "Rails: code is the truth, validation is native"
> in `docs/feature-atoms.md`. The three rules (atoms are code not rows;
> promotion requires native ground truth; validation is bidirectional and judged
> by the native DLL) and the Phase 1-3 re-rail plan supersede the tactical
> milestone list. This file tracks status; that section sets direction.

## Win32 API coverage

### msdelta.dll exports (16 functions)

| Export | Status | Notes |
|--------|--------|-------|
| `ApplyDeltaB` | **done** | `pa30::apply()` |
| `ApplyDeltaGetReverseB` | **done** | `pa30::apply_get_reverse()` |
| `ApplyDeltaProvidedB` | **done** | caller-provided output buffer variant |
| `ApplyDeltaA` / `ApplyDeltaW` | n/a | ANSI/Unicode file-path wrappers, not relevant for a library |
| `CreateDeltaB` | **done** | `pa30::create()` / `CreateOptions` |
| `CreateDeltaA` / `CreateDeltaW` | n/a | ANSI/Unicode file-path wrappers |
| `GetDeltaInfoB` | **done** | `pa30::get_info()` |
| `GetDeltaInfoA` / `GetDeltaInfoW` | n/a | ANSI/Unicode wrappers |
| `GetDeltaSignatureB` | **done** | `pa30::get_signature()` |
| `GetDeltaSignatureA` / `GetDeltaSignatureW` | n/a | ANSI/Unicode wrappers |
| `DeltaFree` | n/a | Rust ownership handles this |
| `DeltaNormalizeProvidedB` | **done** | `pa30::normalize_for_signature()` |

### UpdateCompression.dll extras (1 additional)

| Export | Status | Notes |
|--------|--------|-------|
| `GetDeltaInfoExB` | **done** | returns PA31 extended fields (field1/field2/field3 + extra hash) |

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
| PA31 | **done** | **done** | extended header with 3 extra i32 fields + extra hash |
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
| Multi-segment composite format | done | **done** | encoder always writes 1 segment |
| Pre-tree delta/RLE encoding | done | done | delta/RLE symbols 17-38 |
| Rift table in patch bitstream | done | **missing** | encoder writes empty rift; PE rift goes in preprocess only |

### LZMS details

| Feature | Decode | Encode | Notes |
|---------|--------|--------|-------|
| LZ matches | done | done | |
| Delta matches | done | **done** | encoder never emits delta matches |
| X86 E8/E9 filter | done | done | |
| Adaptive Huffman rebuild | done | done | |
| Compression API wrapper | done | done | 24-byte header format |
| Stored-data fallback | done | done | when compressed >= original |

---

## PE transform pipeline

> Authoritative status from the 2026-06 transform-coverage audit (full matrix,
> tier-ranked worklist, per-transform in-vacuum test plan, and per-arch fixture
> plan in `notes/pa31-lcu-gaps/TRANSFORM-COVERAGE-AUDIT.md`).

**Architecture.** Which transforms run on apply is selected by a flag word in the
delta header (`+0x20`, set by the encoder) AND'd against a static transform table
— *not* re-derived from the PE machine at apply time. `file_type == 1` (RAW)
skips the whole PE pipeline; only flag-gated output post-processes apply (e.g.
the `0xE8`/`0xE9` x86 filter on flag bit 0). The shipped/express corpus is **all
RAW**, so it exercises **zero** PE transforms.

**Honest coverage: ~1 of 17 PE transforms.** RAW is complete; the PE/CLI path
(`file_type != 1`) is the open frontier. `rift_from_exports/pdata/resources` and
`transform_inferred_relocations_*` are **dead code with no live callers** — not
coverage.

| # | Transform | Rewrites content? | Our status | Risk |
|---|-----------|:---:|---|:---:|
| 1 | RelativeCallsX86 (0xE8) | yes | **done** — header-flag-gated (bit 0) | — |
| 2 | RelativeJmpsX86 (0xE9) | yes | missing | high |
| 3 | SmashLockPrefixesX86 (0xF0) | yes | missing | high |
| 4 | TransformDisasmX64 (RIP-rel) | yes | missing | high |
| 5 | TransformDisasmARM (Thumb-2) | yes | missing | low |
| 6 | TransformDisasmARM64 | yes | missing | high |
| 7-8 | TransformCli(4)Disasm (IL RID) | yes | missing | high |
| 9-10 | TransformCli(4)Metadata (#~) | yes | missing (cli_metadata/cli_map discarded) | high |
| 11 | TransformImports (0x03 fill + RVA) | yes | partial (offset half only) | high |
| 12 | TransformExports (EAT/NPT RVA) | yes | missing (rift_from_exports dead) | med |
| 13 | TransformRelocations (HIGHLOW/DIR64) | yes | partial (Mode B dead, Mode A absent) | high |
| 14 | TransformResources (.rsrc RVA tree) | yes | partial (coarse, dead) | high |
| 15 | TransformPdataX64 (RUNTIME_FUNCTION) | yes | missing | high |
| 16-17 | TransformPdata ARM / ARM64 | yes | missing | high |

Offset-only, working: PseudoLzx/LZMS/BsDiff payloads, LRU/rift offset remap, PE
timestamp fixup, RAW decode.

**Tiered worklist** (content-rewrite × artifact frequency × silent-corruption risk):
- **T0 (do first): loud-fail detector** — hard-error when a delta enables a
  transform we don't faithfully implement (non-empty `cli_metadata`/`cli_map`, or
  an unhandled transform flag bit), turning silent `HashMismatch` corruption into
  an honest "unsupported transform" error.
- **T1 (amd64-dense corpus):** TransformPdataX64, TransformRelocations (Mode A),
  TransformDisasmX64.
- **T2:** TransformImports (0x03 fill undo), TransformExports, TransformResources.
- **T3:** RelativeJmpsX86, SmashLockPrefixesX86, TransformDisasmARM64/PdataARM64.
- **T4:** the four CLI transforms (managed assemblies), DisasmARM/PdataARM (ARM32).

Each transform is a pure byte→byte fn and must get its own in-vacuum tests
(round-trip identity, proptest, negative-gating, oracle differential) — never
relying on the full `apply()` pipeline or a single population corpus.

**Fixtures (the corpus has NO `file_type != 1` deltas):** source per-arch PE
deltas via `uup` (`fe3` enumerate + `psf` extract) + `msu gaps`: amd64 LCU/SSU
(pdata/reloc/disasm), i386 (code DLL + the `.mui` gating pair), ARM64
(pdata/disasm — growing, silent-prone), and a real .NET servicing PSF (or two
`CreateDeltaB` C# assemblies) for the CLI transforms.

### Encode (create) side

| Transform | Status | Notes |
|-----------|--------|-------|
| PE auto-detection | **done** | `FileType::Auto` tries goblin parse |
| Preprocess buffer construction | **done** | `build_pe_preprocess()` |
| Rift table serialization | **done** | IntFormat write side |
| Timestamp normalization | **done** | replace target timestamps with source |
| Section / data-dir rift generation | **done** | match by name / fixed index |
| Import / export / resource / pdata rift | **partial** | offset half only; content-rewrite half (see matrix) missing, and these mostly aren't wired on the apply side |
| Rift-aware match finding | missing | encoder ignores rift during LZX compression |

---

## Known bugs

| Bug | Severity | Notes |
|-----|----------|-------|
| (none open) | — | The WOW64 proxystub multi-segment divergence is **fixed** (`debug_wow64_divergence` passes). The big open work is the PE transform pipeline above, not a discrete bug. |

---

## Missing infrastructure

| Feature | Priority | Notes |
|---------|----------|-------|
| **PE transform pipeline** | **high** | the frontier — see the matrix above; start with the T0 loud-fail detector |
| Configurable target size limit | low | currently hardcoded 64 MB |
| PA31 encoding | medium | header extension fields; decoder already handles it |
| `no_std` support | low | would need to feature-gate `std`, replace `Vec` allocations |
| Streaming API | low | current API is one-shot `&[u8]` → `Vec<u8>` |

(`ApplyDeltaProvidedB`, `DeltaNormalizeProvidedB`, `GetDeltaInfoExB` are all
implemented — see the API surface table in the README.)

---

## Testing gaps

| Area | Status | Notes |
|------|--------|-------|
| DCM manifest roundtrips | **done** | all bundled fixtures pass (incl. WOW64 proxystub) |
| RAW delta roundtrips | **done** | PseudoLzx + BsDiff |
| PE delta roundtrips | **done** | cmd→cmd_patched, advapi32_old→advapi32_new |
| PA19 decode | **done** | fixture from Windows |
| PA31 decode (full population) | **done** | 377/377 LCU express deltas, gated in `tests/pa31_lcu_gaps.rs` |
| Fuzz: decoder robustness | **done** | 8 cargo-fuzz targets (incl. fuzz_pa31_apply, fuzz_lzx, fuzz_x86_e8) |
| Fuzz: roundtrip (LZX / BsDiff) | **done** | clean |
| Per-transform in-vacuum tests | **missing** | each PE transform needs isolated round-trip + proptest + oracle (see audit) |
| PE-type (`file_type != 1`) population oracle | **missing** | corpus is all RAW; need per-arch PE deltas via uup (see audit fixture plan) |
| Cross-validation with `UpdateCompression.dll` | partial | manual lab rig; the real PA31 oracle (msdelta.dll has no PA31) |
| Large file tests (>1MB) | missing | only the proxystub fixture (broken) exercises this |
