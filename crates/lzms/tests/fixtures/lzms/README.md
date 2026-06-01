# LZMS test fixtures

Real LZMS-format buffers used to validate the decoder against genuine Microsoft
output. These are excluded from the published crate (see `exclude` in
`crates/lzms/Cargo.toml`); they are only needed for development from a git
checkout.

## Compression API container pairs (`*.lzms` / `*.raw`)

Each `<name>.lzms` is a Windows Compression API LZMS buffer (the `0xC0E5510A`
container produced by `Compress()` with `COMPRESS_ALGORITHM_LZMS`); the matching
`<name>.raw` is the expected decompressed output. The `tests` module in
`src/lib.rs` decodes each `.lzms` and asserts it equals the `.raw`.

- **Source:** generated on Windows Server 2025 via `cabinet.dll`'s LZMS codec.
- **Cross-check:** the codec was verified against `wimlib` and the `cabinet.dll`
  Ghidra decompilation (see `reference/LZMS_ANALYSIS.md`); the container header
  CRC bytes in these fixtures are reproduced bit-for-bit by `container.rs`.

| Fixture | Raw size | Notes |
|---|---|---|
| `zeros` | 4096 | all zero bytes (long-run / rep-match) |
| `sequential` | 1024 | `0..=255` repeated |
| `pattern` | 8192 | small repeating pattern |
| `single_byte` | 16384 | one byte value repeated |
| `english` | 1600 | English-like text |
| `small` | 64 | short buffer |
| `random` | 2048 | incompressible; stored verbatim (`.lzms` > `.raw`) |

## WIM solid LZMS resources (`wim_solid_lzms_ms*.resource`)

Genuine Microsoft solid LZMS resources, extracted verbatim from real ESD files
at their blob-table offsets. Decoded by `decompress_wim_solid` in the
`wim_genuine_ms` integration test.

- **Source:** produced on Windows Server 2025 (`wimgapi.dll` 10.0.26100.1,
  DISM 10.0.26100.5074) with `dism /Export-Image ... /Compress:recovery`, which
  packs the image into a single solid LZMS resource. The solid layout
  (`[u64 uncompressed_size][u32 chunk_size][u32 format=3]` + an `N`-entry
  chunk-size table + chunk data) was reverse-engineered from these bytes.

The `_rebuild` fixture is from a real distributed `.esd` (a Windows 11
professional UUP build payload, downloaded from Microsoft's CDN), not a
DISM-made solid: its single chunk packs a `.cat` catalog plus component
manifests, so it decodes enough distinct symbols to cross the 1024-symbol
adaptive-Huffman rebuild threshold. The repetitive fixtures above never rebuild,
so it is the one that exercises the rebuild path.

| Fixture | On-disk | Decodes to |
|---|---|---|
| `wim_solid_lzms_ms.resource` | 78 B | 180000 B of repeated "The quick brown fox..." text (1 solid chunk) |
| `wim_solid_lzms_ms_3chunk.resource` | 64 B | 140 MiB of zeros across three 64 MiB solid chunks |
| `wim_solid_lzms_ms_rebuild.resource` | 12026 B | 27972 B of `.cat` + manifests; crosses the Huffman rebuild threshold |
