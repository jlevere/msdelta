# Delta Test Fixtures

Generated on Windows Server 2025 (26100 24H2) using `msdelta.dll`'s `CreateDeltaB`.

## Source/Target PEs

All from `C:\Windows\System32\` on the VM. MD5-verified.

| File | Size | MD5 |
|------|------|-----|
| `sources/cmd.exe` | 339,968 | 6D109A3A00F210C1AB89C3B08399ED48 |
| `sources/where.exe` | 65,536 | 8066FE09B1F19BA7752896C2FD68B04C |
| `sources/notepad.exe` | 360,448 | 9E60393DA455F93B0EC32CF124432651 |
| `sources/cmd_patched.exe` | 339,968 | cmd.exe with bytes 100-119 XOR'd with 0x01 |

## Delta Files

| Delta | Bytes | FTS | FT | Flags | Source -> Target | Codec Path |
|-------|-------|-----|----|-------|------------------|------------|
| `cmd__to__where__raw.pa30` | 18,048 | 1 | 1 (RAW) | 0x0 | cmd.exe -> where.exe | PseudoLzx only |
| `cmd__to__notepad__raw.pa30` | 179,471 | 1 | 1 (RAW) | 0x0 | cmd.exe -> notepad.exe | PseudoLzx only |
| `cmd__to__notepad__raw_flag0x20000.pa30` | 179,474 | 1 | 1 (RAW) | 0x20000 | cmd.exe -> notepad.exe | Same as manifests use |
| `cmd__to__notepad__raw_bsdiff_flag0x100.pa30` | 179,472 | 1 | 1 (RAW) | 0x100 | cmd.exe -> notepad.exe | BsDiff path (flags bit 8) |
| `cmd__to__cmd_patched__pe_amd64.pa30` | 139 | 15 | 8 (AMD64) | 0xe63e | cmd.exe -> cmd_patched.exe | PE transforms + PseudoLzx |

## Key Findings

- The **BsDiff codec** is triggered by `flags & 0x100`, NOT by a FileTypeSet bit.
  CreateDeltaB with `SetFlags=0x100` produces a delta with flags=0x100.
- **PE file type** (8 = AMD64) only works when FileTypeSet includes RAW as fallback
  (fts=0xF). Pure fts=8 returns ERROR_INVALID_DATA (13) for cross-binary deltas
  but works for same-binary patches.
- PE delta flags=0xe63e encodes the PE transform pipeline configuration.
