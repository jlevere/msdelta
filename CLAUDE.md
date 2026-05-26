# msdelta

Pure-Rust encoder and decoder for Microsoft's MSDelta (PA30) binary
patch format.

## Goal

There is no Rust crate that can read or write MSDelta-format buffers.
This crate fills that gap. The primary downstream consumer is Windows
component manifest decompression (the DCM-wrapped `.manifest` files in
`WinSxS`), but the format also underlies Windows Update deltas, MSP/MSU
patches, WSUSSCAN.cab, and various other Microsoft binary-patch
artifacts. A decent pure-Rust implementation is broadly useful, not just
for one project.

The library is bidirectional by design: anything we can read, we want to
be able to write. The API target is a direct equivalent of Win32's
`ApplyDeltaB` (decode) and `CreateDeltaB` (encode) — given a reference
buffer and either a delta or a target, produce the other side. The
realistic order of work is decode first, encode second; encode is
genuinely in scope, just later.

### Why bidirectional matters

- Round-trip tests are the cleanest correctness signal — decode a real
  artifact, re-encode it, check bit-for-bit identity (or at least
  decode-equivalence).
- Fuzzing the decoder against generated-but-valid inputs from our own
  encoder is far more powerful than fuzzing raw random bytes.
- Anyone wanting to build, not just consume, Windows-style delta
  artifacts (custom servicing tooling, research patches, modified
  manifest blobs) needs the write side too.

Structured fuzzing support (cargo-fuzz harnesses, proptest strategies
for the IR types) is a future goal once both directions are working.

## Where the format lives in Windows

- `msdelta.dll` (system32) — owns the PA30 algorithm. Exported entrypoints
  of interest: `ApplyDeltaB`, `ApplyDeltaGetReverseB`.
- `wcp.dll` (system32) — Windows Component Platform. Owns the DCM wrapper
  format and the base-manifest reference. Source path strings reveal the
  implementation lives in `onecore\base\wcp\manifestcompression\
  manifest_compression.cpp` with entry points
  `Windows::WCP::Implementation::Rtl::DecompressManifest` and
  `IsManifestCompressed`.
- `ServicingCommon.dll` (ships with WSIM in the ADK) — thin native shim
  that loads `msdelta.dll` and calls `ApplyDeltaB` directly. Useful as a
  cross-check on the calling convention.

DCM on disk is a 4-byte `DCM\x01` magic followed immediately by a PA30
delta. The reference (base manifest) is owned by `wcp.dll` and reused
across every compressed manifest in WinSxS. To produce the full original
XML we need both the PA30 decoder and access to that base.

## Reference material

- **WSIM decompilation** lives at `~/projects/ephw/reference/wsim/` in
  the ephw project. Mostly managed C#, useful for understanding the
  surrounding catalog-generation flow. The delta logic itself is in
  `ServicingCommon.dll` (native PE) and the OS DLLs it loads.
- **Native DLLs from a Windows host**: `msdelta.dll` and `wcp.dll` need
  to be pulled from `C:\Windows\System32\` on a Windows machine for
  serious reverse engineering. ephw's jackson-dev VM is the convenient
  source.
- **Existing decoders**: `wcpex` (https://github.com/smx-smx/wcpex) is a
  C tool that decompresses WinSxS manifests. Closest existing reference
  implementation. Read for algorithm understanding; clean-room rule
  applies.

## Clean-room rule

Decompiled C# from WSIM and any disassembly of `msdelta.dll` / `wcp.dll`
are research material only. Read to understand algorithms, data layouts,
and edge cases. Do NOT paste Microsoft source, decompiler output, or
disassembly verbatim into this crate, its comments, or commit messages.
Translate behaviour into idiomatic Rust.

## Dev environment

```sh
nix develop
cargo build
cargo nextest run
```

The devshell ships `radare2` for poking at the DLLs.

## Conventions

- No emojis in source, comments, or commit messages.
- Don't write summary markdown files unless explicitly asked.
- Test fixtures (real DCM files) live in `tests/fixtures/`; see the
  README in that directory for provenance.
