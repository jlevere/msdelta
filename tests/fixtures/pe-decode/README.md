# Native PE decode fixtures

A small, architecture-diverse set of genuine `msdelta.dll` PE deltas, committed
so CI validates the PE transform pipeline (the git-ignored bulk/matrix corpora
only run locally). Each directory holds:

- `base.bin` — the reference image (genuine Windows binary).
- `delta.pa30` — the genuine `CreateDeltaB` forward delta (raw PA30).
- `target.bin` — the genuine target image; `apply(base, delta)` must equal it
  byte-for-byte (`tests/pe_decode.rs`).

Captured from Windows Server 2025 (build 26100) via the UUP/PSF servicing flow,
then minimized to a single (base, delta, target) triple per component. Chosen
to span the architectures and transforms:

| Fixture | Arch | Exercises |
|---|---|---|
| `wow64_kbdmaori` | i386 (WoW64) | sections, relocations |
| `x86_mscordbi` | i386 | x86 call/jmp transform, relocations |
| `amd64_kbdwol` | amd64 | sections, relocations, pdata |
| `amd64_provdiagnostics` | amd64 | imports/exports, relocations, pdata |
