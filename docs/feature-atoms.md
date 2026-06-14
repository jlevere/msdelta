# Feature Atoms

This project should track MSDelta compatibility as a set of small,
falsifiable feature atoms. A file type such as `0x8` is too large to be a
good implementation unit: it combines header dispatch, preprocess parsing,
rift composition, PE normalization, architecture transforms, compression,
postprocessing, and hash verification. Each of those pieces needs its own
contract and oracle.

The registry in `docs/feature-atoms.tsv` is the project map. It is deliberately
plain TSV so it can be read by shell tools, Rust tests, and future lab tools
without adding dependencies. The registry is not a replacement for code. It is
the shared plan for what code must prove. The managed/.NET branch has a focused
contract in `docs/managed-cli-atoms.md` because it is a pipeline of metadata,
map, rift, IL, and blob-signature atoms rather than one transform. Native
stage-oracle capture with Frida is specified in `docs/frida-oracle-system.md`.

## Atom Contract

Every non-trivial atom should be specified before implementation:

```text
Atom:
Native reference:
Layer:
Kind:
File types:
Flag mask:
Inputs:
State before:
Transition:
Outputs:
State after:
Address domain:
No-op conditions:
Failure conditions:
Oracle strategy:
Fixture packet:
Fuzz/property checks:
Done when:
```

The most important fields are `State before`, `Transition`, `State after`, and
`Address domain`. Most bugs in this project come from proving the wrong state
transition, or mixing source RVA, target RVA, source file offset, and target
file offset.

## Layers

Use these layers when adding atoms to the registry:

| Layer | Purpose | Examples |
|---|---|---|
| `format` | container/header structure | PA30, PA31, PA19, DCM, hashes |
| `codec` | compressed patch payload | PseudoLzx, LZMS, BsDiff flag path |
| `rift` | piecewise map parsing/algebra | read/write, multiply, reverse, sum |
| `pe` | architecture-neutral PE preprocessing | PE info, imports, exports, resources |
| `x86` | i386-only transforms | calls, jumps, E8, lock-prefix handling |
| `x64` | amd64-only transforms | RIP-relative disasm, pdata |
| `ia64` | IA64-only transforms | historical IA64 pdata/disasm path |
| `arm` | ARMNT transforms | ARM disasm, pdata |
| `arm64` | ARM64 transforms | ARM64 disasm, pdata |
| `cli` | managed metadata/IL transforms | CLI metadata, CLI maps, token remap |
| `pipeline` | dispatch/composition policy | file-type classifier, unsupported gates |
| `create` | CreateDeltaB side | raw create, PE create, CLI/ARM create |
| `lab` | workflow and fixture tooling | bulk classifier, stage dumper |

## Status

Registry status is intentionally conservative:

| Status | Meaning |
|---|---|
| `supported` | enabled in normal apply/create and covered by tests/oracles |
| `partial` | implemented or partly implemented, but known gaps remain |
| `rejected` | detected and intentionally rejected in normal apply/create |
| `missing` | known native behavior, no implementation yet |
| `unknown` | identified only by symbols/graph strings or insufficiently scoped |

Do not mark an atom `supported` only because a broad corpus happens to pass.
The atom needs a specific contract and evidence at the right stage.

## Revising Atoms

The registry is a working map, not a schema freeze. Native evidence can and
should change atom boundaries. Split an atom when two behaviors need different
state, fixtures, or fuzz generators; merge atoms when a boundary was only an
implementation convenience and cannot be independently observed. When a split is
about the oracle workflow rather than the Rust behavior, add a `lab` atom and
leave the implementation atom focused on the code contract.

Record coverage gaps as first-class next steps instead of promoting an atom
prematurely. `CliCodedTokenMap` is the current example: natural native calls
prove exact hit/miss behavior and non-exact identity behavior, but a forced
non-identity `MapCoded` call still needs a targeted oracle case.

## Oracle Levels

The registry has a single `oracle_level` field. It records the strongest
current evidence, not every test that exists.

| Level | Meaning |
|---|---|
| `none` | no useful direct evidence |
| `needs_fixture` | behavior known, but no isolated fixture yet |
| `unit` | local synthetic tests only |
| `manual` | one-off lab/oracle evidence, not automated |
| `curated` | checked against curated real fixtures or native dumps |
| `bulk` | broad corpus evidence exists |
| `release` | covered by normal release workspace tests |

## Native Oracles

Native Windows DLLs are the project oracle, but final target equality is too
coarse for the remaining work. Use Frida to capture stage boundaries from the
real implementation and promote normalized captures into fixture packets. The
capture system is its own lab-layer atom set because it must be reproducible
across Windows builds and exact DLL hashes.

The capture order should mirror the atom ladder:

1. export-level `ApplyDeltaB` / `CreateDeltaB` input and output buffers
2. parsed preprocess structures
3. rift tables and composed copy rifts
4. transform entry and exit buffers
5. final target and hash

See `docs/frida-oracle-system.md` for the lab layout, symbol-map format,
normalized object schemas, and version-matrix policy.

## Fixture Packet

An atom fixture should be stage-oriented. Final target equality is useful, but
it is too late in the pipeline to diagnose most failures.

```text
tests/fixtures/atoms/<atom>/<case>/
  source.bin
  target.bin
  delta.pa30 or delta.pa31
  native_tsource.bin
  native_final_rift.tsv
  native_prepost_target.bin
  case.toml
```

`case.toml` should explain the intended isolation:

```toml
atom = "PdataX64"
file_type = "0x8"
flags = "0xe63e"
primary_ranges = [".pdata"]
expected_atoms = ["PePreprocessNative", "FinalPeCopyRiftNative", "PdataX64"]
allowed_noise = ["headers"]
```

The comparison order should be:

1. parsed header and file type
2. parsed preprocess structures
3. decoded or generated rift tables
4. composed final copy rift
5. transformed source, `T(source)`
6. pre-postprocess decoded target
7. final target and embedded hash

This turns a late `HashMismatch` into a specific failed transition.

## Test Ladder

Each atom should move through the same ladder:

| Test | Question answered |
|---|---|
| parser round-trip | can we read and write the structure? |
| synthetic unit | does the local state transition match the contract? |
| property/fuzz | does malformed or randomized input preserve invariants? |
| oracle stage test | does the atom match native behavior at the right stage? |
| pipeline test | does full apply/create still compose correctly? |
| bulk classifier | how often does this atom appear in real corpora? |

For pure atoms, prefer in-module unit tests and proptests. For pipeline atoms,
prefer integration tests that consume fixture packets.

## Implementation Workflow

When starting an atom:

1. Add or update the row in `docs/feature-atoms.tsv`.
2. Write the atom contract using the template above.
3. Build the smallest synthetic test that exercises the transition.
4. Capture or create an oracle fixture packet.
5. Implement the atom behind fail-loud gating.
6. Promote the registry status only after the atom passes its stage oracle.
7. Run the broad corpus and update the classifier buckets.

The fail-loud rule is mandatory: if a delta requires an atom that is not
supported, normal `apply()` should return `Error::Unsupported` with the atom
name, file type, and flags. Lab tools may offer best-effort decode modes, but
library callers should never receive silently corrupted output.

## Learning Loop

Treat each atom as a small research project that must leave behind process
improvements. The goal is not only to make one feature work; it is to make the
next feature less ambiguous.

For each atom, keep the loop explicit:

1. Define the smallest native behavior worth proving.
2. Write the expected contract before writing production code.
3. Build or capture the smallest case that exercises only that behavior.
4. Record every harness, transport, or timing failure as a workflow rule.
5. Add a local test for the rule when it can be automated.
6. Update this guidance or the atom-specific doc before moving to the next atom.

The first Frida export capture followed this pattern. Remote `frida-server`
transport failed on the lab VM, so the stable path became local
`frida-inject.exe` plus a file sink. The first hook attempt missed the native
call, so the harness rule became: load the DLL, pause with the module resident,
attach hooks, then execute the export. Those are not side notes; they are part
of the atom contract machinery because they make future captures reproducible.

When a lesson is local to one atom, put it in that atom's doc. When it changes
how every future atom should be approached, update this file.

## First Atom Pattern

The first managed atom implemented with this workflow is
`ManagedFileTypeBranch`. It is intentionally smaller than the native
`DetermineFileType` concern: it starts after the final PA file type is known and
only answers whether a managed image would use the classic CLI branch or the
CLI4 branch.

Use this as the default shape for future atoms:

1. If the native function covers several responsibilities, split out the pure
   transition first.
2. Write an explicit enum or model for the output state.
3. Exhaustively test small finite domains before adding fixtures.
4. Thread the atom into the pipeline only where it improves fail-loud behavior.
5. Keep downstream behavior rejected until the required parser or transform
   atoms have their own contracts and evidence.

A pure classifier can reach `supported` with `unit` oracle evidence when the
input domain is finite and fully covered. Parser, transform, and rift producer
atoms should not be promoted past `partial` or `missing` without stage fixtures
or native oracle captures.

## First Oracle Pattern

The first lab atom implemented with this workflow was `FridaExportOracle`. It
is not a transform atom; it proves that the project can repeatedly ask Windows
what buffers crossed a native API boundary and normalize that answer into
fixture-shaped data.

The first internal stage capture is
`FridaStageCapture/cli-metadata-win26100`: a hash-selected
`msdelta.dll` hook for `compo::CliMetadata::InternalFromBitReader` that emits
logical `CliMetadataBitstream` records plus standalone native reader-window
bitstreams.

The second internal stage capture is `FridaStageCapture/cli-map-win26100`:
the same hash-selected `msdelta.dll` hook lane for
`compo::CliMap::FromBitReader`. It emits normalized `CliMapBitstream` rift maps
plus reader-window blobs for both empty and populated maps.

The third internal stage capture is
`FridaStageCapture/cli-coded-token-map-win26100`: a non-reader method oracle
for `compo::CliMap::MapCoded` and `compo::CliMap::MapCodedExact`. It emits
normalized call records containing the coded-token kind, raw input, native
return value, and a logical `CliMap` snapshot. This is the first managed
algebra atom validated by call replay rather than by parser bitstreams.

The stage agent snapshots the native reader before and after the call, then
extracts the full consumed bit window into a fresh standalone `BitReader`
stream and rejects the capture if replaying that window does not match the
native exit state. It also traces explicit native `BitReader::Read` calls when
available, but `CliMapBitstream` showed why the full-window extraction is the
actual fixture contract: native Huffman/rift readers can consume bits without
going through the public `Read(n)` helper. The normalized object remains the
stable cross-version assertion; the reader-window blob is the parser input that
proves the wire contract.

For non-reader stage hooks, the fixture contract is the normalized call record:
stable inputs, native return value, and enough normalized object state to replay
the call in Rust. `CliCodedTokenMap` also taught the normalizer to emit signed
64-bit rift values outside JavaScript's safe integer range as decimal strings.

Use this shape for future oracle atoms:

1. Prefer a target program that waits before calling the native function, so
   hooks are installed before the behavior under test occurs.
2. Capture raw bytes immediately at the native boundary; do not rely on the
   caller keeping buffers alive.
3. Normalize tool-specific output into stable `run.json`, `capture.json`, and
   `blobs/*.bin` files.
4. Compare captured blob hashes to known inputs and expected outputs before
   promoting anything.
5. Promote only the smallest capture that proves the behavior.
6. For stage captures, commit normalized logical objects, reader-window blobs,
   and stripped fixture metadata with no volatile file-sink paths.
7. For pure method captures, commit normalized call records and object
   snapshots; do not invent reader blobs when the native function did not
   consume a bitstream.

## Near-Term Milestones

1. Fix debug/release parity for `RiftTable::reverse`.
2. Turn the TSV into an in-crate feature gate used by `apply()`.
3. Add a bulk mismatch classifier that maps each failure to likely atoms and
   byte ranges.
4. Finish the remaining native i386/amd64 apply atoms.
5. Start managed support with the pure parser/model atoms in
   `docs/managed-cli-atoms.md`.
6. Build the Frida oracle loop for `CliMetadata`, `CliMap`, and CLI rift
   captures.
7. Add ARM64 classification and fixtures before implementing ARM64 transforms.
