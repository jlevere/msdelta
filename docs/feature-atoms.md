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
Promotion gate:
Done when:
```

The most important fields are `State before`, `Transition`, `State after`, and
`Address domain`. Most bugs in this project come from proving the wrong state
transition, or mixing source RVA, target RVA, source file offset, and target
file offset.

`Promotion gate` is the evidence required before the atom may be used by a
larger atom. A pure finite classifier can promote on exhaustive unit tests. A
parser needs a native reader-window fixture. A transform needs an entry/exit
fixture at the transform boundary. A rift producer needs the native rift before
it is summed into a later copy map.

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

## Readiness Gates

Track each atom by the strongest thing it can safely do today:

| Gate | Meaning |
|---|---|
| `observed` | native symbol or graph is known, but the transition is not isolated |
| `specified` | inputs, state transition, outputs, and failure policy are written down |
| `modeled` | Rust has a typed representation and synthetic tests |
| `fixture-backed` | curated native fixture replay validates the atom boundary |
| `composed` | a parent atom uses it while preserving fail-loud diagnostics |
| `released` | normal apply/create may rely on it for supported file types |

Do not skip gates for large state machines. If an atom cannot be independently
fixture-backed, that is a signal to split it or to move the boundary to the
nearest observable native function. `bulk` evidence can raise confidence after
composition, but it does not replace a fixture-backed atom contract.

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
3. Decide the promotion gate before implementation starts.
4. Build the smallest synthetic test that exercises the transition.
5. Capture or create an oracle fixture packet.
6. Implement the atom behind fail-loud gating.
7. Promote the registry status only after the atom passes its stage oracle.
8. Run the broad corpus and update the classifier buckets.

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

## Work Lanes

The project should now move in lanes instead of a single queue. Each lane feeds
the others, and each can make progress without pretending a whole file type is
done.

| Lane | Purpose | Current rule |
|---|---|---|
| Lab/oracle lane | Frida capture, promotion, version matrix, native diffing | Improve this before adding many more undocumented atoms |
| Model/parser lane | typed wire/object models and reader-window fixtures | Keep parser atoms fixture-backed before using them in transforms |
| Algebra/rift lane | pure maps, heap/table rifts, rift composition | Prefer small call-record fixtures and property tests |
| Transform lane | PE/IL/metadata byte mutation | Do not start broad transform work until input models and maps are stable |
| Release gate lane | apply/create dispatch and unsupported diagnostics | Fail loud until every required atom for a file type is composed |

This is the practical planning unit: choose the next atom from the lane that
removes the most ambiguity for the others. Right now that usually means
improving the lab/oracle lane or a pure rift/model atom before writing another
large transform.

## Module Boundaries

Keep every serious atom split into four concerns:

| Concern | Owns | Should not own |
|---|---|---|
| semantic model | typed Rust state and invariants | bit-level parsing, fixture paths, native pointers |
| wire parser/writer | bitstream layout and malformed-input errors | transform policy or native-lab assumptions |
| transition/algebra | pure state change under test | file IO, Frida data, broad apply dispatch |
| oracle adapter | fixture normalization and native comparison | production behavior |

This is the maintainability rule that matters most for the managed path:
native evidence may change how we understand an atom, but that should usually
change an oracle adapter or a small transition function, not a whole transform
pipeline. Production code should depend on semantic models and explicit
transitions. Tests may depend on fixture packets. Lab tools may depend on
native layouts. Those dependencies should not point the other way.

When a file starts accumulating multiple concerns, split by concern before
splitting by convenience. For example, `CliMapBitstream` and
`CliCodedTokenMap` can live near each other because they share a model, but the
bitstream reader, coded-token algebra, and native fixture replay should remain
separate entry points.

## Extension Points

Future atom work should add to explicit registries rather than editing several
switches:

| Area | Extension point |
|---|---|
| feature map | one row in `docs/feature-atoms.tsv` |
| Rust parser/model | one typed module or submodule with focused tests |
| native symbol hooks | one symbol-map function entry with versioned layouts |
| Frida stage capture | one capture adapter entry |
| fixture tests | one shared contract plus atom-specific assertions |

If adding an atom requires touching unrelated parser, transform, and fixture
code at the same time, the atom boundary is probably still too large.

For managed/.NET work, the typed subsystem root is `src/pe/cli/`. New managed
atoms should extend that namespace with explicit model, wire, transition, or
oracle modules. Do not add new CLR metadata parsing or rewriting logic directly
to generic PE modules unless the behavior is genuinely PE-wide.

## Next Atom Selection

Pick the next atom by asking:

1. Can we isolate a native boundary for it?
2. Can the Rust behavior be replayed against a small fixture?
3. Does it unblock several later atoms?
4. Can it be tested without full `ApplyDeltaB` success?
5. Will failure produce a useful atom-level diagnostic?

If the answer to any of the first three questions is no, spend the turn on the
lab harness, symbol map, object normalizer, or atom split first. This keeps
reverse-engineering effort from turning into untestable production code.

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

## PE Header Layout

`PeHeaderLayout` is the typed PE NT-header and optional-header layout atom. It
owns the raw file offsets for the fields that MSDelta transforms mutate or use
to route managed/native behavior:

- `e_lfanew` and PE signature validation
- COFF `Machine`, section count, `TimeDateStamp`, and optional-header size
- PE32 vs PE32+ optional-header kind
- `ImageBase`, `SizeOfImage`, `CheckSum`, `NumberOfRvaAndSizes`, and the data
  directory table start
- Section-table header offsets

Transform and classifier code should not rediscover these offsets by hand. Use
`PeHeaderLayout` for header field access, then use `PeDataDirectories` and
`PeLogicalSections` for directory and RVA/file-offset interpretation.

This atom is deliberately layout-only. It does not prove that a directory points
to mapped bytes, that a section is semantically valid, or that a managed image is
supported by the transform pipeline.

## PE Logical Sections

`PeLogicalSections` is the architecture-neutral section/address-domain atom.
It owns the conversion rules shared by PE transforms, managed metadata parsing,
and WinSxS base extraction:

- A section's logical RVA span is `max(VirtualSize, SizeOfRawData)`.
- RVA-to-file-offset mapping requires file-backed raw data, but may land in raw
  padding when raw size is larger than virtual size.
- File-offset-to-RVA and same-section checks use the raw file range only.
- Callers must still bounds-check the returned file offset against the concrete
  buffer before reading.

Keep source RVA, target RVA, source file offset, and target file offset explicit
when composing this atom with rifts or transform markers.

## PE Data Directories

`PeDataDirectories` is the named optional-header data-directory atom. It owns
the mapping from PE directory ordinals to explicit transform concepts such as
imports, resources, exception/pdata, base relocations, and the CLR runtime
header.

- Directory-specific code must request a `DataDirectoryKind`; raw numeric
  indexes are reserved for code that intentionally walks the complete PE table.
- Missing optional-header slots return `None`; present zero-valued slots return
  a `PeDataDirectory` whose `is_empty()` helper treats either zero component as
  absent for directory-to-directory rift generation.
- The directory value is still an RVA/size pair. Callers must map RVAs through
  `PeLogicalSections` helpers and bounds-check the concrete buffer before
  reading or rewriting bytes.
- Managed PE detection and CLR metadata parsing should use
  `DataDirectoryKind::ClrRuntimeHeader` rather than hard-coded COM descriptor
  ordinals.

## Near-Term Milestones

1. Keep `RiftTable::reverse` debug/release parity in the release suite; the
   known overlap, gap, and wrap vectors now use explicit wrapping arithmetic.
2. Turn the TSV into an in-crate feature gate used by `apply()` so unsupported
   paths identify the missing atom instead of collapsing into generic failure.
3. Make fixture promotion repeatable for internal stage captures. The current
   manual curation worked, but it will not scale to many CLI rift and transform
   atoms.
4. Add `NativeOracleDiff`: a normalized-object comparator that can replay Rust
   stage output against promoted native stage captures.
5. Close the current managed parser/model gaps: native `CliMetadata::Init`
   with row/heap accessor samples, CLI4 metadata bitstream, targeted
   non-identity `CliCodedTokenMap`, and native `CliBlobTransformer::GetNumber`.
6. Build the first managed rift producer ladder:
   `CliHeapRift` -> `CliTableRift` -> `CliCompressionRift` ->
   `FinalPeCopyRiftManaged`.
7. Build `TransformContextManaged` before byte transforms, then start the
   managed transform ladder after the context and rift ladder are fixture-backed:
   `MarkNonExeCliMethods`, `TransformCliDisasm`, `CliBlobTypeTokenRemap`, and
   `TransformCliMetadata`.
8. Run the bulk classifier after each composed milestone and update the registry
   buckets by atom, section, flag, and byte range.
9. Add ARM64 classification and fixtures before implementing ARM64 transforms.
