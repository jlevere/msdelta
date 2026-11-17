"""Compare verified native snapshots with snapshots of the Rust apply path.

Reports boundary differences and execution order separately. A differing map
representation or an omitted no-op call is not classified as a semantic bug.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import NotRequired, TypedDict, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pa31-header"))
from make_probes import Reader  # noqa: E402


class Marker(TypedDict):
    file: str
    sha256: str


class Event(TypedDict):
    kind: str
    ordinal: int
    stage: str
    phase: str
    file: str
    sha256: str
    marker: NotRequired[Marker]


class RustTrace(TypedDict):
    schema: int
    id: str
    source_sha256: str
    delta_sha256: str
    delta: str
    expected_sha256: str
    events: list[Event]


class NativeStage(TypedDict):
    id: int
    name: str
    enter_order: int
    leave_order: int
    has_markers: bool
    artifact_sha256: dict[str, str]


class NativeStages(TypedDict):
    schema: int
    dll_sha256: str
    harness_sha256: str
    stages: list[NativeStage]


class Capture(TypedDict):
    schema: int
    dll_sha256: str
    harness_sha256: str
    stage_trace_sha256: str
    uninstrumented_output_equal: bool
    decompress_source_unchanged: bool
    artifact_sha256: dict[str, str]


ALIASES = {
    "mark-non-exe": "MarkNonExe",
    "imports": "TransformImports",
    "exports": "TransformExports",
    "resources": "TransformResources",
    "relocations": "TransformRelocations",
    "inferred-i386": "InferredRelocationsI386",
    "cli-disasm": "TransformCliDisasm",
    "cli-metadata": "TransformCliMetadata",
    "jmps-i386": "RelativeJmpsX86",
    "calls-i386": "RelativeCallsX86",
    "disasm-amd64": "DisasmX64",
    "pdata-amd64": "PdataX64",
    "lock-source": "SmashLockPrefixesX86",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verified(directory: Path, name: str, expected: str) -> bytes:
    data = (directory / name).read_bytes()
    if sha256(data) != expected:
        raise ValueError(f"artifact digest mismatch: {directory / name}")
    return data


def difference(left: bytes, right: bytes) -> dict[str, object]:
    offsets: list[int] = []
    count = abs(len(left) - len(right))
    for offset, (a, b) in enumerate(zip(left, right)):
        if a != b:
            count += 1
            if len(offsets) < 12:
                offsets.append(offset)
    return {
        "equal": left == right,
        "rust_size": len(left),
        "native_size": len(right),
        "different_byte_count": count,
        "first_different_offsets": offsets,
        "length_difference_starts_at": min(len(left), len(right)) if len(left) != len(right) else None,
    }


def verify_header_only_hash_change(original: bytes, observed: bytes) -> str:
    if original == observed:
        return "identical delta"
    if original[:4] != b"PA30" or observed[:12] != original[:12]:
        raise ValueError("native capture used a different delta without supported PA30 signature-only lineage")
    original_reader = Reader(original[12:])
    observed_reader = Reader(observed[12:])
    if [original_reader.integer() for _ in range(4)] != [observed_reader.integer() for _ in range(4)]:
        raise ValueError("native capture changed PA30 file type, flags, or target size")
    original_reader.integer()
    original_reader.buffer()
    if observed_reader.integer() != 0 or observed_reader.buffer():
        raise ValueError("native delta signature mutation is not algorithm0 plus empty target hash")
    for _ in range(2):
        if original_reader.buffer() != observed_reader.buffer():
            raise ValueError("native capture changed preprocess or compressed payload")
    if original_reader.position != original_reader.limit or observed_reader.position != observed_reader.limit:
        raise ValueError("unexpected delta trailing data")
    return "only PA30 algorithm and target digest disabled; payload, preprocess, flags, file type, target size and FILETIME identical"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rust", type=Path, help="directory containing trace.json")
    parser.add_argument("native", type=Path, help="directory containing capture.json and stages.json")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rust = cast(RustTrace, json.loads((args.rust / "trace.json").read_text()))
    capture = cast(Capture, json.loads((args.native / "capture.json").read_text()))
    stages_bytes = verified(args.native, "stages.json", capture["stage_trace_sha256"])
    native = cast(NativeStages, json.loads(stages_bytes))
    if rust["schema"] != 1 or capture["schema"] != 1 or native["schema"] != 1:
        raise ValueError("unsupported trace schema")
    if not capture["uninstrumented_output_equal"] or not capture["decompress_source_unchanged"]:
        raise ValueError("native instrumentation control failed")
    if native["dll_sha256"] != capture["dll_sha256"] or native["harness_sha256"] != capture["harness_sha256"]:
        raise ValueError("native trace provenance mismatch")
    native_artifacts = {name: verified(args.native, name, digest) for name, digest in capture["artifact_sha256"].items()}
    if sha256(native_artifacts["source.bin"]) != rust["source_sha256"]:
        raise ValueError("Rust and native traces used different source files")
    if sha256(native_artifacts["target.bin"]) != rust["expected_sha256"]:
        raise ValueError("native control does not reconstruct the corpus truth digest")
    original_delta = Path(rust["delta"]).read_bytes()
    if sha256(original_delta) != rust["delta_sha256"]:
        raise ValueError("original delta changed after Rust trace")
    lineage = verify_header_only_hash_change(original_delta, native_artifacts["delta.pa30"])
    rust_bytes = {event["ordinal"]: verified(args.rust, event["file"], event["sha256"]) for event in rust["events"]}
    rust_markers = {event["ordinal"]: verified(args.rust, event["marker"]["file"], event["marker"]["sha256"]) for event in rust["events"] if "marker" in event}
    paired: list[dict[str, object]] = []
    native_only: list[dict[str, object]] = []
    native_order: list[str] = []
    matched_ordinals: set[int] = set()
    seen: dict[str, int] = {}
    for stage in sorted(native["stages"], key=lambda stage: stage["enter_order"]):
        blobs = {name: verified(args.native, name, digest) for name, digest in stage["artifact_sha256"].items()}
        prefix = f"stage-{stage['id']:02}-{stage['name']}-"
        before, after = blobs[prefix + "before.bin"], blobs[prefix + "after.bin"]
        name = ALIASES.get(stage["name"])
        occurrence = seen.get(stage["name"], 0)
        seen[stage["name"]] = occurrence + 1
        candidates = [event for event in rust["events"] if event["stage"] == name and event["phase"] == "before"]
        if name is None or occurrence >= len(candidates):
            native_only.append({"stage": stage["name"], "enter_order": stage["enter_order"], "source_changed": before != after, "marker_changed": blobs[prefix + "marker-before.bin"] != blobs[prefix + "marker-after.bin"], "interpretation": "unmatched stage; absence alone does not establish a semantic divergence"})
            continue
        native_order.append(name)
        record: dict[str, object] = {"stage": name, "native_name": stage["name"], "native_enter_order": stage["enter_order"], "native_leave_order": stage["leave_order"]}
        for phase in ("before", "after"):
            events = [event for event in rust["events"] if event["stage"] == name and event["phase"] == phase]
            if occurrence >= len(events):
                raise ValueError(f"missing Rust {phase} event for {name}")
            event = events[occurrence]
            matched_ordinals.add(event["ordinal"])
            record[f"rust_{phase}_ordinal"] = event["ordinal"]
            record[phase] = difference(rust_bytes[event["ordinal"]], blobs[prefix + phase + ".bin"])
            if stage["has_markers"] and event["ordinal"] in rust_markers:
                record[f"marker_{phase}"] = difference(rust_markers[event["ordinal"]], blobs[prefix + "marker-" + phase + ".bin"])
        paired.append(record)
    rust_order = [event["stage"] for event in rust["events"] if event["ordinal"] in matched_ordinals and event["phase"] == "before"]
    boundaries: list[dict[str, object]] = []
    for stage, phase, filename in [("TransformedSource", "after", "transformed-source.bin"), ("Decompress", "after", "decompressed-target.bin"), ("Apply", "after", "target.bin"), ("CallerRift", "after", "caller-rift.bin"), ("PatchRift", "after", "patch-rift.bin"), ("MergedRift", "before-sort", "merged-rift.bin")]:
        events = [event for event in rust["events"] if event["stage"] == stage and event["phase"] == phase]
        if len(events) != 1:
            raise ValueError(f"expected exactly one Rust boundary {stage}/{phase}, got {len(events)}")
        event = events[0]
        boundaries.append({"stage": stage, "phase": phase, "kind": event["kind"], **difference(rust_bytes[event["ordinal"]], native_artifacts[filename]), "interpretation": "exact serialized map comparison only; representation differences are not assigned semantic meaning" if event["kind"] == "rift" else "exact buffer comparison"})
    result = {"schema": 1, "id": rust["id"], "native_dll_sha256": capture["dll_sha256"], "native_harness_sha256": capture["harness_sha256"], "delta_lineage": lineage, "shared_stage_order_equal": rust_order == native_order, "rust_shared_stage_order": rust_order, "native_shared_stage_order": native_order, "stages": paired, "native_only_stages": native_only, "boundaries": boundaries, "scope": "observed boundary differences; causal attribution requires matching input state, stage contract and execution order"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"id": rust["id"], "shared_stage_order_equal": result["shared_stage_order_equal"], "boundaries": [{"stage": boundary["stage"], "equal": boundary["equal"], "different_byte_count": boundary["different_byte_count"]} for boundary in boundaries], "native_only_stages": native_only}, indent=2))


if __name__ == "__main__":
    main()
