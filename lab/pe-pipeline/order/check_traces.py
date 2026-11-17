"""Validate captured native stage ordering against pinned embedded recipes.

Run with uv run --no-project lab/pe-pipeline/order/check_traces.py STATIC_JSON CAPTURE_ROOT OUTPUT_JSON.
Only classic I386/AMD64 captures from the pinned msdelta graph are covered.
The report distinguishes static recipe expectations from observed execution.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "pa31-header"))
from make_probes import Reader  # noqa: E402

NAMES = {
    "MarkNonExe": "mark-non-exe",
    "RiftTransformImports": "imports",
    "RiftTransformExports": "exports",
    "RiftTransformResources": "resources",
    "RiftTransformRelocations": "relocations",
    "RiftTransformRelocationsI386": "relocations",
    "RiftTransformCliDisasm": "cli-disasm",
    "RiftTransformCliMetadata": "cli-metadata",
    "SmashLockPrefixesI386": "lock-source",
    "RiftTransformRelativeJmpsI386": "jmps-i386",
    "RiftTransformRelativeCallsI386": "calls-i386",
    "RiftTransformDisasmAmd64": "disasm-amd64",
    "RiftTransformPdataAmd64": "pdata-amd64",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_files(directory: Path, hashes: dict[str, str]) -> None:
    for name, expected in hashes.items():
        if sha((directory / name).read_bytes()) != expected:
            raise ValueError(f"artifact hash mismatch: {directory / name}")


def check(directory: Path, static: dict[str, Any]) -> dict[str, Any]:
    metadata = json.loads((directory / "capture.json").read_text())
    stages_data = (directory / "stages.json").read_bytes()
    stages = json.loads(stages_data)
    if metadata["dll_sha256"] != static["sha256"] or stages["dll_sha256"] != static["sha256"]:
        raise ValueError("capture DLL is outside the static recipe evidence")
    if sha(stages_data) != metadata["stage_trace_sha256"]:
        raise ValueError("stage trace hash mismatch")
    if not metadata["uninstrumented_output_equal"]:
        raise ValueError("instrumentation changed native output")
    verify_files(directory, metadata["artifact_sha256"])
    delta = (directory / "delta.pa30").read_bytes()
    reader = Reader(delta[12:])
    if delta[:4] == b"PA31":
        reader = Reader(reader.buffer())
    elif delta[:4] != b"PA30":
        raise ValueError("unexpected delta signature")
    file_type_set, file_type, flags = (reader.integer() for _ in range(3))
    source = (directory / "source.bin").read_bytes()
    nt = struct.unpack_from("<I", source, 0x3C)[0]
    machine = struct.unpack_from("<H", source, nt + 4)[0]
    optional = nt + 24
    magic = struct.unpack_from("<H", source, optional)[0]
    directories = optional + (96 if magic == 0x10B else 112)
    reloc_rva = struct.unpack_from("<I", source, directories + 5 * 8)[0]
    recipe_offset = {2: 0x69370, 8: 0x6AE40}.get(file_type)
    if recipe_offset is None:
        raise ValueError(f"uncaptured recipe family {file_type:#x}")
    recipe = next(row for row in static["recipes"] if row["file_offset"] == recipe_offset)
    expected = []
    for row in recipe["stages"]:
        if row["flag_mask"] & flags:
            name = NAMES[row["component"]]
            if row["component"] == "RiftTransformRelocationsI386" and reloc_rva == 0:
                name = "inferred-i386"
            expected.append(name)
    actual = []
    previous_leave = -1
    for row in stages["stages"]:
        verify_files(directory, row["artifact_sha256"])
        if not previous_leave < row["enter_order"] < row["leave_order"]:
            raise ValueError("selected stage events overlap or are unordered")
        previous_leave = row["leave_order"]
        actual.append(row["name"])
    return {
        "capture": str(directory), "stage_trace_sha256": sha(stages_data),
        "machine": machine, "file_type_set": file_type_set, "file_type": file_type,
        "flags": flags, "relocation_directory_rva": reloc_rva,
        "static_recipe_file_offset": recipe_offset, "expected_leaf_order": expected,
        "observed_leaf_order": actual, "exact_order_match": actual == expected,
        "machine_matches_file_type": machine == {2: 0x14C, 8: 0x8664}[file_type],
        "inferred_relocation_observed": "inferred-i386" in actual,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("static", type=Path)
    parser.add_argument("captures", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    static = json.loads(args.static.read_text())["dlls"]["msdelta"]
    captures = sorted(path.parent for path in args.captures.rglob("stages.json"))
    if not captures:
        raise ValueError("no completed stage captures")
    result = {
        "schema": 1, "evidence_kind": "observed-native-order-against-static-recipes",
        "static_evidence_sha256": sha(args.static.read_bytes()),
        "checker_sha256": sha(Path(__file__).read_bytes()),
        "bitstream_helper_sha256": sha((LAB / "pa31-header/make_probes.py").read_bytes()),
        "cases": [check(directory, static) for directory in captures],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
