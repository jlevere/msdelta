"""Owned RAW PA30 controls for the flag-selected native E8 postprocessor."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parents[1]
DLL_SHA256 = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
HARNESS_SHA256 = "06f385c4039c5f014f1262b4780934e4fc52ed9d45dc328a65a59161754a4871"
sys.path.insert(0, str(LAB / "pa31-header"))
from make_probes import Reader, Writer  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def owned_cases() -> dict[str, bytes]:
    cases: dict[str, bytes] = {}
    for remaining in (4, 5, 6, 9, 10, 11):
        data = bytearray(b"Z" * 128)
        site = len(data) - remaining
        data[site] = 0xE8
        if remaining >= 5:
            struct.pack_into("<i", data, site + 1, -site + 1)
        cases[f"raw-tail-{remaining}"] = bytes(data)
    data = bytearray(b"Z" * 512)
    # The operand contains another E8. It must be skipped with the other four
    # operand bytes, even though interpreting it as an opcode would be in range.
    data[16:21] = b"\xe8\xe8\0\0\0"
    cases["raw-embedded-opcode"] = bytes(data)
    for name, value in (("lower-bound", -16), ("below-bound", -17),
                        ("upper-bound", 128), ("zero", 0)):
        data = bytearray(b"Z" * 128)
        data[16] = 0xE8
        struct.pack_into("<i", data, 17, value)
        cases[f"raw-{name}"] = bytes(data)
    return cases


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    for name, target in owned_cases().items():
        directory = output / name
        directory.mkdir()
        (directory / "source.bin").write_bytes(b"Q" * len(target))
        (directory / "target.bin").write_bytes(target)


def adapt(captures: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    for name in owned_cases():
        capture = captures / name
        delta = (capture / "delta.pa30").read_bytes()
        if delta[:4] != b"PA30":
            raise ValueError("expected native PA30")
        reader = Reader(delta[12:])
        fields = [reader.integer() for _ in range(5)]
        signature = reader.buffer()
        payload = [reader.bits(1) for _ in range(reader.limit - reader.position)]

        def encode(values: list[int], digest: bytes) -> bytes:
            writer = Writer()
            for value in values:
                writer.integer(value)
            writer.buffer(digest)
            writer.output.extend(payload)
            return delta[:12] + writer.finish()

        if encode(fields, signature) != delta:
            raise ValueError("native no-op roundtrip was not exact")
        if fields[1] != 1 or fields[2] != 0:
            raise ValueError(f"expected RAW flag-zero native control, got {fields}")
        directory = output / name
        directory.mkdir()
        (directory / "source.bin").write_bytes((capture / "source.bin").read_bytes())
        observations: list[dict[str, Any]] = []
        for flag in (0, 1):
            changed = fields.copy()
            changed[2], changed[4] = flag, 0
            altered = encode(changed, b"")
            check = Reader(altered[12:])
            if [check.integer() for _ in range(5)] != changed or check.buffer():
                raise ValueError("altered header mismatch")
            if [check.bits(1) for _ in range(check.limit - check.position)] != payload:
                raise ValueError("altered payload differs")
            filename = f"flag-{flag}.pa30"
            (directory / filename).write_bytes(altered)
            observations.append({"file": filename, "flags": flag, "sha256": sha(altered)})
        metadata = {"schema": 1, "original_delta_sha256": sha(delta),
                    "native_header_fields": fields, "native_noop_roundtrip_exact": True,
                    "payload_bits_unchanged": True,
                    "adaptation": "flags=0 or 1; hash_algorithm=0; target_hash=empty",
                    "generator_sha256": sha(Path(__file__).read_bytes()),
                    "helper_sha256": sha((LAB / "pa31-header/make_probes.py").read_bytes()),
                    "variants": observations}
        (directory / "input.json").write_text(json.dumps(metadata, indent=2) + "\n")


def capture_metadata(directory: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = json.loads((directory / "capture.json").read_text())
    if metadata["dll_sha256"] != DLL_SHA256 or metadata["harness_sha256"] != HARNESS_SHA256:
        raise ValueError("unexpected capture producer")
    if not metadata["uninstrumented_output_equal"] or not metadata["decompress_source_unchanged"]:
        raise ValueError("native instrumentation invariants failed")
    for filename, digest in metadata["artifact_sha256"].items():
        if sha((directory / filename).read_bytes()) != digest:
            raise ValueError(f"capture hash mismatch: {directory / filename}")
    if sha((directory / "stages.json").read_bytes()) != metadata["stage_trace_sha256"]:
        raise ValueError("stage trace hash mismatch")
    return metadata


def collect(controls: Path, probes: Path, variants: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    cases: list[dict[str, Any]] = []
    for name, owned_target in owned_cases().items():
        control = controls / name
        control_metadata = capture_metadata(control)
        if (control / "target.bin").read_bytes() != owned_target:
            raise ValueError("native create/apply control differs from owned target")
        directory = output / name
        directory.mkdir()
        artifacts = {"source.bin": (control / "source.bin").read_bytes(),
                     "original.pa30": (control / "delta.pa30").read_bytes(),
                     "decompressed.bin": (control / "decompressed-target.bin").read_bytes()}
        if artifacts["decompressed.bin"] != owned_target:
            raise ValueError("flag-zero RAW control unexpectedly postprocessed")
        observations: list[dict[str, Any]] = []
        for flag in (0, 1):
            capture = probes / name / f"flag-{flag}"
            metadata = capture_metadata(capture)
            delta = (capture / "delta.pa30").read_bytes()
            if delta != (variants / name / f"flag-{flag}.pa30").read_bytes():
                raise ValueError("probe delta differs from adapted input")
            if (capture / "source.bin").read_bytes() != artifacts["source.bin"]:
                raise ValueError("probe source differs from native control")
            if (capture / "decompressed-target.bin").read_bytes() != artifacts["decompressed.bin"]:
                raise ValueError("flag mutation changed decompressed payload")
            target = (capture / "target.bin").read_bytes()
            if flag == 0 and target != owned_target:
                raise ValueError("hash-disabled flag-zero control changed output")
            artifacts[f"flag-{flag}.pa30"] = delta
            artifacts[f"target-flag-{flag}.bin"] = target
            observations.append({"flags": flag, "native_capture": metadata,
                                 "changed_offsets": [i for i, (a, b) in enumerate(zip(owned_target, target, strict=True)) if a != b]})
        for filename, data in artifacts.items():
            (directory / filename).write_bytes(data)
        entry = {"id": name, "source_size": len(artifacts["source.bin"]),
                 "target_size": len(owned_target), "control_capture": control_metadata,
                 "header_adaptation": json.loads((variants / name / "input.json").read_text()),
                 "observations": observations,
                 "artifact_sha256": {filename: sha(data) for filename, data in artifacts.items()}}
        cases.append(entry)
    provenance = {"schema": 1, "evidence": "native whole ApplyDeltaB postprocessing after identical captured RAW decompression",
                  "dll_sha256": DLL_SHA256, "harness_sha256": HARNESS_SHA256,
                  "source_sha256": {str(path.relative_to(LAB.parent)): sha(path.read_bytes()) for path in
                                    (Path(__file__), LAB / "pe-pipeline/postprocess.ps1", LAB / "pe-pipeline/capture.c", LAB / "pa31-header/make_probes.py")},
                  "cases": cases}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate")
    create.add_argument("output", type=Path)
    modify = commands.add_parser("adapt")
    modify.add_argument("captures", type=Path)
    modify.add_argument("output", type=Path)
    package = commands.add_parser("collect")
    for name in ("controls", "probes", "variants", "output"):
        package.add_argument(name, type=Path)
    args = parser.parse_args()
    if args.command == "generate":
        generate(args.output)
    elif args.command == "adapt":
        adapt(args.captures, args.output)
    else:
        collect(args.controls, args.probes, args.variants, args.output)


if __name__ == "__main__":
    main()
