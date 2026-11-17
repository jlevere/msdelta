"""Derive bounded reverse-integrity probes from native GetReverse controls.

uv run --no-project lab/pa31-reverse/mutate_reverse.py CONTROLS OUTPUT
Only PA31 header fields or one specified reference byte change. The complete
reverse payload is preserved; no assumption about its internal section count
or layout is used by this mutator.
"""

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

# Reuse the previously verified bitstream adapter without modifying its source.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pa31-header"))
from make_probes import Header, Reader, Writer  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("controls", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    for kind in ("literal", "copy"):
        control = args.controls / ("native-" + kind)
        reference = (control / "source.bin").read_bytes()
        original = (control / "target.bin").read_bytes()
        delta = (control / "delta.pa31").read_bytes()
        if delta[:4] != b"PA31":
            raise ValueError("native reverse control is not PA31")
        outer = Reader(delta[12:])
        header = Header.read(outer.buffer())
        if header.file_type_set & 0x100 == 0:
            raise ValueError("native reverse control lacks the reverse flag")
        if header.source_hash != hashlib.sha256(reference).digest():
            raise ValueError("reverse source hash does not describe its reference")
        if header.target_hash != hashlib.sha256(original).digest():
            raise ValueError("reverse target hash does not describe original output")
        payload = [outer.bits(1) for _ in range(outer.limit - outer.position)]

        def encode(changed: Header) -> bytes:
            writer = Writer()
            writer.buffer(changed.encode())
            writer.output.extend(payload)
            return delta[:12] + writer.finish()

        if encode(header) != delta:
            raise ValueError("native reverse no-op serialization is not byte-exact")
        bad_source_hash = bytes([header.source_hash[0] ^ 1]) + header.source_hash[1:]
        bad_target_hash = bytes([header.target_hash[0] ^ 1]) + header.target_hash[1:]
        changed_reference = bytes([reference[0] ^ 1]) + reference[1:]
        cases: list[tuple[str, Header, bytes, dict[str, str | int]]] = [
            (f"{kind}-source-hash-corrupt", replace(header, source_hash=bad_source_hash), reference,
             {"field": "source_hash", "change": "flip first digest bit"}),
            (f"{kind}-reference-byte", header, changed_reference,
             {"field": "reference[0]", "offset": 0, "change": "flip first reference byte"}),
        ]
        if kind == "literal":
            cases += [
                ("literal-source-hash-empty", replace(header, source_hash=b""), reference,
                 {"field": "source_hash", "change": "empty digest"}),
                ("literal-source-hash-31", replace(header, source_hash=header.source_hash[:31]), reference,
                 {"field": "source_hash", "change": "31-byte digest"}),
                ("literal-source-hash-33", replace(header, source_hash=header.source_hash + b"\0"), reference,
                 {"field": "source_hash", "change": "33-byte digest"}),
                ("literal-target-hash-corrupt", replace(header, target_hash=bad_target_hash), reference,
                 {"field": "target_hash", "change": "flip first digest bit"}),
            ]
        else:
            # The identity reverse control's copy record covers reference byte
            # zero; native replay tests verify that structural precondition.
            cases.append(("copy-reference-byte-target-hash-empty", replace(header, target_hash=b""), changed_reference,
                          {"parent": "copy-reference-byte", "field": "target_hash", "change": "empty output digest"}))
        for name, changed_header, changed_input, mutation in cases:
            directory = args.output / name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "source.bin").write_bytes(changed_input)
            (directory / "target.bin").write_bytes(original)
            (directory / "delta.pa31").write_bytes(encode(changed_header))
            description: dict[str, object] = {
                "control": control.name,
                "native_control_sha256": hashlib.sha256(delta).hexdigest(),
                "payload_unchanged": True,
                "native_noop_roundtrip_exact": True,
                "mutation": mutation,
            }
            (directory / "probe.json").write_text(json.dumps(description, indent=2) + "\n")


if __name__ == "__main__":
    main()
