"""Make bounded semantic PA31 header probes from a native-created control.

uv run --no-project lab/pa31-header/make_probes.py NATIVE_CONTROL OUTPUT
The no-op reserialization must equal the entire native delta byte for byte.
Payload bytes remain unchanged in every header mutation.
"""

import argparse
import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path


class Reader:
    def __init__(self, data: bytes) -> None:
        if not data:
            raise ValueError("empty bitstream")
        self.data = data
        self.position = 3
        self.limit = len(data) * 8 - (data[0] & 7)

    def bits(self, width: int) -> int:
        if width < 0 or self.position + width > self.limit:
            raise ValueError("truncated bitstream")
        value = 0
        for bit in range(width):
            position = self.position + bit
            value |= ((self.data[position // 8] >> (position % 8)) & 1) << bit
        self.position += width
        return value

    def integer(self) -> int:
        for nibbles in range(16):
            if self.bits(1):
                return self.bits((nibbles + 1) * 4)
        raise ValueError("invalid integer prefix")

    def buffer(self) -> bytes:
        length = self.integer()
        self.position = (self.position + 7) & ~7
        if length > (self.limit - self.position) // 8:
            raise ValueError("truncated buffer")
        start = self.position // 8
        self.position += length * 8
        return self.data[start : start + length]


class Writer:
    def __init__(self) -> None:
        self.output: list[int] = [0, 0, 0]

    def bits(self, value: int, width: int) -> None:
        self.output.extend((value >> bit) & 1 for bit in range(width))

    def integer(self, value: int) -> None:
        if not 0 <= value < 1 << 64:
            raise ValueError("probe integer outside uint64 domain")
        nibbles = max(1, (value.bit_length() + 3) // 4)
        self.bits(1 << (nibbles - 1), nibbles)
        self.bits(value, nibbles * 4)

    def buffer(self, value: bytes) -> None:
        self.integer(len(value))
        self.output.extend([0] * (-len(self.output) % 8))
        for byte in value:
            self.bits(byte, 8)

    def finish(self) -> bytes:
        padding = -len(self.output) % 8
        self.output.extend([0] * padding)
        self.output[:3] = [(padding >> bit) & 1 for bit in range(3)]
        return bytes(sum(self.output[index + bit] << bit for bit in range(8))
                     for index in range(0, len(self.output), 8))


@dataclass(frozen=True)
class Header:
    file_type_set: int
    file_type: int
    flags: int
    target_size: int
    hash_algorithm: int
    target_hash: bytes
    structure_size: int
    format_version: int
    minimum_client_version: int
    source_hash: bytes

    @classmethod
    def read(cls, data: bytes) -> "Header":
        reader = Reader(data)
        values = [reader.integer() for _ in range(5)]
        target_hash = reader.buffer()
        extras = [reader.integer() for _ in range(3)]
        source_hash = reader.buffer()
        if reader.position != reader.limit:
            raise ValueError("unexpected native header extension")
        return cls(*values, target_hash, *extras, source_hash)

    def encode(self) -> bytes:
        writer = Writer()
        for value in (self.file_type_set, self.file_type, self.flags, self.target_size, self.hash_algorithm):
            writer.integer(value)
        writer.buffer(self.target_hash)
        for value in (self.structure_size, self.format_version, self.minimum_client_version):
            writer.integer(value)
        writer.buffer(self.source_hash)
        return writer.finish()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = (args.control / "source.bin").read_bytes()
    target = (args.control / "target.bin").read_bytes()
    delta = (args.control / "delta.pa31").read_bytes()
    if delta[:4] != b"PA31":
        raise ValueError("control must be native PA31")
    outer = Reader(delta[12:])
    encoded_header = outer.buffer()
    header = Header.read(encoded_header)
    payload = [outer.bits(1) for _ in range(outer.limit - outer.position)]

    def encode(value: Header) -> bytes:
        writer = Writer()
        writer.buffer(value.encode())
        writer.output.extend(payload)
        return delta[:12] + writer.finish()

    if encode(header) != delta:
        raise ValueError("no-op reserialization differs from native delta")
    if header.source_hash != hashlib.sha256(source).digest():
        raise ValueError("native source hash is not the source SHA256")
    cases: list[tuple[str, Header, bytes, dict[str, str | int]]] = []

    def field_case(name: str, field: str, value: int) -> None:
        cases.append((name, replace(header, **{field: value}), source,
                      {"field": field, "before": getattr(header, field), "after": value}))

    for value in (0, 4, 8, 0x50, 0x89, 0x100000088):
        field_case(f"structure-size-{value:x}", "structure_size", value)
    for value in (0, 2, 0xFFFFFFFF, 0x100000001):
        field_case(f"format-version-{value:x}", "format_version", value)
    for value in (1, 2, 0xFFFFFFFF, 0x100000000, 0x100000001):
        field_case(f"minimum-version-{value:x}", "minimum_client_version", value)
    bad_hash = bytes([header.source_hash[0] ^ 1]) + header.source_hash[1:]
    cases += [
        ("source-hash-corrupt", replace(header, source_hash=bad_hash), source, {"field": "source_hash", "change": "flip first digest bit"}),
        ("source-hash-empty", replace(header, source_hash=b""), source, {"field": "source_hash", "change": "empty digest"}),
        ("source-hash-31", replace(header, source_hash=header.source_hash[:31]), source, {"field": "source_hash", "change": "31-byte digest"}),
        ("source-hash-33", replace(header, source_hash=header.source_hash + b"\0"), source, {"field": "source_hash", "change": "33-byte digest"}),
        ("target-hash-33", replace(header, target_hash=header.target_hash + b"\0"), source, {"field": "target_hash", "change": "33-byte digest"}),
    ]
    changed_source = bytes([source[0] ^ 1]) + source[1:]
    cases += [
        ("unused-source-byte", header, changed_source, {"field": "source[0]", "change": "flip byte absent from literal-only target"}),
        ("unused-source-byte-unchecked", replace(header, source_hash=b""), changed_source,
         {"parent": "unused-source-byte", "field": "source_hash", "change": "empty digest; target must remain exact"}),
    ]
    unchecked = replace(header, hash_algorithm=0, target_hash=b"", source_hash=b"")
    cases += [
        ("hash-disabled-control", unchecked, source, {"role": "control", "change": "disable algorithm and both signatures; preserve native payload"}),
        ("hash-zero-source-nonempty", replace(unchecked, source_hash=header.source_hash), source,
         {"parent": "hash-disabled-control", "field": "source_hash", "change": "restore only source digest"}),
    ]
    for name, changed_header, changed_input, mutation in cases:
        directory = args.output / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "source.bin").write_bytes(changed_input)
        (directory / "target.bin").write_bytes(target)
        (directory / "delta.pa31").write_bytes(encode(changed_header))
        description: dict[str, object] = {
            "native_control_sha256": hashlib.sha256(delta).hexdigest(),
            "payload_unchanged": True,
            "native_noop_roundtrip_exact": True,
            "mutation": mutation,
        }
        (directory / "probe.json").write_text(json.dumps(description, indent=2) + "\n")


if __name__ == "__main__":
    main()
