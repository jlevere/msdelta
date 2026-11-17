"""Create owned x86 load-config/lock-prefix oracle inputs from the synthetic PE.

Run with uv run --no-project lab/pa30-lock/make_inputs.py OUTPUT_DIRECTORY.
"""

import argparse
import struct
from pathlib import Path


def image(variant: str, *, target: bool) -> bytes:
    fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/atoms/RelocationsNative/x86/base.bin"
    data = bytearray(fixture.read_bytes())

    def dword(offset: int, value: int) -> None:
        struct.pack_into("<I", data, offset, value)

    image_base = 0x80000000
    optional = 0x98
    directories = optional + 96
    config = 0x500
    config_rva = 0x2100
    table = 0x13FC if variant == "raw-boundary" else 0x600
    table_rva = 0x2000 + table - 0x400
    dword(0x88, 2 if target else 1)
    dword(directories + 10 * 8, config_rva)
    dword(directories + 10 * 8 + 4, 0x40 if variant != "short-directory" else 0x3F)
    data[config:config + 0x40] = bytes(0x40)
    dword(config, 0x40)
    dword(config + 0x20, image_base + table_rva if variant != "absent-table" else 0)
    # Deliberately include a non-executable section byte, a header byte,
    # an unmapped address, a duplicate, and an entry after the terminator.
    locations = (0x1010,) if variant == "raw-boundary" else (
        0x1010, 0x1018, 0x2300, 0x100, 0x6000, 0x1010, 0, 0x1020)
    for index, rva in enumerate(locations):
        dword(table + index * 4, image_base + rva if rva else 0)
    for offset in (0x210, 0x218, 0x220, 0x700):
        data[offset] = 0x90
    if target and variant in ("mixed-targets", "raw-boundary", "raw-after-virtual"):
        for offset in ((0x210,) if variant == "raw-boundary" else (0x210, 0x218, 0x700)):
            data[offset] = 0xF0
    if variant == "raw-after-virtual":
        # Legal raw padding makes the native file-section eligibility check
        # distinguish file offsets from the virtual section end.
        data = data[:0x200] + bytearray(0x1E00) + data[0x200:]
        for index in range(3):
            pointer = optional + 0xE0 + index * 40 + 20
            dword(pointer, struct.unpack_from("<I", data, pointer)[0] + 0x1E00)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    for variant in ("mixed-targets", "raw-boundary", "absent-table", "short-directory", "raw-after-virtual"):
        case = args.output / variant
        case.mkdir(parents=True, exist_ok=True)
        for target in (False, True):
            (case / ("target.bin" if target else "base.bin")).write_bytes(image(variant, target=target))


if __name__ == "__main__":
    main()
