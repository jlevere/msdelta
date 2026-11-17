"""Generate owned PE inputs whose data section moves by one page.

Run with uv run --no-project lab/relocations/make_inputs.py OUTPUT_DIRECTORY.
Native CreateDeltaB, not this generator, supplies deltas and expected stages.
"""

import argparse
import struct
from pathlib import Path


def image(*, wide: bool, target: bool, variant: str = "normal") -> bytes:
    data_size = 0x1000
    reloc = 0x400 + data_size
    data = bytearray(reloc + 0x200)

    def word(offset: int, value: int) -> None:
        struct.pack_into("<H", data, offset, value)

    def dword(offset: int, value: int) -> None:
        struct.pack_into("<I", data, offset, value)

    def qword(offset: int, value: int) -> None:
        struct.pack_into("<Q", data, offset, value)

    data[:2] = b"MZ"
    dword(0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    word(0x84, 0x8664 if wide else 0x14C)
    word(0x86, 3)
    dword(0x88, 2 if target else 1)
    optional_size = 0xF0 if wide else 0xE0
    word(0x94, optional_size)
    word(0x96, 0x2022 if wide else 0x2102)
    optional = 0x98
    word(optional, 0x20B if wide else 0x10B)
    dword(optional + 4, 0x200)
    dword(optional + 8, data_size + 0x200)
    dword(optional + 16, 0x1000)
    dword(optional + 20, 0x1000)
    data_rva = 0x3000 if target else 0x2000
    if target and variant in ("regroup", "regroup-tight"):
        data_rva += 0x100
    image_base = (0x240000000 if target else 0x140000000) if wide else 0x80000000
    if wide:
        qword(optional + 24, image_base)
    else:
        dword(optional + 24, data_rva)
        dword(optional + 28, image_base)
    dword(optional + 32, 0x1000)
    dword(optional + 36, 0x200)
    word(optional + 40, 6)
    word(optional + 48, 6)
    dword(optional + 56, data_rva + data_size + 0x1000)
    dword(optional + 60, 0x200)
    word(optional + 68, 3)
    word(optional + 70, 0x140)
    if wide:
        for offset, value in (
            (72, 0x100000),
            (80, 0x1000),
            (88, 0x100000),
            (96, 0x1000),
        ):
            qword(optional + offset, value)
    else:
        for offset, value in (
            (72, 0x100000),
            (76, 0x1000),
            (80, 0x100000),
            (84, 0x1000),
        ):
            dword(optional + offset, value)
    directories = optional + (112 if wide else 96)
    dword(directories - 4, 16)
    dword(directories + 5 * 8, data_rva + data_size)
    dword(directories + 5 * 8 + 4, 16)
    sections = (
        (b".text", 0x1000, 0x200, 0x200, 0x60000020),
        (b".data", data_rva, data_size, 0x400, 0xC0000040),
        (b".reloc", data_rva + data_size, 0x200, reloc, 0x42000040),
    )
    for index, (name, rva, size, raw, flags) in enumerate(sections):
        if variant in ("executable", "short-operand-executable"):
            flags |= 0x20000000
        if variant in ("renamed", "regroup-tight") and name == b".reloc":
            name = b".fixups"
        elif variant == "name-suffix" and name == b".reloc":
            name = b".reloc\0X"
        elif variant == "name-spaces" and name == b".reloc":
            name = b".RELOC  "
        header = optional + optional_size + index * 40
        data[header : header + len(name)] = name
        dword(header + 8, size)
        dword(header + 12, rva)
        dword(header + 16, size)
        dword(header + 20, raw)
        dword(header + 36, flags)
    data[0x200:0x203] = b"\x31\xc0\xc3"
    # Distinct payload makes the section correspondence observable to native create.
    for index in range(0x1000):
        data[0x400 + index] = (
            0x90
            if variant in ("executable", "short-operand-executable")
            else (index * 73 + (index >> 5) * 19) & 0xFF
        )
    operands = ((0x20, 0x100), (0x28, 0x200), (0xFF0, 0x300), (0xFF8, 0x400))
    records: dict[int, list[int]] = {}
    for index, (location, pointee) in enumerate(operands):
        value = image_base + data_rva + pointee
        if variant == "external" and index == 0:
            value += 0x10000000000
        if wide:
            qword(0x400 + location, value)
        else:
            dword(0x400 + location, value)
        records.setdefault((data_rva + location) & ~0xFFF, []).append(
            ((10 if wide else 3) << 12) | ((data_rva + location) & 0xFFF)
        )
    block = reloc
    for page, entries in records.items():
        if len(entries) % 2:
            entries.append(0)
        block_size = 8 + 2 * len(entries)
        dword(block, page)
        dword(block + 4, block_size)
        for index, entry in enumerate(entries):
            word(block + 8 + 2 * index, entry)
        block += block_size
    dword(directories + 5 * 8 + 4, block - reloc)
    if variant == "mixed":
        entries = [0x1020, 0x2028, 0x4030, 0xABCD, 0x7038, 0x3FF0]
        for index, entry in enumerate(entries):
            word(0x1408 + index * 2, entry)
        dword(0x1404, 8 + 2 * len(entries))
        dword(directories + 5 * 8 + 4, 8 + 2 * len(entries))
    elif variant == "missing-highadj":
        word(0x1408, 0x4020)
        dword(0x1404, 10)
        dword(directories + 5 * 8 + 4, 10)
    elif variant == "padding":
        word(0x140A, 0)
    elif variant == "unmapped-page":
        dword(0x1400, 0xFFFFF000)
    elif variant in ("short-operand", "short-operand-executable"):
        dword(0x1400, data_rva + 0x1000)
        word(0x1408, 0x31FF)
        word(0x140A, 0)
    elif variant == "short-block":
        dword(0x1404, 6)
    elif variant == "oversized-block":
        dword(0x1404, 0x1000)
    elif variant == "duplicate":
        word(0x140A, 0x1020)
    elif variant == "raw-directory":
        dword(directories + 5 * 8, 0x1400)
    elif variant == "header-page":
        dword(0x1400, 0x40)
        word(0x1408, 0x3010)
        word(0x140A, 0)
        dword(0x50, image_base + data_rva + 0x100)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cases = [(False, "normal"), (True, "normal"), (True, "external")]
    cases += [
        (False, variant)
        for variant in (
            "mixed",
            "missing-highadj",
            "padding",
            "unmapped-page",
            "short-operand",
            "short-block",
            "oversized-block",
            "duplicate",
            "renamed",
            "raw-directory",
            "header-page",
            "name-suffix",
            "name-spaces",
            "regroup",
            "regroup-tight",
            "executable",
            "short-operand-executable",
        )
    ]
    for wide, variant in cases:
        name = "x64" if wide else "x86"
        if variant != "normal":
            name += "-" + variant
        case = args.output / name
        case.mkdir(parents=True, exist_ok=True)
        for target in (False, True):
            (case / ("target.bin" if target else "base.bin")).write_bytes(
                image(wide=wide, target=target, variant=variant)
            )


if __name__ == "__main__":
    main()
