"""Generate owned PA30 pairs separating virtual layout from file layout.

Run with uv run --no-project lab/pa30-copy/make_inputs.py OUTPUT_DIRECTORY.
The shared relocation generator supplies complete PE headers and operands.
This generator moves raw sections independently while preserving their contents.
"""

import argparse
import importlib.util
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast


class ImageFactory(Protocol):
    def __call__(
        self, *, wide: bool, target: bool, variant: str = "normal"
    ) -> bytes: ...


def image_factory() -> ImageFactory:
    source = Path(__file__).resolve().parents[1] / "relocations" / "make_inputs.py"
    specification = importlib.util.spec_from_file_location("relocation_inputs", source)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {source}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return cast(ImageFactory, module.image)


@dataclass(frozen=True)
class RawSection:
    name: bytes
    header: int
    offset: int
    size: int


def move_sections(image: bytes, offsets: dict[bytes, int]) -> bytes:
    nt = struct.unpack_from("<I", image, 0x3C)[0]
    section_count = struct.unpack_from("<H", image, nt + 6)[0]
    optional_size = struct.unpack_from("<H", image, nt + 20)[0]
    optional_header = nt + 24
    header_size = struct.unpack_from("<I", image, optional_header + 60)[0]
    sections: list[RawSection] = []
    for index in range(section_count):
        header = optional_header + optional_size + index * 40
        name = image[header : header + 8].rstrip(b"\0")
        size, offset = struct.unpack_from("<II", image, header + 16)
        sections.append(RawSection(name, header, offset, size))
    new_size = max(
        offsets.get(section.name, section.offset) + section.size for section in sections
    )
    result = bytearray([0xCC]) * new_size
    result[:header_size] = image[:header_size]
    occupied: list[range] = [range(header_size)]
    for section in sections:
        offset = offsets.get(section.name, section.offset)
        extent = range(offset, offset + section.size)
        if any(
            extent.start < used.stop and used.start < extent.stop for used in occupied
        ):
            raise ValueError(f"overlapping synthetic section {section.name!r}")
        occupied.append(extent)
        result[extent.start : extent.stop] = image[
            section.offset : section.offset + section.size
        ]
        struct.pack_into("<I", result, section.header + 20, offset)
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    make_image = image_factory()
    for wide in (False, True):
        for preserve_rva in (False, True):
            case = ("x64" if wide else "x86") + (
                "-rva-preserved" if preserve_rva else "-rva-moved"
            )
            source = make_image(wide=wide, target=False)
            target = make_image(wide=wide, target=not preserve_rva)
            # The target's raw sections move by different amounts, introducing
            # gaps. No RVA or pointer is inferred from those raw-file shifts.
            target = move_sections(target, {b".data": 0x600, b".reloc": 0x1800})
            directory = args.output / case
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "base.bin").write_bytes(source)
            (directory / "target.bin").write_bytes(target)


if __name__ == "__main__":
    main()
