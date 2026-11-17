"""Build owned composed PE32 pairs with semantically named branch destinations."""
import argparse
import importlib.util
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, cast


class ImageFactory(Protocol):
    def __call__(self, *, wide: bool, target: bool, variant: str = 'normal') -> bytes: ...


@dataclass(frozen=True)
class Destination:
    name: str
    offset: int
    virtual_size: int
    in_headers_gap: bool = False


DESTINATIONS = (
    Destination('virtual-tail-file-alias', 0x1100, 0x2000),
    Destination('backed-executable', 0x100, 0x2000),
    Destination('raw-padding', 0x900, 0x800),
    Destination('virtual-tail-outside-file', 0x1F00, 0x2000),
    Destination('header-gap', 0x800, 0x2000, True),
)


def load_function(path: Path, name: str) -> object:
    spec = importlib.util.spec_from_file_location(path.parent.name.replace('-', '_') + '_inputs', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, name)


def build(destination: Destination, *, target: bool) -> tuple[bytes, list[dict[str, str | int]]]:
    lab = Path(__file__).resolve().parents[1]
    image = cast(ImageFactory, load_function(lab / 'relocations/make_inputs.py', 'image'))
    move = cast(Callable[[bytes, dict[bytes, int]], bytes], load_function(lab / 'pa30-copy/make_inputs.py', 'move_sections'))
    data = bytearray(image(wide=False, target=target))
    optional = 0x98
    directories = optional + 96
    section_headers = optional + 0xE0
    text_rva = 0x2000 if target else 0x1000
    data_rva = 0x4000 if target else 0x2000
    reloc_rva = data_rva + 0x2000
    data_raw = 0x400
    data[data_raw:data_raw + 0x1000] = bytes([0x90]) * 0x1000

    def dword(offset: int, value: int) -> None:
        struct.pack_into('<I', data, offset, value)

    for offset in (16, 20):
        dword(optional + offset, text_rva)
    dword(optional + 24, data_rva)
    dword(optional + 56, reloc_rva + 0x1000)
    dword(section_headers + 12, text_rva)
    dword(section_headers + 40 + 8, destination.virtual_size)
    dword(section_headers + 40 + 12, data_rva)
    dword(section_headers + 40 + 36, 0xE0000040)  # Executable data: branch destination ownership stays observable.
    dword(section_headers + 80 + 12, reloc_rva)
    dword(directories + 5 * 8, reloc_rva)
    dword(0x1400, data_rva)
    for location, pointee in ((0x20, 0x100), (0x28, 0x200), (0xFF0, 0x300), (0xFF8, 0x400)):
        dword(data_raw + location, 0x80000000 + data_rva + pointee)

    # A real import descriptor, lookup table, IAT and named import compose with
    # relocations and branch rewriting without overlapping branch destinations.
    descriptor, lookup, iat, dll_name, import_name = 0x500, 0x600, 0x640, 0x680, 0x6A0
    data[data_raw + descriptor:data_raw + 0x700] = bytes(0x200)
    dword(directories + 8, data_rva + descriptor)
    dword(directories + 12, 40)
    struct.pack_into('<IIIII', data, data_raw + descriptor, data_rva + lookup, 0, 0, data_rva + dll_name, data_rva + iat)
    dword(data_raw + lookup, data_rva + import_name)
    dword(data_raw + iat, data_rva + import_name)
    data[data_raw + dll_name:data_raw + dll_name + 12] = b'example.dll\0'
    data[data_raw + import_name:data_raw + import_name + 8] = b'\0\0Entry\0'
    data[0x200:0x400] = bytes([0x90]) * 0x200
    sites: list[dict[str, str | int]] = []
    branch_target = destination.offset if destination.in_headers_gap else data_rva + destination.offset
    for instruction, opcode, offset in (('call', b'\xE8', 0x20), ('jmp', b'\xE9', 0x40), ('jcc', b'\x0F\x85', 0x60)):
        length = len(opcode) + 4
        raw = 0x200 + offset
        data[raw:raw + len(opcode)] = opcode
        struct.pack_into('<i', data, raw + len(opcode), branch_target - (text_rva + offset + length))
        sites.append({'instruction': instruction, 'file_offset': raw, 'rva': text_rva + offset,
                      'length': length, 'destination_rva': branch_target,
                      'destination_kind': destination.name})
    # Raw gaps deliberately retain unowned bytes. A virtual-only .data address
    # can numerically alias this gap, but that does not make it file-backed.
    result = move(bytes(data), {b'.data': 0x600 if target else 0x400, b'.reloc': 0x1C00 if target else 0x1800})
    return result, sites


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    for destination in DESTINATIONS:
        directory = args.output / ('x86-' + destination.name)
        directory.mkdir(parents=True, exist_ok=False)
        metadata: dict[str, object] = {'schema': 1, 'destination': destination.name,
                                     'data_virtual_size': destination.virtual_size, 'data_raw_size': 0x1000}
        for target in (False, True):
            data, sites = build(destination, target=target)
            name = 'target' if target else 'source'
            (directory / ('target.bin' if target else 'base.bin')).write_bytes(data)
            metadata[name + '_branches'] = sites
        (directory / 'input.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
