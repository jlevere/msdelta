"""Build one owned AMD64 relayout with RIP operands, unwind records and relocations."""
import argparse
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Callable, Protocol, cast


class ImageFactory(Protocol):
    def __call__(self, *, wide: bool, target: bool, variant: str = 'normal') -> bytes: ...


def load_function(path: Path, name: str) -> object:
    spec = importlib.util.spec_from_file_location(path.parent.name.replace('-', '_') + '_x64_inputs', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, name)


def build(*, target: bool) -> tuple[bytes, dict[str, object]]:
    lab = Path(__file__).resolve().parents[1]
    image = cast(ImageFactory, load_function(lab / 'relocations/make_inputs.py', 'image'))
    move = cast(Callable[[bytes, dict[bytes, int]], bytes], load_function(lab / 'pa30-copy/make_inputs.py', 'move_sections'))
    data = bytearray(image(wide=True, target=target))
    optional, section_table = 0x98, 0x188
    text_rva, data_rva = (0x2000, 0x5000) if target else (0x1000, 0x3000)
    reloc_rva, pdata_rva = data_rva + 0x1000, data_rva + 0x2000
    image_base = 0x240000000 if target else 0x140000000
    data_raw, reloc_raw, pdata_raw = (0x800, 0x1C00, 0x2000) if target else (0x600, 0x1600, 0x1800)

    def dword(offset: int, value: int) -> None:
        struct.pack_into('<I', data, offset, value)

    dword(optional + 60, 0x400)
    # Move the three existing sections before adding a fourth section header;
    # the larger header range no longer overlaps the relocated .text bytes.
    data = bytearray(move(bytes(data), {b'.text': 0x400, b'.data': data_raw, b'.reloc': reloc_raw}))
    data.extend(bytes(pdata_raw + 0x200 - len(data)))
    struct.pack_into('<H', data, 0x86, 4)
    dword(optional + 16, text_rva + 0x20)
    dword(optional + 20, text_rva)
    dword(optional + 8, 0x1400)
    dword(optional + 56, pdata_rva + 0x1000)
    dword(section_table + 12, text_rva)
    dword(section_table + 40 + 12, data_rva)
    dword(section_table + 80 + 12, reloc_rva)
    pdata_header = section_table + 120
    data[pdata_header:pdata_header + 40] = bytes(40)
    data[pdata_header:pdata_header + 8] = b'.pdata\0\0'
    struct.pack_into('<IIII', data, pdata_header + 8, 12, pdata_rva, 0x200, pdata_raw)
    dword(pdata_header + 36, 0x40000040)
    directories = optional + 112
    struct.pack_into('<II', data, directories + 3 * 8, pdata_rva, 12)
    dword(directories + 5 * 8, reloc_rva)
    dword(reloc_raw, data_rva)
    data[data_raw:data_raw + 0x1000] = bytes([0x90]) * 0x1000
    for location, pointee in ((0x20, 0x100), (0x28, 0x200), (0xFF0, 0x300), (0xFF8, 0x400)):
        struct.pack_into('<Q', data, data_raw + location, image_base + data_rva + pointee)
    data[0x400:0x600] = bytes([0x90]) * 0x200
    instructions: list[dict[str, int | str]] = []
    for name, prefix, offset, pointee in [('load', b'\x48\x8b\x05', 0x20, 0x100), ('address', b'\x48\x8d\x0d', 0x27, 0x200)]:
        raw = 0x400 + offset
        data[raw:raw + 3] = prefix
        struct.pack_into('<i', data, raw + 3, data_rva + pointee - (text_rva + offset + 7))
        instructions.append({'name': name, 'rva': text_rva + offset, 'file_offset': raw,
                             'length': 7, 'operand_file_offset': raw + 3, 'destination_rva': data_rva + pointee})
    data[0x42E] = 0xC3
    data[0x500] = 0xC3  # Named exception handler is another owned executable byte.
    unwind_rva, unwind_raw = data_rva + 0x300, data_raw + 0x300
    data[unwind_raw:unwind_raw + 4] = bytes([9, 0, 0, 0])  # version1, EHANDLER, zero unwind codes
    dword(unwind_raw + 4, text_rva + 0x100)
    struct.pack_into('<III', data, pdata_raw, text_rva + 0x20, text_rva + 0x2F, unwind_rva)
    semantics: dict[str, object] = {'text_rva': text_rva, 'data_rva': data_rva, 'image_base': image_base,
        'rip_instructions': instructions, 'runtime_function_file_offset': pdata_raw,
        'runtime_function': {'begin': text_rva + 0x20, 'end': text_rva + 0x2F, 'unwind': unwind_rva},
        'unwind_header_file_offset': unwind_raw, 'handler_slot_file_offset': unwind_raw + 4,
        'handler_rva': text_rva + 0x100, 'relocation_operand_file_offsets': [data_raw + offset for offset in (0x20, 0x28, 0xFF0, 0xFF8)]}
    return bytes(data), semantics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    directory = args.output / 'x64-rip-unwind-relocations'
    directory.mkdir(parents=True, exist_ok=False)
    metadata: dict[str, object] = {'schema': 1}
    for target in (False, True):
        data, semantics = build(target=target)
        (directory / ('target.bin' if target else 'base.bin')).write_bytes(data)
        metadata['target' if target else 'source'] = semantics
    (directory / 'input.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
