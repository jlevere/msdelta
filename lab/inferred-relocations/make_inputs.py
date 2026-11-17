"""Owned PE32 inference controls: section pointers, structural words and scan edges."""
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
    spec = importlib.util.spec_from_file_location(path.parent.name.replace('-', '_') + '_inferred_inputs', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, name)


def image(*, target: bool, tail_remaining: int) -> tuple[bytes, list[dict[str, str | int]]]:
    lab = Path(__file__).resolve().parents[1]
    make_image = cast(ImageFactory, load_function(lab / 'relocations/make_inputs.py', 'image'))
    move = cast(Callable[[bytes, dict[bytes, int]], bytes], load_function(lab / 'pa30-copy/make_inputs.py', 'move_sections'))
    data = bytearray(make_image(wide=False, target=target))
    optional, directories = 0x98, 0xF8
    data_rva = 0x3000 if target else 0x2000
    base = 0x90000000 if target else 0x80000000
    data_raw, tail_raw = (0x600, 0x1C00) if target else (0x400, 0x1800)
    struct.pack_into('<I', data, optional + 28, base)
    struct.pack_into('<II', data, directories + 5 * 8, 0, 0)
    # No relocation directory: the final section is ordinary inert data.
    section = optional + 0xE0 + 80
    data[section:section + 8] = b'.tail\0\0\0'
    data[0x200:0x400] = bytes([0x90]) * 0x200
    data[0x400:0x1400] = bytes([0x90]) * 0x1000
    data[0x1400:0x1600] = bytes([0x90]) * 0x200
    data = bytearray(move(bytes(data), {b'.data': data_raw, b'.tail': tail_raw}))
    # A valid PE32 load-config extent owns bit-patterns which are scalar fields,
    # even when their numeric values resemble addresses in this image.
    load_config = data_raw + 0x500
    data[load_config:load_config + 64] = bytes(64)
    struct.pack_into('<II', data, directories + 10 * 8, data_rva + 0x500, 64)
    struct.pack_into('<I', data, load_config, 64)
    sites: list[dict[str, str | int]] = []

    def word(name: str, offset: int, value: int, category: str) -> None:
        struct.pack_into('<I', data, offset, value)
        sites.append({'name': name, 'file_offset': offset, 'value': value, 'category': category})

    word('header-pointer-pattern', 0x50, 0x80002100, 'before-scan')
    word('header-last-word', 0x1FC, 0x80002100, 'before-scan')
    word('first-scanned-word', 0x200, base + data_rva + 0x100, 'code-pointer')
    data[0x220] = 0xB8  # MOV EAX,imm32; its immediate is unaligned.
    word('unaligned-code-immediate', 0x221, base + data_rva + 0x200, 'code-pointer')
    word('nonexec-data-pointer', data_raw + 0x20, base + data_rva + 0x100, 'data-pointer')
    word('unaligned-data-pointer', data_raw + 0x29, base + data_rva + 0x200, 'data-pointer')
    word('header-rva-pointee', data_raw + 0x40, base + 1, 'header-target')
    word('virtual-only-pointee', data_raw + 0x48, base + data_rva + 0x1800, 'unbacked-image-target')
    word('equal-image-base', data_raw + 0x80, 0x80000000, 'exclusive-lower-bound')
    word('equal-image-end', data_raw + 0x88, 0x80004000, 'exclusive-upper-bound')
    word('below-image-base', data_raw + 0x90, 0x7FFFFFFF, 'outside-image')
    word('above-image-end', data_raw + 0x98, 0x80004001, 'outside-image')
    word('structural-timestamp-pattern', load_config + 4, 0x80002100, 'structural-owned')
    word('raw-gap-pointer', data_raw + 0x1100, base + data_rva + 0x100, 'outside-sections')
    word('scan-tail-boundary', len(data) - tail_remaining, base + data_rva + 0x100, f'end-minus-{tail_remaining}')
    return bytes(data), sites


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    for remaining in (4, 5):
        directory = args.output / f'x86-tail-{remaining}'
        directory.mkdir(parents=True, exist_ok=False)
        metadata: dict[str, object] = {'schema': 1, 'relocation_directory': {'rva': 0, 'size': 0},
                                     'tail_remaining': remaining, 'source_image_base': 0x80000000,
                                     'target_image_base': 0x90000000, 'source_size_of_image': 0x4000,
                                     'target_size_of_image': 0x5000, 'size_of_headers': 0x200}
        for target in (False, True):
            data, sites = image(target=target, tail_remaining=remaining)
            (directory / ('target.bin' if target else 'base.bin')).write_bytes(data)
            metadata['target_sites' if target else 'source_sites'] = sites
        (directory / 'input.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
