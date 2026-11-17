"""One owned import-by-name record terminated beyond its section's raw extent."""
import argparse
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Protocol, cast


class Builder(Protocol):
    def __call__(self, destination: object, *, target: bool) -> tuple[bytes, list[dict[str, str | int]]]: ...


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    helper = Path(__file__).with_name('make_inputs.py')
    spec = importlib.util.spec_from_file_location('composed_import_inputs', helper)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {helper}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    build = cast(Builder, module.build)
    destination = next(item for item in module.DESTINATIONS if item.name == 'backed-executable')
    case = args.output / 'x86-import-name-beyond-section'
    case.mkdir(parents=True, exist_ok=False)
    semantics: dict[str, object] = {'schema': 1, 'case': case.name,
        'expected_name_resolution': 'unterminated within raw section; external NUL is not part of name'}
    for target in (False, True):
        original, branches = build(destination, target=target)
        data = bytearray(original)
        raw, rva = (0x600, 0x4000) if target else (0x400, 0x2000)
        name_offset = 0xFFC
        for thunk in (0x600, 0x640):
            struct.pack_into('<I', data, raw + thunk, rva + name_offset)
        data[raw + name_offset:raw + 0x1000] = b'\0\0AB'
        data[raw + 0x1000] = 0
        (case / ('target.bin' if target else 'base.bin')).write_bytes(data)
        semantics['target' if target else 'source'] = {
            'branches': branches, 'import_name_rva': rva + name_offset,
            'hint_file_offset': raw + name_offset, 'raw_section_end': raw + 0x1000,
            'first_nul_after_hint': raw + 0x1000,
            'ilt_file_offset': raw + 0x600, 'iat_file_offset': raw + 0x640,
        }
    (case / 'input.json').write_text(json.dumps(semantics, indent=2) + '\n')


if __name__ == '__main__':
    main()
