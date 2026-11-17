"""Normalize compiler-generated identity fields, preserving all assembly structure.

Run with uv run --no-project --with dnfile==0.18.0.
"""
import argparse
import hashlib
import json
from pathlib import Path
import dnfile


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiled', type=Path)
    parser.add_argument('sources', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for case in ('definition-moves', 'reference-moves', 'both-move'):
        directory = args.output / case
        directory.mkdir()
        metadata: dict[str, object] = {'schema': 1, 'case': case, 'dnfile_version': '0.18.0'}
        for variant in ('source', 'target'):
            original = (args.compiled / case / variant / 'ControlledSignatures.dll').read_bytes()
            source = (args.sources / case / (variant + '.cs')).read_bytes()
            pe = dnfile.dnPE(data=original)
            if pe.net is None or pe.net.mdtables is None or pe.net.mdtables.Module is None:
                raise ValueError('expected CLI Module table')
            module = pe.net.mdtables.Module.rows[0]
            guid_offset = pe.get_offset_from_rva(module.Mvid.rva)
            timestamp_offset = pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp')
            checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
            edits: list[tuple[int, bytes, str]] = [
                (guid_offset, hashlib.sha256(source).digest()[:16], 'Module.Mvid derived from source SHA256'),
                (timestamp_offset, bytes(4), 'COFF.TimeDateStamp'),
                (checksum_offset, bytes(4), 'OptionalHeader.CheckSum'),
            ]
            result = bytearray(original)
            for offset, value, _ in edits:
                result[offset:offset + len(value)] = value
            artifact = bytes(result)
            (directory / ('base.bin' if variant == 'source' else 'target.bin')).write_bytes(artifact)
            (directory / (variant + '.cs')).write_bytes(source)
            metadata[variant] = {'compiler_output_sha256': sha(original), 'normalized_sha256': sha(artifact),
                'source_sha256': sha(source), 'normalization': [{'field': field, 'offset': offset,
                'before_hex': original[offset:offset + len(value)].hex(), 'after_hex': value.hex()}
                for offset, value, field in edits]}
        (directory / 'input.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
