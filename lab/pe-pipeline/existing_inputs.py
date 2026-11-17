"""Stage unchanged owned managed and x64 fixtures for the native pipeline capture."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path


CASES: dict[str, tuple[str, ...]] = {
    'ManagedNativeCorpus': ('cli-interface-impl', 'cli-constructor-token-boundary',
                           'cli-constructor-user-string-boundary', 'cli-static-constructor-token-boundary'),
    'Pa30CopyNative': ('x64-rva-moved', 'x64-rva-preserved'),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    for family, names in CASES.items():
        for name in names:
            original = root / 'tests/fixtures/atoms' / family / name
            directory = args.output / name
            directory.mkdir()
            extension = '.dll' if family == 'ManagedNativeCorpus' else '.bin'
            for old, new in [('source' + extension, 'source.bin'), ('target' + extension, 'target.bin'), ('delta.pa30', 'delta.pa30')]:
                shutil.copyfile(original / old, directory / new)
            provenance = original / ('case.toml' if family == 'ManagedNativeCorpus' else 'capture.json')
            metadata: dict[str, str | int] = {
                'schema': 1, 'original_fixture': str(original.relative_to(root)),
                'source_sha256': sha256(directory / 'source.bin'),
                'delta_sha256': sha256(directory / 'delta.pa30'),
                'expected_sha256': sha256(directory / 'target.bin'),
                'original_provenance_file': str(provenance.relative_to(root)),
                'original_provenance_sha256': sha256(provenance),
            }
            (directory / 'input.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
