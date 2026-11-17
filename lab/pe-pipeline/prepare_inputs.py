"""Prepare explicitly hash-adapted PA30 inputs; preserve native payload exactly."""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selection', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    helper = Path(__file__).resolve().parents[1] / 'pa31-header/make_probes.py'
    spec = importlib.util.spec_from_file_location('header_codec', helper)
    assert spec and spec.loader
    codec = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = codec
    spec.loader.exec_module(codec)
    for case in json.loads(args.selection.read_text()):
        delta = Path(case['delta']).read_bytes()
        if delta[:4] != b'PA30':
            raise ValueError('only PA30 inputs supported')
        reader = codec.Reader(delta[12:])
        fields = [reader.integer() for _ in range(5)]
        target_hash = reader.buffer()
        payload = [reader.bits(1) for _ in range(reader.limit - reader.position)]

        def encode(values: list[int], signature: bytes) -> bytes:
            writer = codec.Writer()
            for value in values:
                writer.integer(value)
            writer.buffer(signature)
            writer.output.extend(payload)
            return delta[:12] + writer.finish()

        if encode(fields, target_hash) != delta:
            raise ValueError('native no-op roundtrip differs')
        if fields[4] != 0x800c or target_hash.hex() != case['expected_sha256']:
            raise ValueError('expected embedded SHA256 must match corpus manifest')
        changed = fields.copy()
        changed[4] = 0
        adapted = encode(changed, b'')
        check = codec.Reader(adapted[12:])
        assert [check.integer() for _ in range(5)] == changed
        assert check.buffer() == b''
        assert [check.bits(1) for _ in range(check.limit-check.position)] == payload
        directory = args.output / case['id']
        directory.mkdir(parents=True, exist_ok=False)
        source = Path(case['source']).read_bytes()
        (directory / 'source.bin').write_bytes(source)
        (directory / 'original.delta').write_bytes(delta)
        (directory / 'adapted.delta').write_bytes(adapted)
        metadata = dict(case, original_sha256=digest(delta), adapted_sha256=digest(adapted),
                        source_sha256=digest(source), payload_bits_unchanged=True,
                        native_noop_roundtrip_exact=True, adaptation='hash_algorithm=0,target_hash=empty',
                        helper_sha256=digest(helper.read_bytes()), generator_sha256=digest(Path(__file__).read_bytes()))
        (directory / 'input.json').write_text(json.dumps(metadata, indent=2)+'\n')


if __name__ == '__main__':
    main()
