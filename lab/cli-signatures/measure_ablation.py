"""Measure one native CLI metadata ablation and identify reusable signature ranges.

Run with uv run --no-project --with dnfile==0.18.0. Actual copy operations are
verified separately; equal ranges here are candidates, not copy-use claims.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
import dnfile


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ablation', type=Path)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    helper = Path(__file__).resolve().parents[1] / 'pa31-header/make_probes.py'
    spec = importlib.util.spec_from_file_location('ablation_codec', helper)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {helper}')
    codec = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = codec
    spec.loader.exec_module(codec)
    measured: dict[str, dict[str, object]] = {}
    fields: dict[str, list[int]] = {}
    buffers: dict[str, dict[str, bytes]] = {}
    for mode in ('normal', 'no-metadata'):
        directory = args.ablation / mode / 'capture'
        capture = json.loads((directory / 'capture.json').read_text())
        artifacts: dict[str, bytes] = {}
        for file, digest in capture['artifact_sha256'].items():
            artifacts[file] = (directory / file).read_bytes()
            if sha(artifacts[file]) != digest:
                raise ValueError('capture hash mismatch')
        if not capture['uninstrumented_output_equal'] or not capture['decompress_source_unchanged']:
            raise ValueError('native control failed')
        delta = artifacts['delta.pa30']
        reader = codec.Reader(delta[12:])
        fields[mode] = [reader.integer() for _ in range(5)]
        signature = reader.buffer()
        preprocess, patch = reader.buffer(), reader.buffer()
        buffers[mode] = artifacts
        measured[mode] = {'flags': fields[mode][2], 'delta_size': len(delta),
            'preprocess_size': len(preprocess), 'patch_size': len(patch),
            'target_signature_hex': signature.hex(), 'delta_sha256': sha(delta),
            'transformed_source_sha256': sha(artifacts['transformed-source.bin']),
            'native_creation': json.loads((args.ablation / mode / 'created/creation.json').read_text())}
    normal, disabled = fields['normal'], fields['no-metadata']
    if normal[2] ^ disabled[2] != 0x8000 or not normal[2] & 0x8000:
        raise ValueError('actual native flags differ beyond CLI metadata ablation')
    if normal[:2] + normal[3:] != disabled[:2] + disabled[3:]:
        raise ValueError('other native header fields changed')
    for file in ('source.bin', 'target.bin'):
        if buffers['normal'][file] != buffers['no-metadata'][file] or buffers['normal'][file] != (args.baseline / file).read_bytes():
            raise ValueError('ablation inputs or output differ from owned baseline')
    if buffers['normal']['delta.pa30'] != (args.baseline / 'delta.pa30').read_bytes():
        raise ValueError('normal native delta did not reproduce baseline')
    if measured['normal']['target_signature_hex'] != measured['no-metadata']['target_signature_hex']:
        raise ValueError('target signature differs')
    a, b = buffers['normal']['transformed-source.bin'], buffers['no-metadata']['transformed-source.bin']
    target = dnfile.dnPE(data=buffers['normal']['target.bin'])
    observations = json.loads((args.baseline / 'observations.json').read_text())
    candidates: list[dict[str, object]] = []
    for record in observations['records']:
        source_offset, length = record['signature_file_offset'], record['signature_size']
        row = getattr(target.net.mdtables, record['table']).rows[record['target_rid'] - 1]
        target_offset = target.get_offset_from_rva(row.Signature.rva) + len(row.Signature.__data__) - len(row.Signature.value)
        target_signature = row.Signature.value
        if a[source_offset:source_offset + length] == target_signature and b[source_offset:source_offset + length] != target_signature:
            candidates.append({'table': record['table'], 'rid': record['rid'], 'name': record['name'],
                'target_rid': record['target_rid'], 'source_file_offset': source_offset,
                'target_file_offset': target_offset, 'length': length,
                'signature_hex': target_signature.hex(), 'claim': 'equal reusable range; copy-use requires decoder trace'})
    output = {'schema': 1, 'only_changed_actual_header_flag': 0x8000,
        'normal_delta_reproduces_baseline': True, 'identical_source_and_target': True,
        'measurements': measured, 'transformed_source_different_bytes': sum(x != y for x, y in zip(a, b, strict=True)),
        'reusable_signature_candidates': candidates}
    args.output.write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    main()
