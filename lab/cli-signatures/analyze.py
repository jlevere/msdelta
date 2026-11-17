"""Link native signature mutations to typed CLI owners and captured native maps.

Run with uv run --no-project --with dnfile==0.18.0.
"""
import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
import dnfile


@dataclass(frozen=True)
class Token:
    role: str
    element: str
    signature_offset: int
    width: int
    coded: int
    table_id: int
    rid: int


def compressed(data: bytes, position: int) -> tuple[int, int]:
    first = data[position]
    width = 1 if first < 0x80 else 2 if first < 0xC0 else 4 if first < 0xE0 else 0
    if not width or position + width > len(data):
        raise ValueError('invalid compressed integer')
    value = first & (0x7F if width == 1 else 0x3F if width == 2 else 0x1F)
    for byte in data[position + 1:position + width]:
        value = value * 256 + byte
    return value, width


def signature_tokens(data: bytes, kind: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0

    def number() -> int:
        nonlocal position
        value, width = compressed(data, position)
        position += width
        return value

    def type_signature(role: str) -> None:
        nonlocal position
        element = data[position]
        position += 1
        if element in (0x11, 0x12):
            start = position
            coded = number()
            tag = coded & 3
            if tag > 2:
                raise ValueError('invalid TypeDefOrRef tag')
            tokens.append(Token(role, 'VALUETYPE' if element == 0x11 else 'CLASS', start,
                                position - start, coded, (2, 1, 0x1B)[tag], coded >> 2))
        elif element == 0x15:
            type_signature(role + '.generic_outer')
            count = number()
            for index in range(count):
                type_signature(f'{role}.generic_argument[{index}]')
        elif element in (0x1D, 0x0F, 0x10):
            type_signature(role + {0x1D: '.array_element', 0x0F: '.pointer_target', 0x10: '.byref_target'}[element])
        elif element in (0x13, 0x1E):
            number()
        elif element not in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                             0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x16, 0x18, 0x19, 0x1C):
            raise ValueError(f'unexpected signature element {element:#x}')

    if kind == 'TypeSpec':
        type_signature('type')
    else:
        convention = data[position]
        position += 1
        if convention & 0x10:
            raise ValueError('generic method arity is outside this matrix')
        parameters = number()
        type_signature('return')
        for index in range(parameters):
            type_signature(f'parameter[{index}]')
    if position != len(data):
        raise ValueError('unparsed signature suffix')
    return tokens


def map_point(entries: list[tuple[int, int]], point: int) -> int:
    if not entries:
        return point
    selected = next((pair for pair in reversed(entries) if pair[0] <= point), entries[-1])
    return point + selected[1] - selected[0]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ('definition-moves', 'reference-moves', 'both-move'):
        directory = args.captures / name
        capture = json.loads((directory / 'capture.json').read_text())
        for file, digest in capture['artifact_sha256'].items():
            if sha((directory / file).read_bytes()) != digest:
                raise ValueError('capture artifact hash mismatch')
        stage_manifest = (directory / 'stages.json').read_bytes()
        if sha(stage_manifest) != capture['stage_trace_sha256']:
            raise ValueError('stage manifest hash mismatch')
        stages = json.loads(stage_manifest)
        stage = next(item for item in stages['stages'] if item['name'] == 'cli-metadata')
        prefix = f"stage-{stage['id']:02}-cli-metadata"
        before, after = ((directory / (prefix + suffix + '.bin')).read_bytes() for suffix in ('-before', '-after'))
        for suffix, data in (('-before', before), ('-after', after)):
            if sha(data) != stage['artifact_sha256'][prefix + suffix + '.bin']:
                raise ValueError('metadata stage digest mismatch')
        native_maps = json.loads((directory / 'cli-maps.json').read_text())
        if not native_maps['unchanged_on_return'] or native_maps['dll_sha256'] != capture['dll_sha256'] or native_maps['harness_sha256'] != capture['harness_sha256']:
            raise ValueError('native CliMap producer/immutability mismatch')
        if len(native_maps['artifact_sha256']) != 68:
            raise ValueError('incomplete native CliMap')
        maps: dict[int, list[tuple[int, int]]] = {}
        for file, digest in native_maps['artifact_sha256'].items():
            data = (directory / file).read_bytes()
            if sha(data) != digest or len(data) % 16:
                raise ValueError('native CliMap artifact mismatch')
            if file.startswith('cli-map-table-'):
                maps[int(file.removeprefix('cli-map-table-').removesuffix('.bin'), 16)] = list(struct.iter_unpack('<qq', data))
        source = dnfile.dnPE(data=before)
        target = dnfile.dnPE(str(directory / 'target.bin'))
        if source.net is None or target.net is None:
            raise ValueError('missing CLI metadata')
        owners: dict[int, list[str]] = {}
        for table_name, table_id in (('TypeSpec', 0x1B), ('MethodDef', 6), ('MemberRef', 0x0A)):
            table = getattr(source.net.mdtables, table_name)
            for rid, row in enumerate(table.rows, 1):
                owners.setdefault(row.struct.Signature_BlobIndex, []).append(f'{table_name}:{rid}')
        records: list[dict[str, object]] = []
        for table_name, table_id in (('TypeSpec', 0x1B), ('MethodDef', 6), ('MemberRef', 0x0A)):
            table = getattr(source.net.mdtables, table_name)
            target_table = getattr(target.net.mdtables, table_name)
            for rid, row in enumerate(table.rows, 1):
                blob = row.Signature
                heap_offset = row.struct.Signature_BlobIndex
                blob_file_offset = source.get_offset_from_rva(blob.rva)
                length, prefix_width = compressed(before, blob_file_offset)
                signature_offset = blob_file_offset + prefix_width
                original = before[signature_offset:signature_offset + length]
                changed = after[signature_offset:signature_offset + length]
                if original != blob.value:
                    raise ValueError('typed blob extent disagrees with decoded heap item')
                target_rid = map_point(maps[table_id], rid)
                target_row = target_table.rows[target_rid - 1]
                observations: list[dict[str, object]] = []
                for token in signature_tokens(original, table_name):
                    value, width = compressed(changed, token.signature_offset)
                    if width != token.width:
                        raise ValueError('width change outside this initial matrix')
                    table2_prediction = (map_point(maps[2], token.rid) << 2) | (token.coded & 3)
                    tagged_prediction = (map_point(maps[token.table_id], token.rid) << 2) | (token.coded & 3)
                    metadata_table = getattr(source.net.mdtables, {1: 'TypeRef', 2: 'TypeDef', 0x1B: 'TypeSpec'}[token.table_id])
                    referenced = metadata_table.rows[token.rid - 1]
                    referenced_name = '.'.join(filter(None, (str(getattr(referenced, 'TypeNamespace', '')), str(getattr(referenced, 'TypeName', '')))))
                    observations.append(dict(asdict(token), referenced_name=referenced_name,
                        native_after_coded=value, table2_prediction=table2_prediction,
                        tag_selected_prediction=tagged_prediction))
                records.append({'table': table_name, 'table_id': table_id, 'rid': rid,
                    'name': str(getattr(row, 'Name', '')), 'source_heap_offset': heap_offset,
                    'signature_file_offset': signature_offset, 'signature_size': length,
                    'source_signature_hex': original.hex(), 'native_after_signature_hex': changed.hex(),
                    'target_rid': target_rid, 'target_name': str(getattr(target_row, 'Name', '')),
                    'target_heap_offset': target_row.struct.Signature_BlobIndex,
                    'target_signature_hex': target_row.Signature.value.hex(),
                    'heap_owners': owners[heap_offset], 'tokens': observations})
        result = {'schema': 1, 'case': name, 'capture_sha256': sha((directory / 'capture.json').read_bytes()),
            'cli_maps_sha256': sha((directory / 'cli-maps.json').read_bytes()),
            'native_type_ref_map': maps[1], 'native_type_def_map': maps[2],
            'native_type_spec_map': maps[0x1B], 'records': records}
        (args.output / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
