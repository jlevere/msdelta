"""Owned assemblies separating generic outer-type and argument table movements."""
import argparse
import json
from pathlib import Path


def source(*, move_definitions: bool, move_references: bool) -> str:
    pads = '\n'.join(f'public sealed class StableType{i:02} {{ }}' for i in range(10))
    inserted = 'public sealed class InsertedA { }\npublic sealed class InsertedB { }' if move_definitions else ''
    reference_prefix = 'public static System.Version AddedReference(System.Version value) { return value; }' if move_references else ''
    return f'''using System;
using System.Collections.Generic;
namespace ControlledSignatures {{
{inserted}
{pads}
public sealed class LocalBox<T> {{ public T Value; }}
public sealed class LocalArg {{ public int Value; }}
public static class Probe {{
    {reference_prefix}
    public static LocalArg PlainDefinition(LocalArg value) {{ return value; }}
    public static Uri PlainReference(Uri value) {{ return value; }}
    public static List<LocalArg> GenericReturnThenPlain(Uri following) {{ return null; }}
    public static LocalArg GenericParameterThenPlain(List<LocalArg> generic, Uri following) {{ return null; }}
    public static LocalBox<Uri> InternalGenericThenPlain(LocalArg following) {{ return null; }}
    public static Type ExternalSpecification() {{ return typeof(List<LocalArg>); }}
    public static Type InternalSpecification() {{ return typeof(LocalBox<Uri>); }}
    public static Type PlainDefinitionArraySpecification() {{ return typeof(LocalArg[]); }}
    public static Type PlainReferenceArraySpecification() {{ return typeof(Uri[]); }}
    public static void FinalMethod() {{ }}
}}
}}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, definitions, references in [('definition-moves', True, False), ('reference-moves', False, True), ('both-move', True, True)]:
        directory = args.output / name
        directory.mkdir()
        (directory / 'source.cs').write_text(source(move_definitions=False, move_references=False))
        (directory / 'target.cs').write_text(source(move_definitions=definitions, move_references=references))
        (directory / 'recipe.json').write_text(json.dumps({'schema': 1, 'case': name,
            'intended_definition_insertion': 2 if definitions else 0,
            'intended_reference_insertion': 'System.Version' if references else None,
            'require_observed_native_map_movement': True}, indent=2) + '\n')


if __name__ == '__main__':
    main()
