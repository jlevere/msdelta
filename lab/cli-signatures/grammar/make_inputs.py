"""Owned signatures distinguishing VOID cursor behavior and generic arity consumption."""
import argparse
import json
from pathlib import Path

REFERENCES: tuple[str, ...] = (
    'Exception', 'ArgumentException', 'ArgumentNullException', 'ArgumentOutOfRangeException',
    'ArithmeticException', 'ArrayTypeMismatchException', 'DivideByZeroException', 'FormatException',
    'IndexOutOfRangeException', 'InvalidCastException', 'InvalidOperationException',
    'NotImplementedException', 'NotSupportedException', 'NullReferenceException',
    'ObjectDisposedException', 'OverflowException', 'RankException', 'StackOverflowException',
    'TimeoutException', 'TypeInitializationException', 'TypeLoadException', 'AccessViolationException',
    'AppDomainUnloadedException', 'BadImageFormatException', 'CannotUnloadAppDomainException',
    'DataMisalignedException', 'DllNotFoundException', 'EntryPointNotFoundException',
    'FieldAccessException', 'InsufficientMemoryException', 'InvalidProgramException',
    'MemberAccessException', 'MethodAccessException', 'MissingFieldException',
    'MissingMemberException', 'MissingMethodException', 'MulticastNotSupportedException',
    'OutOfMemoryException', 'PlatformNotSupportedException', 'SystemException',
)


def source(*, definitions: bool, references: bool) -> str:
    inserted = 'public sealed class InsertedA {}\npublic sealed class InsertedB {}' if definitions else ''
    pads = '\n'.join(f'public sealed class StableType{i:02} {{}}' for i in range(45))
    parameters = ', '.join(f'System.{name} value{i}' for i, name in enumerate(REFERENCES))
    ref_prefix = 'public static Version AddedReference(Version value) {return value;}' if references else ''
    return f'''using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
namespace ControlledSignatureGrammar {{
{inserted}
{pads}
public sealed class LocalArg {{}}
public sealed class Probe {{
    {ref_prefix}
    public static LocalArg SeedReferenceRows({parameters}) {{ return null; }}
    public Probe(LocalArg local, Uri external) {{}}
    public static void StaticVoid(LocalArg local, Uri external) {{}}
    public static LocalArg StaticClass(LocalArg local, Uri external) {{ return local; }}
    public static int StaticPrimitive(LocalArg local, Uri external) {{ return 0; }}
    public void InstanceVoid(LocalArg local, Uri external) {{}}
    public LocalArg InstanceClass(LocalArg local, Uri external) {{ return local; }}
    public static LocalArg GenericArityOne(List<LocalArg> first, Uri second, LocalArg third) {{ return null; }}
    public static LocalArg GenericArityTwo(Dictionary<LocalArg,Uri> first, Uri second, LocalArg third) {{ return null; }}
    public static void CallVoidReferences(ILGenerator il, OpCode code, Type type, MethodInfo method, Type[] arguments) {{
        il.Emit(code); il.Emit(code,type); il.EmitCall(code,method,arguments);
    }}
    public static Type CallNonVoidReference() {{ return typeof(LocalArg); }}
    public static Type ArityTwoSpecification() {{ return typeof(Dictionary<LocalArg,Uri>); }}
    public static void FinalMethod() {{}}
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
        (directory / 'source.cs').write_text(source(definitions=False, references=False))
        (directory / 'target.cs').write_text(source(definitions=definitions, references=references))
        (directory / 'recipe.json').write_text(json.dumps({'schema': 1, 'case': name,
            'local_padding_types': 45, 'external_reference_parameters': list(REFERENCES),
            'require_native_map_and_token_width_observation': True,
            'discriminators': ['static/instance VOID versus CLASS return with identical parameters',
                'primitive non-VOID return control', 'MemberRef VOID with two-byte OpCode and Type tokens',
                'generic arity one versus two with three declared method parameters']}, indent=2) + '\n')


if __name__ == '__main__':
    main()
