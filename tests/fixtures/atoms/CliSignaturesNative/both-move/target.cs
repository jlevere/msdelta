using System;
using System.Collections.Generic;
namespace ControlledSignatures {
public sealed class InsertedA { }
public sealed class InsertedB { }
public sealed class StableType00 { }
public sealed class StableType01 { }
public sealed class StableType02 { }
public sealed class StableType03 { }
public sealed class StableType04 { }
public sealed class StableType05 { }
public sealed class StableType06 { }
public sealed class StableType07 { }
public sealed class StableType08 { }
public sealed class StableType09 { }
public sealed class LocalBox<T> { public T Value; }
public sealed class LocalArg { public int Value; }
public static class Probe {
    public static System.Version AddedReference(System.Version value) { return value; }
    public static LocalArg PlainDefinition(LocalArg value) { return value; }
    public static Uri PlainReference(Uri value) { return value; }
    public static List<LocalArg> GenericReturnThenPlain(Uri following) { return null; }
    public static LocalArg GenericParameterThenPlain(List<LocalArg> generic, Uri following) { return null; }
    public static LocalBox<Uri> InternalGenericThenPlain(LocalArg following) { return null; }
    public static Type ExternalSpecification() { return typeof(List<LocalArg>); }
    public static Type InternalSpecification() { return typeof(LocalBox<Uri>); }
    public static Type PlainDefinitionArraySpecification() { return typeof(LocalArg[]); }
    public static Type PlainReferenceArraySpecification() { return typeof(Uri[]); }
    public static void FinalMethod() { }
}
}
