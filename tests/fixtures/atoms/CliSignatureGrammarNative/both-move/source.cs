using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
namespace ControlledSignatureGrammar {

public sealed class StableType00 {}
public sealed class StableType01 {}
public sealed class StableType02 {}
public sealed class StableType03 {}
public sealed class StableType04 {}
public sealed class StableType05 {}
public sealed class StableType06 {}
public sealed class StableType07 {}
public sealed class StableType08 {}
public sealed class StableType09 {}
public sealed class StableType10 {}
public sealed class StableType11 {}
public sealed class StableType12 {}
public sealed class StableType13 {}
public sealed class StableType14 {}
public sealed class StableType15 {}
public sealed class StableType16 {}
public sealed class StableType17 {}
public sealed class StableType18 {}
public sealed class StableType19 {}
public sealed class StableType20 {}
public sealed class StableType21 {}
public sealed class StableType22 {}
public sealed class StableType23 {}
public sealed class StableType24 {}
public sealed class StableType25 {}
public sealed class StableType26 {}
public sealed class StableType27 {}
public sealed class StableType28 {}
public sealed class StableType29 {}
public sealed class StableType30 {}
public sealed class StableType31 {}
public sealed class StableType32 {}
public sealed class StableType33 {}
public sealed class StableType34 {}
public sealed class StableType35 {}
public sealed class StableType36 {}
public sealed class StableType37 {}
public sealed class StableType38 {}
public sealed class StableType39 {}
public sealed class StableType40 {}
public sealed class StableType41 {}
public sealed class StableType42 {}
public sealed class StableType43 {}
public sealed class StableType44 {}
public sealed class LocalArg {}
public sealed class Probe {
    
    public static LocalArg SeedReferenceRows(System.Exception value0, System.ArgumentException value1, System.ArgumentNullException value2, System.ArgumentOutOfRangeException value3, System.ArithmeticException value4, System.ArrayTypeMismatchException value5, System.DivideByZeroException value6, System.FormatException value7, System.IndexOutOfRangeException value8, System.InvalidCastException value9, System.InvalidOperationException value10, System.NotImplementedException value11, System.NotSupportedException value12, System.NullReferenceException value13, System.ObjectDisposedException value14, System.OverflowException value15, System.RankException value16, System.StackOverflowException value17, System.TimeoutException value18, System.TypeInitializationException value19, System.TypeLoadException value20, System.AccessViolationException value21, System.AppDomainUnloadedException value22, System.BadImageFormatException value23, System.CannotUnloadAppDomainException value24, System.DataMisalignedException value25, System.DllNotFoundException value26, System.EntryPointNotFoundException value27, System.FieldAccessException value28, System.InsufficientMemoryException value29, System.InvalidProgramException value30, System.MemberAccessException value31, System.MethodAccessException value32, System.MissingFieldException value33, System.MissingMemberException value34, System.MissingMethodException value35, System.MulticastNotSupportedException value36, System.OutOfMemoryException value37, System.PlatformNotSupportedException value38, System.SystemException value39) { return null; }
    public Probe(LocalArg local, Uri external) {}
    public static void StaticVoid(LocalArg local, Uri external) {}
    public static LocalArg StaticClass(LocalArg local, Uri external) { return local; }
    public static int StaticPrimitive(LocalArg local, Uri external) { return 0; }
    public void InstanceVoid(LocalArg local, Uri external) {}
    public LocalArg InstanceClass(LocalArg local, Uri external) { return local; }
    public static LocalArg GenericArityOne(List<LocalArg> first, Uri second, LocalArg third) { return null; }
    public static LocalArg GenericArityTwo(Dictionary<LocalArg,Uri> first, Uri second, LocalArg third) { return null; }
    public static void CallVoidReferences(ILGenerator il, OpCode code, Type type, MethodInfo method, Type[] arguments) {
        il.Emit(code); il.Emit(code,type); il.EmitCall(code,method,arguments);
    }
    public static Type CallNonVoidReference() { return typeof(LocalArg); }
    public static Type ArityTwoSpecification() { return typeof(Dictionary<LocalArg,Uri>); }
    public static void FinalMethod() {}
}
}
