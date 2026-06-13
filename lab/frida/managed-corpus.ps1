param(
    [string]$OutDir = (Join-Path (Get-Location) "managed-corpus"),
    [string]$CscPath = "",
    [UInt64]$Seed = 12648430
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Find-Csc([string]$Requested) {
    if ($Requested) {
        if (Test-Path -LiteralPath $Requested) { return (Resolve-Path -LiteralPath $Requested).Path }
        throw "csc.exe not found at $Requested"
    }

    $candidates = @(
        (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
    }

    throw "Could not find .NET Framework csc.exe"
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Write-Bytes([string]$Path, [byte[]]$Bytes) {
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Sha256File([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Compile-Case(
    [string]$Compiler,
    [string]$Id,
    [string]$Variant,
    [string]$Platform,
    [string]$SourcePath,
    [string]$OutPath,
    [string[]]$Resources
) {
    $args = @(
        "/nologo",
        "/target:library",
        "/debug-",
        "/optimize+",
        "/platform:$Platform",
        "/out:$OutPath"
    )
    foreach ($resource in $Resources) {
        $args += "/resource:$resource"
    }
    $args += $SourcePath

    & $Compiler @args
    if ($LASTEXITCODE -ne 0) {
        throw "csc.exe failed for $Id $Variant with exit code $LASTEXITCODE"
    }
}

function New-CorpusCase(
    [string]$Compiler,
    [string]$Root,
    [string]$Id,
    [string]$Intent,
    [string]$Platform,
    [string]$SourceCode,
    [string]$TargetCode,
    [hashtable]$SourceResources = @{},
    [hashtable]$TargetResources = @{}
) {
    $inputDir = Join-Path $Root "inputs"
    $sourceCs = Join-Path $inputDir "$Id.source.cs"
    $targetCs = Join-Path $inputDir "$Id.target.cs"
    $sourceDll = Join-Path $inputDir "$Id.source.dll"
    $targetDll = Join-Path $inputDir "$Id.target.dll"

    Write-Utf8NoBom $sourceCs $SourceCode
    Write-Utf8NoBom $targetCs $TargetCode

    $sourceResourceArgs = @()
    foreach ($name in $SourceResources.Keys) {
        $path = Join-Path $inputDir "$Id.source.$name"
        Write-Bytes $path ([byte[]]$SourceResources[$name])
        $sourceResourceArgs += "$path,ManagedFixture.$name"
    }

    $targetResourceArgs = @()
    foreach ($name in $TargetResources.Keys) {
        $path = Join-Path $inputDir "$Id.target.$name"
        Write-Bytes $path ([byte[]]$TargetResources[$name])
        $targetResourceArgs += "$path,ManagedFixture.$name"
    }

    Compile-Case $Compiler $Id "source" $Platform $sourceCs $sourceDll $sourceResourceArgs
    Compile-Case $Compiler $Id "target" $Platform $targetCs $targetDll $targetResourceArgs

    $sourceRel = "inputs/$Id.source.dll"
    $targetRel = "inputs/$Id.target.dll"
    $sourceInfo = Get-Item -LiteralPath $sourceDll
    $targetInfo = Get-Item -LiteralPath $targetDll

    return [ordered]@{
        job = [ordered]@{
            id = $Id
            category = "managed-cli/$Intent"
            reference = $sourceRel
            target = $targetRel
            ours_delta = "empty.ours.delta"
            target_sha256 = Sha256File $targetDll
            target_len = [UInt64]$targetInfo.Length
            reference_sha256 = Sha256File $sourceDll
            reverse_delta = $null
            native = [ordered]@{
                file_type_set = 15
                set_flags = 0
                reset_flags = 0
                hash_alg = 0
            }
            directions = @("native_to_ours", "native_to_native")
        }
        manifest = [ordered]@{
            id = $Id
            intent = $Intent
            platform = $Platform
            source = [ordered]@{
                path = $sourceRel
                len = [UInt64]$sourceInfo.Length
                sha256 = Sha256File $sourceDll
            }
            target = [ordered]@{
                path = $targetRel
                len = [UInt64]$targetInfo.Length
                sha256 = Sha256File $targetDll
            }
        }
    }
}

$compiler = Find-Csc $CscPath
$root = [System.IO.Path]::GetFullPath($OutDir)
if (Test-Path -LiteralPath $root) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
New-Item -ItemType Directory -Force $root | Out-Null
New-Item -ItemType Directory -Force (Join-Path $root "inputs") | Out-Null
Write-Bytes (Join-Path $root "empty.ours.delta") ([byte[]]@())

$cases = @()
$manifestCases = @()

$source = @"
using System;

namespace ManagedFixture {
    public sealed class Entry {
        public string Message() {
            return "source-alpha";
        }

        public int Value() {
            return Message().Length + 7;
        }
    }
}
"@
$target = @"
using System;

namespace ManagedFixture {
    public sealed class Entry {
        public string Message() {
            return "target-beta-with-longer-text";
        }

        public int Value() {
            return Message().Length + 11;
        }
    }
}
"@
$case = New-CorpusCase $compiler $root "cli-const-string" "user-string-and-method-body" "anycpu" $source $target
$cases += $case.job
$manifestCases += $case.manifest

$source = @"
namespace ManagedFixture {
    public sealed class Calculator {
        public int Compute(int a, int b) {
            return Helper(a) + b;
        }

        private static int Helper(int value) {
            return value + 3;
        }
    }
}
"@
$target = @"
namespace ManagedFixture {
    public sealed class Calculator {
        public int Compute(int a, int b) {
            return Added(Helper(a), b);
        }

        private static int Helper(int value) {
            return value + 5;
        }

        private static int Added(int left, int right) {
            return (left * 2) + right;
        }
    }
}
"@
$case = New-CorpusCase $compiler $root "cli-add-method" "metadata-row-growth" "anycpu" $source $target
$cases += $case.job
$manifestCases += $case.manifest

$source = @"
using System;

namespace ManagedFixture {
    public sealed class Box<T> {
        private readonly T value;

        public Box(T value) {
            this.value = value;
        }

        public T Identity(T input) {
            return input;
        }

        public T Value {
            get { return value; }
        }
    }

    public static class UseBox {
        public static string Join(Box<string> box, string suffix) {
            return box.Value + suffix;
        }
    }
}
"@
$target = @"
using System;
using System.Collections.Generic;

namespace ManagedFixture {
    public sealed class Box<T> {
        private readonly T value;

        public Box(T value) {
            this.value = value;
        }

        public U Convert<U>(Func<T, U> map) {
            return map(value);
        }

        public T Value {
            get { return value; }
        }
    }

    public static class UseBox {
        public static Dictionary<string, List<int>> Make(Box<string> box) {
            return new Dictionary<string, List<int>> {
                { box.Value, new List<int> { 1, 2, 3 } }
            };
        }
    }
}
"@
$case = New-CorpusCase $compiler $root "cli-generics-signature" "signature-blob-and-memberref" "anycpu" $source $target
$cases += $case.job
$manifestCases += $case.manifest

$source = @"
using System;

namespace ManagedFixture {
    [AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
    public sealed class MarkerAttribute : Attribute {
        public MarkerAttribute(string name) {
            Name = name;
        }

        public string Name { get; private set; }
        public int Version;
    }

    [Marker("source", Version = 1)]
    public sealed class Annotated {
        [Marker("source-method", Version = 2)]
        public void Run() {
        }
    }
}
"@
$target = @"
using System;

namespace ManagedFixture {
    [AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
    public sealed class MarkerAttribute : Attribute {
        public MarkerAttribute(string name) {
            Name = name;
        }

        public string Name { get; private set; }
        public int Version;
    }

    [Marker("target", Version = 3)]
    [Marker("second", Version = 4)]
    public sealed class Annotated {
        [Marker("target-method", Version = 5)]
        public void Run() {
        }
    }
}
"@
$case = New-CorpusCase $compiler $root "cli-custom-attribute" "custom-attribute-table-and-blob" "anycpu" $source $target
$cases += $case.job
$manifestCases += $case.manifest

$source = @"
using System.Reflection;

namespace ManagedFixture {
    public sealed class Resources {
        public string[] Names() {
            return Assembly.GetExecutingAssembly().GetManifestResourceNames();
        }
    }
}
"@
$target = @"
using System.Reflection;

namespace ManagedFixture {
    public sealed class Resources {
        public string[] Names() {
            string[] names = Assembly.GetExecutingAssembly().GetManifestResourceNames();
            System.Array.Sort(names);
            return names;
        }
    }
}
"@
$sourcePayload = [System.Text.Encoding]::UTF8.GetBytes("source resource payload`n")
$targetPayload = [System.Text.Encoding]::UTF8.GetBytes("target resource payload with extra bytes`n")
$case = New-CorpusCase $compiler $root "cli-resource" "manifest-resource-and-method-body" "anycpu" $source $target @{ "payload.bin" = $sourcePayload } @{ "payload.bin" = $targetPayload }
$cases += $case.job
$manifestCases += $case.manifest

$source = @"
using System;

namespace ManagedFixture {
    public sealed class PlatformCase {
        public long PointerScaled(long value) {
            return value + IntPtr.Size;
        }
    }
}
"@
$target = @"
using System;

namespace ManagedFixture {
    public sealed class PlatformCase {
        public long PointerScaled(long value) {
            return (value * 2) + IntPtr.Size;
        }
    }
}
"@
$case = New-CorpusCase $compiler $root "cli-platform-x64" "amd64-managed-pe" "x64" $source $target
$cases += $case.job
$manifestCases += $case.manifest

$job = [ordered]@{
    schema_version = 1
    domain = "msdelta"
    seed = $Seed
    cases = $cases
}
$job | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root "job.json") -Encoding utf8

$manifest = [ordered]@{
    schema = 1
    corpus = "managed-cli-small"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    compiler = $compiler
    seed = $Seed
    cases = $manifestCases
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root "manifest.json") -Encoding utf8

Write-Host ("managed corpus: {0} cases -> {1}" -f $cases.Count, $root)
