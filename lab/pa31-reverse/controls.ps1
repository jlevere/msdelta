param(
    [Parameter(Mandatory = $true)][string]$OracleExe,
    [Parameter(Mandatory = $true)][string]$Dll,
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$oracle = (Resolve-Path -LiteralPath $OracleExe).Path
$library = (Resolve-Path -LiteralPath $Dll).Path
if (Test-Path -LiteralPath $Output) { throw 'Choose a fresh output directory.' }
$sourceHashes = [ordered]@{}
foreach ($name in @('oracle.c', 'mutate_reverse.py', 'controls.ps1', '../pa31-header/make_probes.py', '../pa31-header/probe.ps1')) {
    $sourceHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$root = (New-Item -ItemType Directory -Path $Output).FullName
$inputs = (New-Item -ItemType Directory -Path (Join-Path $root '_inputs')).FullName
try {
    $literalOriginal = Join-Path $inputs 'literal-original.bin'
    $literalNew = Join-Path $inputs 'literal-new.bin'
    $copyOriginal = Join-Path $inputs 'copy-original.bin'
    $copyNew = Join-Path $inputs 'copy-new.bin'
    [IO.File]::WriteAllBytes($literalOriginal, [Text.Encoding]::ASCII.GetBytes('C' * 1024))
    [IO.File]::WriteAllBytes($literalNew, [Text.Encoding]::ASCII.GetBytes('D' * 256))
    $copy = [byte[]]::new(4096)
    for ($index = 0; $index -lt $copy.Length; $index++) {
        $copy[$index] = ($index * 73 + ($index -shr 4) * 19) -band 255
    }
    [IO.File]::WriteAllBytes($copyOriginal, $copy)
    [IO.File]::WriteAllBytes($copyNew, $copy)
    $cases = @(
        @{ Name = 'native-literal'; Original = $literalOriginal; New = $literalNew },
        @{ Name = 'native-copy'; Original = $copyOriginal; New = $copyNew }
    )
    foreach ($case in $cases) {
        $destination = (New-Item -ItemType Directory -Path (Join-Path $root $case.Name)).FullName
        & $oracle create-reverse $library $case.Original $case.New $destination
        if ($LASTEXITCODE -ne 0) { throw "Oracle execution failed for $($case.Name)" }
        $observation = Get-Content -LiteralPath (Join-Path $destination 'observation.json') -Raw | ConvertFrom-Json
        if ($observation.native_reverse_created -ne $true -or $observation.target_equal -ne $true) {
            throw "Native reverse control failed for $($case.Name)"
        }
    }
    $provenance = [ordered]@{
        schema = 1
        dll_sha256 = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
        dll_file_version = (Get-Item -LiteralPath $library).VersionInfo.FileVersion
        oracle_sha256 = (Get-FileHash -LiteralPath $oracle -Algorithm SHA256).Hash.ToLowerInvariant()
        source_sha256 = $sourceHashes
        input_design = 'Literal control C1024->D256; copy control is an identical deterministic 4096-byte pair.'
        reverse_api = 'ApplyDeltaGetReverseB(flags, original, forward_delta, source_filetime, new_out, reverse_delta_out)'
        source_filetime = 0
        next_stage = 'Run mutate_reverse.py on these controls, then ../pa31-header/probe.ps1 with this reverse oracle.'
    }
    $provenance | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'provenance.json') -Encoding utf8
} finally {
    Remove-Item -LiteralPath $inputs -Recurse -Force
}
