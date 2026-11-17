param(
    [Parameter(Mandatory = $true)][string]$OracleExe,
    [Parameter(Mandatory = $true)][string]$Dll,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$RustInputs
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$oracle = (Resolve-Path -LiteralPath $OracleExe).Path
$library = (Resolve-Path -LiteralPath $Dll).Path
if (Test-Path -LiteralPath $Output) { throw 'Choose a fresh output directory.' }
$sourceHashes = [ordered]@{}
foreach ($name in @('oracle.c', 'make_probes.py', 'controls.ps1', 'probe.ps1')) {
    $sourceHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
if ($RustInputs) { $RustInputs = (Resolve-Path -LiteralPath $RustInputs).Path }
$root = (New-Item -ItemType Directory -Path $Output).FullName
$inputs = (New-Item -ItemType Directory -Path (Join-Path $root '_inputs')).FullName
try {
    $source = Join-Path $inputs 'source.bin'
    $target = Join-Path $inputs 'target.bin'
    $empty = Join-Path $inputs 'empty.bin'
    [IO.File]::WriteAllBytes($source, [Text.Encoding]::ASCII.GetBytes('C' * 1024))
    [IO.File]::WriteAllBytes($target, [Text.Encoding]::ASCII.GetBytes('D' * 256))
    [IO.File]::WriteAllBytes($empty, [byte[]]@())
    $cases = @(
        @{ Name = 'native-sha256'; Mode = 'create'; Source = $source },
        @{ Name = 'native-empty-source'; Mode = 'create'; Source = $empty },
        @{ Name = 'native-no-hash'; Mode = 'create-no-hash'; Source = $source },
        @{ Name = 'native-pa30'; Mode = 'create-pa30'; Source = $source }
    )
    foreach ($case in $cases) {
        $destination = (New-Item -ItemType Directory -Path (Join-Path $root $case.Name)).FullName
        & $oracle $case.Mode $library $case.Source $target $destination
        if ($LASTEXITCODE -ne 0) { throw "Oracle execution failed for $($case.Name)" }
        $null = Get-Content -LiteralPath (Join-Path $destination 'observation.json') -Raw | ConvertFrom-Json
    }
    if ($RustInputs) {
        foreach ($name in @('rust-md5', 'rust-nohash', 'rust-sha256')) {
            $destination = (New-Item -ItemType Directory -Path (Join-Path $root $name)).FullName
            & $oracle probe $library (Join-Path $RustInputs 'source.bin') (Join-Path $RustInputs "$name.pa31") (Join-Path $RustInputs 'target.bin') $destination
            if ($LASTEXITCODE -ne 0) { throw "Oracle execution failed for $name" }
            $observation = Get-Content -LiteralPath (Join-Path $destination 'observation.json') -Raw | ConvertFrom-Json
            if ($observation.target_equal -ne $true) { throw "Native consumer rejected $name" }
        }
    }
    $provenance = [ordered]@{
        schema = 1
        dll_sha256 = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
        dll_file_version = (Get-Item -LiteralPath $library).VersionInfo.FileVersion
        oracle_sha256 = (Get-FileHash -LiteralPath $oracle -Algorithm SHA256).Hash.ToLowerInvariant()
        source_sha256 = $sourceHashes
        input_design = 'RAW source is 1024 C bytes; target is 256 D bytes, independent of source copies.'
        next_stage = 'Run make_probes.py on native-sha256, then probe.ps1 on generated cases.'
    }
    $provenance | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'provenance.json') -Encoding utf8
} finally {
    # Only the freshly generated temporary input directory is removed.
    Remove-Item -LiteralPath $inputs -Recurse -Force
}
