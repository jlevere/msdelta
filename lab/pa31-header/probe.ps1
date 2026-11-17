param(
    [Parameter(Mandatory = $true)][string]$OracleExe,
    [Parameter(Mandatory = $true)][string]$Dll,
    [Parameter(Mandatory = $true)][string]$Inputs,
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$oracle = (Resolve-Path -LiteralPath $OracleExe).Path
$library = (Resolve-Path -LiteralPath $Dll).Path
$inputPath = (Resolve-Path -LiteralPath $Inputs).Path
if (Test-Path -LiteralPath $Output) { throw 'Choose a fresh output directory.' }
$cases = @(Get-ChildItem -LiteralPath $inputPath -Directory | Sort-Object Name)
if ($cases.Count -eq 0) { throw 'No semantic probes were found.' }
foreach ($case in $cases) {
    foreach ($name in @('source.bin', 'target.bin', 'delta.pa31', 'probe.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $case.FullName $name) -PathType Leaf)) {
            throw "Missing $name for $($case.Name)"
        }
    }
}
$root = (New-Item -ItemType Directory -Path $Output).FullName
foreach ($case in $cases) {
    $destination = (New-Item -ItemType Directory -Path (Join-Path $root $case.Name)).FullName
    Copy-Item -LiteralPath (Join-Path $case.FullName 'probe.json') -Destination $destination
    Write-Output $case.Name
    & $oracle probe $library (Join-Path $case.FullName 'source.bin') (Join-Path $case.FullName 'delta.pa31') (Join-Path $case.FullName 'target.bin') $destination
    if ($LASTEXITCODE -ne 0) { throw "Oracle execution failed for $($case.Name)" }
    # Native rejection is a valid observation; a missing manifest is not.
    $null = Get-Content -LiteralPath (Join-Path $destination 'observation.json') -Raw | ConvertFrom-Json
}
Write-Output "Observed $($cases.Count) semantic probes."
