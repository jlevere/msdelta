param(
    [Parameter(Mandatory = $true)][string]$CaptureExe,
    [Parameter(Mandatory = $true)][string]$Dll,
    [Parameter(Mandatory = $true)][string]$Inputs,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$capturePath = (Resolve-Path -LiteralPath $CaptureExe).Path
$dllPath = (Resolve-Path -LiteralPath $Dll).Path
$inputPath = (Resolve-Path -LiteralPath $Inputs).Path
if (Test-Path -LiteralPath $Output) {
    throw 'Choose a new output directory so previous captures remain intact.'
}
$cases = @(Get-ChildItem -LiteralPath $inputPath -Directory | Sort-Object Name)
if ($cases.Count -eq 0) { throw 'No input cases were found.' }
foreach ($case in $cases) {
    foreach ($name in @('base.bin', 'target.bin')) {
        if (-not (Test-Path -LiteralPath (Join-Path $case.FullName $name) -PathType Leaf)) {
            throw "Missing $name in $($case.FullName)"
        }
    }
}
$outputPath = (New-Item -ItemType Directory -Path $Output).FullName
foreach ($case in $cases) {
    $destination = (New-Item -ItemType Directory -Path (Join-Path $outputPath $case.Name)).FullName
    & $capturePath $dllPath (Join-Path $case.FullName 'base.bin') (Join-Path $case.FullName 'target.bin') $destination --create
    if ($LASTEXITCODE -ne 0) {
        throw "Capture failed for $($case.Name) with exit code $LASTEXITCODE"
    }
    $metadata = Get-Content -LiteralPath (Join-Path $destination 'capture.json') -Raw | ConvertFrom-Json
    if ($metadata.uninstrumented_output_equal -ne $true -or $metadata.decompress_source_unchanged -ne $true) {
        throw "Native control checks missing for $($case.Name)"
    }
}
Write-Output "Captured all $($cases.Count) PA30 copy boundaries in $outputPath"
