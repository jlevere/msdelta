param(
    [Parameter(Mandatory = $true)][string]$CaptureExe,
    [Parameter(Mandatory = $true)][string]$Dll,
    [Parameter(Mandatory = $true)][string]$Inputs,
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$exe = (Resolve-Path -LiteralPath $CaptureExe).Path
$dllPath = (Resolve-Path -LiteralPath $Dll).Path
$inputPath = (Resolve-Path -LiteralPath $Inputs).Path
if (Test-Path -LiteralPath $Output) { throw 'Output already exists; preserve previous evidence.' }
$root = (New-Item -ItemType Directory -Path $Output).FullName
$cases = @(Get-ChildItem -LiteralPath $inputPath -Directory | Sort-Object Name)
if ($cases.Count -eq 0) { throw 'No prepared cases.' }
foreach ($case in $cases) {
    $metadata = Get-Content -LiteralPath (Join-Path $case.FullName 'input.json') -Raw | ConvertFrom-Json
    $destination = (New-Item -ItemType Directory -Path (Join-Path $root $case.Name)).FullName
    $original = (New-Item -ItemType Directory -Path (Join-Path $destination 'original-attempt')).FullName
    # Expected original provider rejection is evidence, not a request to retry.
    # The separately described hash-disabled input is a distinct experiment.
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $exe $dllPath (Join-Path $case.FullName 'source.bin') (Join-Path $case.FullName 'original.delta') $original $metadata.expected_sha256 > (Join-Path $destination 'original.stdout') 2> (Join-Path $destination 'original.stderr')
    $originalExit = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    if ($originalExit -eq 0) {
        $capturePath = $original
        $adapted = $false
    } else {
        $originalError = Get-Content -LiteralPath (Join-Path $destination 'original.stderr') -Raw
        if ($originalError -notmatch 'native uninstrumented ApplyDeltaB failed \(Windows error 13\)') {
            throw "Unexpected original failure for $($case.Name): $originalError"
        }
        $capturePath = (New-Item -ItemType Directory -Path (Join-Path $destination 'adapted-capture')).FullName
        & $exe $dllPath (Join-Path $case.FullName 'source.bin') (Join-Path $case.FullName 'adapted.delta') $capturePath $metadata.expected_sha256
        if ($LASTEXITCODE -ne 0) { throw "Adapted native capture failed for $($case.Name): $LASTEXITCODE" }
        $adapted = $true
    }
    $capture = Get-Content -LiteralPath (Join-Path $capturePath 'capture.json') -Raw | ConvertFrom-Json
    if (-not $capture.uninstrumented_output_equal -or $capture.artifact_sha256.'target.bin' -ne $metadata.expected_sha256) { throw 'Target control mismatch.' }
    [ordered]@{schema=1; original_exit_code=$originalExit; hash_adapted=$adapted; expected_sha256=$metadata.expected_sha256; capture_directory=$capturePath; harness_sha256=(Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower(); dll_sha256=(Get-FileHash -Algorithm SHA256 $dllPath).Hash.ToLower()} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $destination 'acceptance.json')
    Copy-Item -LiteralPath (Join-Path $case.FullName 'input.json') -Destination $destination
    Write-Output "Completed $($case.Name)"
}
