$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root='C:/Users/localuser/msdelta-pe-pipeline'
$output=New-Item -ItemType Directory -Path "$root/existing-captures"
foreach ($case in Get-ChildItem "$root/existing-inputs" -Directory | Sort-Object Name) {
    $metadata=Get-Content -LiteralPath "$($case.FullName)/input.json" -Raw | ConvertFrom-Json
    $destination=New-Item -ItemType Directory -Path "$($output.FullName)/$($case.Name)"
    & "$root/pe-pipeline-capture.exe" "$root/msdelta.dll" "$($case.FullName)/source.bin" "$($case.FullName)/delta.pa30" $destination.FullName $metadata.expected_sha256
    if ($LASTEXITCODE -ne 0) { throw "Capture failed: $($case.Name)" }
    Copy-Item -LiteralPath "$($case.FullName)/input.json" -Destination $destination.FullName
}
