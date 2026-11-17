param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$dll='C:/Users/localuser/msdelta-pe-pipeline/msdelta.dll'
$mint='C:/Users/localuser/msdelta-cli-signatures/cli-signatures-mint-ablation.exe'
$capture='C:/Users/localuser/msdelta-cli-signatures/cli-signatures-capture.exe'
if((Test-Path "$Root/minted") -or (Test-Path "$Root/captures")){throw 'Preserve earlier native observations.'}
New-Item -ItemType Directory "$Root/minted" | Out-Null
New-Item -ItemType Directory "$Root/captures" | Out-Null
foreach($case in Get-ChildItem "$Root/grammar-prepared" -Directory | Sort-Object Name){
    $metadata=Get-Content "$($case.FullName)/input.json" -Raw | ConvertFrom-Json
    $minted=(New-Item -ItemType Directory "$Root/minted/$($case.Name)").FullName
    $observed=(New-Item -ItemType Directory "$Root/captures/$($case.Name)").FullName
    & $mint normal $dll "$($case.FullName)/base.bin" "$($case.FullName)/target.bin" $minted
    if($LASTEXITCODE -ne 0){throw "Native creation failed: $($case.Name)"}
    & $capture $dll "$($case.FullName)/base.bin" "$minted/delta.pa30" $observed $metadata.target.normalized_sha256
    if($LASTEXITCODE -ne 0){throw "Native capture failed: $($case.Name)"}
    Copy-Item "$minted/creation.json" "$observed/creation.json"
    foreach($file in @('input.json','source.cs','target.cs')){Copy-Item "$($case.FullName)/$file" "$observed/$file"}
}
