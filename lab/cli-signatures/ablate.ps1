$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:/Users/localuser/msdelta-cli-signatures'
$source="$root/cli-signatures-prepared/definition-moves/base.bin"
$target="$root/cli-signatures-prepared/definition-moves/target.bin"
$expected=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
foreach($mode in @('normal','no-metadata')){
    $created=(New-Item -ItemType Directory -Path "$root/ablation/$mode/created").FullName
    & "$root/cli-signatures-mint-ablation.exe" $mode 'C:/Users/localuser/msdelta-pe-pipeline/msdelta.dll' $source $target $created
    if($LASTEXITCODE -ne 0){throw "Native creation failed: $mode"}
    $capture=(New-Item -ItemType Directory -Path "$root/ablation/$mode/capture").FullName
    & 'C:/Users/localuser/msdelta-pe-pipeline/pe-pipeline-capture.exe' 'C:/Users/localuser/msdelta-pe-pipeline/msdelta.dll' $source "$created/delta.pa30" $capture $expected
    if($LASTEXITCODE -ne 0){throw "Native capture failed: $mode"}
}
