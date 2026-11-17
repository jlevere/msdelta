param([Parameter(Mandatory=$true)][string]$Inputs,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$csc='C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$inputRoot=(Resolve-Path -LiteralPath $Inputs).Path
if(Test-Path -LiteralPath $Output){throw 'Preserve existing compile evidence.'}
$outputRoot=(New-Item -ItemType Directory -Path $Output).FullName
foreach($case in Get-ChildItem -LiteralPath $inputRoot -Directory | Sort-Object Name){
    foreach($variant in @('source','target')){
        $destination=(New-Item -ItemType Directory -Path "$outputRoot/$($case.Name)/$variant").FullName
        $sourcePath=(Resolve-Path -LiteralPath (Join-Path $case.FullName "$variant.cs")).Path
        $assemblyPath=Join-Path $destination 'ControlledSignatures.dll'
        $compilerArgs=@('/nologo','/target:library','/debug-','/optimize+','/platform:x86',"/out:$assemblyPath",$sourcePath)
        & $csc @compilerArgs
        if($LASTEXITCODE -ne 0){throw "Compiler failed: $($case.Name) $variant"}
    }
}
[ordered]@{schema=1;compiler_path=$csc;compiler_sha256=(Get-FileHash $csc -Algorithm SHA256).Hash.ToLower();compiler_version=(Get-Item $csc).VersionInfo.FileVersion;flags=@('/target:library','/debug-','/optimize+','/platform:x86')} | ConvertTo-Json | Set-Content -LiteralPath "$outputRoot/compiler.json" -Encoding UTF8
