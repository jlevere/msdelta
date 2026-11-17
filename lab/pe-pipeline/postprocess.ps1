param([ValidateSet('create', 'probe')][string]$Phase)
$ErrorActionPreference = 'Stop'
$root = 'C:/Users/localuser/msdelta-pe-postprocess'
$capture = 'C:/Users/localuser/msdelta-pe-pipeline/pe-pipeline-capture.exe'
$dll = 'C:/Users/localuser/msdelta-pe-pipeline/msdelta.dll'
if ($Phase -eq 'create') {
    foreach ($case in Get-ChildItem "$root/inputs" -Directory | Sort-Object Name) {
        $output = "$root/controls/$($case.Name)"
        New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
        & $capture $dll "$($case.FullName)/source.bin" "$($case.FullName)/target.bin" $output --create
        if ($LASTEXITCODE -ne 0) { throw "Native create failed: $($case.Name)" }
    }
} else {
    foreach ($case in Get-ChildItem "$root/variants" -Directory | Sort-Object Name) {
        foreach ($flag in 0, 1) {
            $output = "$root/probes/$($case.Name)/flag-$flag"
            New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
            & $capture $dll "$($case.FullName)/source.bin" "$($case.FullName)/flag-$flag.pa30" $output
            if ($LASTEXITCODE -ne 0) { throw "Native probe failed: $($case.Name), flag $flag" }
        }
    }
}
