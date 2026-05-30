# Universal differential-oracle executor.
#
# Reads a job.json (written by the `oracle` crate), runs the requested
# interop-matrix directions for each case against ONE native reference DLL, and
# writes a structured result.<dll>.json. Stateless: every policy decision (file
# type set, hash alg, which directions) comes from the job, never from case
# names.
#
# Run once per DLL in a fresh PowerShell process (the DLL name is baked into the
# P/Invoke type at Add-Type time, so a single process binds one DLL):
#
#   powershell -ExecutionPolicy Bypass -File oracle_harness.ps1 `
#       -Dir .\job -Dll msdelta.dll -Out .\result.msdelta.json
#   powershell -ExecutionPolicy Bypass -File oracle_harness.ps1 `
#       -Dir .\job -Dll UpdateCompression.dll -Out .\result.UpdateCompression.json
#
# Directions (see crate::kernel::Direction):
#   ours_to_native   apply <id>.ours.delta to <id>.ref; compare to expected target
#   native_to_ours   CreateDeltaB(ref,target,spec) -> <id>.<dll>.gold (decoded on the mac)
#   native_to_native CreateDeltaB then ApplyDeltaB on the same pair (control)
#   ours_to_ours     local-only; ignored here

param(
    [Parameter(Mandatory = $true)][string]$Dir,
    [string]$Dll = "msdelta.dll",
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = "Stop"

# The DLL name is interpolated into the DllImport so a single code path serves
# any reference DLL exposing the msdelta ABI.
$src = @"
using System;
using System.Runtime.InteropServices;

public static class OracleRef {
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_INPUT  { public IntPtr lpStart; public IntPtr uSize; public int Editable; }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_OUTPUT { public IntPtr lpStart; public IntPtr uSize; }

    [DllImport("$Dll", SetLastError=true)]
    public static extern bool ApplyDeltaB(long ApplyFlags, DELTA_INPUT Source, DELTA_INPUT Delta, out DELTA_OUTPUT Target);

    [DllImport("$Dll", SetLastError=true)]
    public static extern bool CreateDeltaB(long FileTypeSet, long SetFlags, long ResetFlags,
        DELTA_INPUT Source, DELTA_INPUT Target, DELTA_INPUT SourceOptions, DELTA_INPUT TargetOptions,
        DELTA_INPUT GlobalOptions, IntPtr TargetFileTime, uint HashAlgId, out DELTA_OUTPUT Delta);

    [DllImport("$Dll", SetLastError=true)]
    public static extern bool ApplyDeltaGetReverseB(long ApplyFlags, DELTA_INPUT Source, DELTA_INPUT Delta,
        IntPtr TargetFileTime, out DELTA_OUTPUT Target, out DELTA_OUTPUT TargetReverse);

    [DllImport("$Dll")]
    public static extern bool DeltaFree(IntPtr lpMemory);

    static DELTA_INPUT In(IntPtr p, long n) { return new DELTA_INPUT { lpStart = p, uSize = (IntPtr)n, Editable = 0 }; }
    static DELTA_INPUT Nul() { return new DELTA_INPUT { lpStart = IntPtr.Zero, uSize = IntPtr.Zero, Editable = 0 }; }

    // Apply delta to reference -> produced target bytes (throws on failure).
    public static byte[] Apply(byte[] reference, byte[] delta) {
        GCHandle hR = GCHandle.Alloc(reference, GCHandleType.Pinned);
        GCHandle hD = GCHandle.Alloc(delta, GCHandleType.Pinned);
        try {
            DELTA_OUTPUT o;
            if (!ApplyDeltaB(0, In(hR.AddrOfPinnedObject(), reference.Length),
                                In(hD.AddrOfPinnedObject(), delta.Length), out o))
                throw new Exception("ApplyDeltaB GetLastError=" + Marshal.GetLastWin32Error());
            long n = o.uSize.ToInt64();
            byte[] r = new byte[n];
            if (n > 0 && o.lpStart != IntPtr.Zero) Marshal.Copy(o.lpStart, r, 0, (int)n);
            DeltaFree(o.lpStart);
            return r;
        } finally { hR.Free(); hD.Free(); }
    }

    // CreateDeltaB(ref,target,spec) -> delta bytes (throws on failure).
    public static byte[] Create(byte[] reference, byte[] target, long fileTypeSet, long setFlags, long resetFlags, uint hashAlg) {
        GCHandle hR = GCHandle.Alloc(reference, GCHandleType.Pinned);
        GCHandle hT = GCHandle.Alloc(target, GCHandleType.Pinned);
        try {
            DELTA_OUTPUT o;
            if (!CreateDeltaB(fileTypeSet, setFlags, resetFlags,
                    In(hR.AddrOfPinnedObject(), reference.Length), In(hT.AddrOfPinnedObject(), target.Length),
                    Nul(), Nul(), Nul(), IntPtr.Zero, hashAlg, out o))
                throw new Exception("CreateDeltaB GetLastError=" + Marshal.GetLastWin32Error());
            long n = o.uSize.ToInt64();
            byte[] r = new byte[n];
            if (n > 0 && o.lpStart != IntPtr.Zero) Marshal.Copy(o.lpStart, r, 0, (int)n);
            DeltaFree(o.lpStart);
            return r;
        } finally { hR.Free(); hT.Free(); }
    }

    // Apply a forward delta and get the reverse delta in one call. Returns
    // { target, reverse } (throws on failure). TargetFileTime null -> current.
    public static byte[][] ApplyGetReverse(byte[] source, byte[] delta) {
        GCHandle hS = GCHandle.Alloc(source, GCHandleType.Pinned);
        GCHandle hD = GCHandle.Alloc(delta, GCHandleType.Pinned);
        try {
            DELTA_OUTPUT ot, orv;
            if (!ApplyDeltaGetReverseB(0, In(hS.AddrOfPinnedObject(), source.Length),
                    In(hD.AddrOfPinnedObject(), delta.Length), IntPtr.Zero, out ot, out orv))
                throw new Exception("ApplyDeltaGetReverseB GetLastError=" + Marshal.GetLastWin32Error());
            long nt = ot.uSize.ToInt64(); byte[] t = new byte[nt];
            if (nt > 0 && ot.lpStart != IntPtr.Zero) Marshal.Copy(ot.lpStart, t, 0, (int)nt);
            long nr = orv.uSize.ToInt64(); byte[] rv = new byte[nr];
            if (nr > 0 && orv.lpStart != IntPtr.Zero) Marshal.Copy(orv.lpStart, rv, 0, (int)nr);
            DeltaFree(ot.lpStart); DeltaFree(orv.lpStart);
            return new byte[][] { t, rv };
        } finally { hS.Free(); hD.Free(); }
    }
}
"@
Add-Type -TypeDefinition $src

function Sha256Hex([byte[]]$b) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    ($sha.ComputeHash($b) | ForEach-Object { $_.ToString("x2") }) -join ""
}
function Read-Bytes([string]$p) { [System.IO.File]::ReadAllBytes($p) }

# Canonicalize the job dir to an absolute backslash path and work inside it, so
# every read/write uses a clean local filename (forward-slash absolute paths fed
# straight to .NET / Set-Content resolved inconsistently against the ssh CWD).
$Dir = (Resolve-Path -LiteralPath $Dir).Path
Set-Location -LiteralPath $Dir

$dllTag = [System.IO.Path]::GetFileNameWithoutExtension($Dll)
$job = Get-Content (Join-Path $Dir "job.json") -Raw | ConvertFrom-Json
$results = @()

foreach ($case in $job.cases) {
    $refPath = Join-Path $Dir $case.reference
    $tgtPath = Join-Path $Dir $case.target
    $reference = Read-Bytes $refPath
    $target = Read-Bytes $tgtPath
    $spec = $case.native
    $dirs = @($case.directions)
    $row = [ordered]@{ id = $case.id }

    if ($dirs -contains "ours_to_native") {
        try {
            $delta = Read-Bytes (Join-Path $Dir $case.ours_delta)
            # NB: never name this $out -- PowerShell is case-insensitive, so $out
            # would alias and clobber the $Out parameter (the result path).
            $produced = [OracleRef]::Apply($reference, $delta)
            $gotSha = Sha256Hex $produced
            $status = if ($gotSha -eq $case.target_sha256 -and $produced.Length -eq [int64]$case.target_len) { "PASS" } else { "FAIL" }
            $row.ours_to_native = [ordered]@{ status = $status; got_sha = $gotSha; got_len = $produced.Length; message = "" }
        } catch {
            $row.ours_to_native = [ordered]@{ status = "ERROR"; got_sha = ""; got_len = 0; message = $_.Exception.Message }
        }
    }

    if ($dirs -contains "native_to_ours") {
        try {
            $gold = [OracleRef]::Create($reference, $target, [int64]$spec.file_type_set, [int64]$spec.set_flags, [int64]$spec.reset_flags, [uint32]$spec.hash_alg)
            $goldName = "$($case.id).$dllTag.gold"
            [System.IO.File]::WriteAllBytes((Join-Path $Dir $goldName), $gold)
            $row.native_to_ours = [ordered]@{ status = "OK"; gold = $goldName; gold_len = $gold.Length; message = "" }
        } catch {
            $row.native_to_ours = [ordered]@{ status = "ERROR"; gold = ""; gold_len = 0; message = $_.Exception.Message }
        }
    }

    if ($dirs -contains "native_to_native") {
        try {
            $gold = [OracleRef]::Create($reference, $target, [int64]$spec.file_type_set, [int64]$spec.set_flags, [int64]$spec.reset_flags, [uint32]$spec.hash_alg)
            $produced = [OracleRef]::Apply($reference, $gold)
            $gotSha = Sha256Hex $produced
            $status = if ($gotSha -eq $case.target_sha256 -and $produced.Length -eq [int64]$case.target_len) { "PASS" } else { "FAIL" }
            $row.native_to_native = [ordered]@{ status = $status; got_sha = $gotSha; got_len = $produced.Length; message = "" }
        } catch {
            $row.native_to_native = [ordered]@{ status = "ERROR"; got_sha = ""; got_len = 0; message = $_.Exception.Message }
        }
    }

    if ($dirs -contains "reverse_round_trip") {
        try {
            $delta = Read-Bytes (Join-Path $Dir $case.ours_delta)
            # Genuine reverse-API applied to OUR forward delta.
            $res = [OracleRef]::ApplyGetReverse($reference, $delta)
            $tgt = $res[0]; $rev = $res[1]
            $fwdOk = (Sha256Hex $tgt) -eq $case.target_sha256
            # Persist the genuine reverse delta as a gold for our decoder.
            $revName = "$($case.id).$dllTag.reverse.gold"
            [System.IO.File]::WriteAllBytes((Join-Path $Dir $revName), $rev)
            # Genuine reverse delta must reconstruct the source.
            $src2 = [OracleRef]::Apply($tgt, $rev)
            $genRevOk = (Sha256Hex $src2) -eq $case.reference_sha256
            # Our reverse delta (if provided) must also be accepted by genuine apply.
            $oursRevOk = $true
            if ($case.reverse_delta) {
                $ourRev = Read-Bytes (Join-Path $Dir $case.reverse_delta)
                $src3 = [OracleRef]::Apply($tgt, $ourRev)
                $oursRevOk = (Sha256Hex $src3) -eq $case.reference_sha256
            }
            $status = if ($fwdOk -and $genRevOk -and $oursRevOk) { "PASS" } else { "FAIL" }
            $row.reverse_round_trip = [ordered]@{ status = $status; got_sha = (Sha256Hex $tgt); got_len = $tgt.Length; gold = $revName; message = ("fwd={0} genRev={1} oursRev={2}" -f $fwdOk, $genRevOk, $oursRevOk) }
        } catch {
            $row.reverse_round_trip = [ordered]@{ status = "ERROR"; got_sha = ""; got_len = 0; gold = ""; message = $_.Exception.Message }
        }
    }

    $results += [pscustomobject]$row
}

$report = [ordered]@{
    schema_version = 1
    dll            = $Dll
    domain         = $job.domain
    seed           = $job.seed
    results        = $results
}
# Depth must exceed the nested ordered dictionaries or ConvertTo-Json truncates.
# Windows PowerShell 5.1's `Set-Content -Encoding utf8` prepends a UTF-8 BOM; the
# Rust-side reader strips it. (Raw .NET WriteAllText hit spurious PathTooLong
# here, so we stick with the provider-aware Set-Content.)
$outPath = Join-Path $Dir ([System.IO.Path]::GetFileName($Out))
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outPath -Encoding utf8
Write-Host ("{0}: {1} cases -> {2}" -f $Dll, $results.Count, $Out)
