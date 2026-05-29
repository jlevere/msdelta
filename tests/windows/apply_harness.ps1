# ApplyDeltaB cross-check harness.
# Applies each <name>.delta to <name>.ref via the real msdelta.dll and prints:
#   <name>\t<PASS|FAIL|ERROR>\t<got-sha256>\t<expected-sha256>\t<got-len>\t<expected-len>
# Usage: powershell -ExecutionPolicy Bypass -File rt_harness.ps1 <corpus-dir>

param([Parameter(Mandatory=$true)][string]$Dir)
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class MsDelta {
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_INPUT {
        public IntPtr lpStart;
        public IntPtr uSize;     // SIZE_T
        public int    Editable;  // BOOL
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_OUTPUT {
        public IntPtr lpStart;
        public IntPtr uSize;     // SIZE_T
    }

    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool ApplyDeltaB(
        long ApplyFlags,
        DELTA_INPUT Source,
        DELTA_INPUT Delta,
        out DELTA_OUTPUT lpTarget);

    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool DeltaFree(IntPtr lpMemory);

    // Apply a delta to a reference, returning the produced target bytes.
    public static byte[] Apply(byte[] reference, byte[] delta) {
        GCHandle hRef = GCHandle.Alloc(reference, GCHandleType.Pinned);
        GCHandle hDel = GCHandle.Alloc(delta, GCHandleType.Pinned);
        try {
            DELTA_INPUT src = new DELTA_INPUT {
                lpStart = hRef.AddrOfPinnedObject(),
                uSize = (IntPtr)reference.Length,
                Editable = 0 };
            DELTA_INPUT del = new DELTA_INPUT {
                lpStart = hDel.AddrOfPinnedObject(),
                uSize = (IntPtr)delta.Length,
                Editable = 0 };
            DELTA_OUTPUT outp;
            if (!ApplyDeltaB(0, src, del, out outp)) {
                int err = Marshal.GetLastWin32Error();
                throw new Exception("ApplyDeltaB failed, GetLastError=" + err);
            }
            long n = outp.uSize.ToInt64();
            byte[] result = new byte[n];
            if (n > 0 && outp.lpStart != IntPtr.Zero) {
                Marshal.Copy(outp.lpStart, result, 0, (int)n);
            }
            DeltaFree(outp.lpStart);
            return result;
        } finally {
            hRef.Free();
            hDel.Free();
        }
    }
}
"@

function Sha256Hex([byte[]]$b) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    ($sha.ComputeHash($b) | ForEach-Object { $_.ToString("x2") }) -join ""
}

$manifest = Get-Content (Join-Path $Dir "manifest.tsv")
foreach ($line in $manifest) {
    if (-not $line.Trim()) { continue }
    $f = $line -split "`t"
    $name = $f[0]; $expSha = $f[1]; $expLen = $f[2]
    $refPath = Join-Path $Dir "$name.ref"
    $delPath = Join-Path $Dir "$name.delta"
    try {
        $ref = [System.IO.File]::ReadAllBytes($refPath)
        $del = [System.IO.File]::ReadAllBytes($delPath)
        $out = [MsDelta]::Apply($ref, $del)
        $gotSha = Sha256Hex $out
        $status = if ($gotSha -eq $expSha -and $out.Length -eq [int]$expLen) { "PASS" } else { "FAIL" }
        "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $name, $status, $gotSha, $expSha, $out.Length, $expLen
    } catch {
        "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $name, "ERROR", $_.Exception.Message, $expSha, "-", $expLen
    }
}
