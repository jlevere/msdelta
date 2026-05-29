# Control test: does msdelta.dll's own CreateDeltaB -> ApplyDeltaB round-trip
# through the same P/Invoke harness? Also dumps the genuine delta header so we
# can compare it to our encoder's output.
param([Parameter(Mandatory=$true)][string]$Dir)
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class MsDelta {
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_INPUT { public IntPtr lpStart; public IntPtr uSize; public int Editable; }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_OUTPUT { public IntPtr lpStart; public IntPtr uSize; }

    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool ApplyDeltaB(long Flags, DELTA_INPUT Source, DELTA_INPUT Delta, out DELTA_OUTPUT Target);
    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool CreateDeltaB(long FileTypeSet, long SetFlags, long ResetFlags,
        DELTA_INPUT Source, DELTA_INPUT Target, DELTA_INPUT SourceOptions, DELTA_INPUT TargetOptions,
        DELTA_INPUT GlobalOptions, IntPtr TargetFileTime, uint HashAlgId, out DELTA_OUTPUT Delta);
    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool DeltaFree(IntPtr lpMemory);

    static DELTA_INPUT In(IntPtr p, int n) { return new DELTA_INPUT { lpStart=p, uSize=(IntPtr)n, Editable=0 }; }
    static DELTA_INPUT Nul() { return new DELTA_INPUT { lpStart=IntPtr.Zero, uSize=IntPtr.Zero, Editable=0 }; }

    // Create a delta with the genuine encoder (RAW file type, default flags).
    public static byte[] Create(byte[] reference, byte[] target) {
        GCHandle hR=GCHandle.Alloc(reference,GCHandleType.Pinned), hT=GCHandle.Alloc(target,GCHandleType.Pinned);
        try {
            DELTA_OUTPUT outp;
            // FileTypeSet = DELTA_FILE_TYPE_RAW (1)
            if (!CreateDeltaB(1, 0, 0, In(hR.AddrOfPinnedObject(),reference.Length),
                In(hT.AddrOfPinnedObject(),target.Length), Nul(), Nul(), Nul(), IntPtr.Zero, 0, out outp)) {
                throw new Exception("CreateDeltaB failed, GetLastError=" + Marshal.GetLastWin32Error());
            }
            long n = outp.uSize.ToInt64();
            byte[] d = new byte[n]; Marshal.Copy(outp.lpStart, d, 0, (int)n); DeltaFree(outp.lpStart); return d;
        } finally { hR.Free(); hT.Free(); }
    }
    public static byte[] Apply(byte[] reference, byte[] delta) {
        GCHandle hR=GCHandle.Alloc(reference,GCHandleType.Pinned), hD=GCHandle.Alloc(delta,GCHandleType.Pinned);
        try {
            DELTA_OUTPUT outp;
            if (!ApplyDeltaB(0, In(hR.AddrOfPinnedObject(),reference.Length), In(hD.AddrOfPinnedObject(),delta.Length), out outp))
                throw new Exception("ApplyDeltaB failed, GetLastError=" + Marshal.GetLastWin32Error());
            long n = outp.uSize.ToInt64();
            byte[] r = new byte[n]; Marshal.Copy(outp.lpStart, r, 0, (int)n); DeltaFree(outp.lpStart); return r;
        } finally { hR.Free(); hD.Free(); }
    }
}
"@

function Hex([byte[]]$b, [int]$n) { ($b[0..([Math]::Min($n,$b.Length)-1)] | ForEach-Object { $_.ToString("x2") }) -join " " }

$ref = [System.IO.File]::ReadAllBytes((Join-Path $Dir "text_pa30_lzx.ref"))
$tgt = [byte[]]([System.Text.Encoding]::ASCII.GetBytes("Hello, this is a MODIFIED buffer with some repeated content. Goodbye now! " +
    "          The quick brown fox jumps over the lazy cat. Repeated content repeated content."))
# (target reconstructed not needed; we just round-trip create->apply)

"--- CreateDeltaB on text pair ---"
$genuine = [MsDelta]::Create($ref, $tgt)
"genuine delta len: $($genuine.Length)"
"genuine delta head: $(Hex $genuine 32)"
$back = [MsDelta]::Apply($ref, $genuine)
"apply(genuine) len: $($back.Length)  matches target: $([System.Linq.Enumerable]::SequenceEqual($back, $tgt))"

"--- our delta head for same case ---"
$ours = [System.IO.File]::ReadAllBytes((Join-Path $Dir "text_pa30_lzx.delta"))
"our delta len: $($ours.Length)"
"our delta head: $(Hex $ours 32)"

"--- our PASSING bigtext delta head ---"
$big = [System.IO.File]::ReadAllBytes((Join-Path $Dir "bigtext_lzx_multiseg.delta"))
"big delta head: $(Hex $big 32)"
