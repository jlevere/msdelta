# Produce GENUINE msdelta.dll deltas (CreateDeltaB) for every case in the
# corpus, so we can diff our encoder against ground truth. Writes <name>.gold.
param([Parameter(Mandatory=$true)][string]$Dir)
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class M {
    [StructLayout(LayoutKind.Sequential)] public struct DI { public IntPtr p; public IntPtr n; public int e; }
    [StructLayout(LayoutKind.Sequential)] public struct DO { public IntPtr p; public IntPtr n; }
    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool CreateDeltaB(long FileTypeSet, long SetFlags, long ResetFlags,
        DI Source, DI Target, DI SourceOptions, DI TargetOptions, DI GlobalOptions,
        IntPtr TargetFileTime, uint HashAlgId, out DO Delta);
    [DllImport("msdelta.dll")] public static extern bool DeltaFree(IntPtr m);
    static DI In(IntPtr p,int n){return new DI{p=p,n=(IntPtr)n,e=0};}
    static DI Nul(){return new DI{p=IntPtr.Zero,n=IntPtr.Zero,e=0};}
    public static byte[] Create(byte[] r, byte[] t, long fileTypeSet, uint hashAlg) {
        var hR=GCHandle.Alloc(r,GCHandleType.Pinned); var hT=GCHandle.Alloc(t,GCHandleType.Pinned);
        try { DO o;
            if(!CreateDeltaB(fileTypeSet,0,0,In(hR.AddrOfPinnedObject(),r.Length),
                In(hT.AddrOfPinnedObject(),t.Length),Nul(),Nul(),Nul(),IntPtr.Zero,hashAlg,out o))
                throw new Exception("CreateDeltaB err "+Marshal.GetLastWin32Error());
            long n=o.n.ToInt64(); var d=new byte[n]; Marshal.Copy(o.p,d,0,(int)n); DeltaFree(o.p); return d;
        } finally { hR.Free(); hT.Free(); }
    }
}
"@
# DELTA_FILE_TYPE_RAW=1; executable set covers I386/AMD64 etc.
$RAW = 1
$EXE = 0x0FFFFFFFE   # DELTA_FILE_TYPE_SET_EXECUTABLES (all non-raw types)
$ALG_MD5 = 0x8003
$ALG_SHA256 = 0x800C

foreach ($line in Get-Content (Join-Path $Dir "manifest.tsv")) {
    if (-not $line.Trim()) { continue }
    $name = ($line -split "`t")[0]
    $ref = [System.IO.File]::ReadAllBytes((Join-Path $Dir "$name.ref"))
    $tgt = [System.IO.File]::ReadAllBytes((Join-Path $Dir "$name.target"))
    $fts = if ($name -like "pe_*") { $EXE } else { $RAW }
    $alg = if ($name -eq "text_md5") { $ALG_MD5 } elseif ($name -eq "text_sha256") { $ALG_SHA256 } else { 0 }
    try {
        $d = [M]::Create($ref, $tgt, $fts, [uint32]$alg)
        [System.IO.File]::WriteAllBytes((Join-Path $Dir "$name.gold"), $d)
        "{0}`tOK`tgold_len={1}" -f $name, $d.Length
    } catch {
        "{0}`tFAIL`t{1}" -f $name, $_.Exception.Message
    }
}
