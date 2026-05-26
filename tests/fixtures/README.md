# Test fixtures

Real DCM-compressed manifest files pulled from a Windows host, used as
decoder inputs.

## Provenance

Pulled from `jackson-dev` (Windows Server 2025 Standard Evaluation,
build 26100), sourced from `C:\Windows\WinSxS\Manifests\`. Picks span
the size distribution (P0, P25, P50, P75, P95, P99, max) of the 34,882
manifests present on a fresh install.

All files have been verified to begin with the DCM wrapper magic
`44 43 4D 01` (`DCM\x01`).

| File | Size | Notes |
|---|---|---|
| `amd64_microsoft-windows-core_*.manifest` | 65 B | Smallest manifest on the box |
| `amd64_multipoint-srcres.resources_*.manifest` | 249 B | ~P25 |
| `amd64_microsoft-windows-font-truetype-gadugi_*.manifest` | 355 B | ~P50 (median) |
| `amd64_microsoft-windows-s..riencehost.appxmain_*.manifest` | 696 B | ~P75 |
| `amd64_dual_netvg63a.inf_*.manifest` | 2.8 KB | ~P95 |
| `amd64_microsoft-windows-network-security_*.manifest` | 9.3 KB | ~P99 |
| `wow64_microsoft-windows-o..euapcommonproxystub_*.manifest` | 175 KB | Largest manifest on the box |

## What's missing: decoded XML

Each DCM-compressed manifest ideally pairs with its decoded XML form
(`<file>.manifest.xml`) so round-trip tests can assert byte-equivalence.
That side is not collected yet — producing it requires a working
decoder. Options for unblocking it:

1. **Build/install `wcpex`** (https://github.com/smx-smx/wcpex) on a
   Windows host and run it against each manifest. Closest pre-existing
   reference implementation.
2. **Write a P/Invoke wrapper** in PowerShell or C# that calls
   `wcp.dll!IsManifestCompressed` + `wcp.dll!DecompressManifest`
   directly. Single-purpose, no third-party dependency.
3. **Bootstrap once we have our own decoder**, then use it on the same
   inputs and pin the output as the golden file. Risky as the only
   source of truth — but acceptable as a second check alongside (1) or
   (2).

## Distribution caveat

These files are extracted from a Microsoft product image and are not
freely redistributable. They are checked-in here as test inputs for
local development; downstream packaging (e.g. publishing to crates.io)
should exclude this directory and direct users to regenerate from their
own Windows install via the staging script in this project.
