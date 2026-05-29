# Windows cross-check harnesses

These PowerShell scripts validate this crate's encoder/decoder against the
genuine `msdelta.dll` on a Windows host (any build with
`C:\Windows\System32\msdelta.dll`). They P/Invoke `ApplyDeltaB` /
`CreateDeltaB` / `DeltaFree` directly — no crate code runs on Windows.

The in-crate `cargo nextest` suite only proves the encoder and decoder agree
with each other. These harnesses are the only ground truth for whether genuine
`msdelta.dll` accepts the deltas this crate produces.

## Workflow

1. On the dev host, generate a test corpus with the Rust example:

   ```sh
   cargo run --release --example gen_roundtrip_corpus -- ./rtcorpus
   ```

   This writes, per case, `<name>.ref`, `<name>.target`, `<name>.delta` (our
   encoder) and a `manifest.tsv` of `name <tab> sha256(target) <tab>
   target_len <tab> delta_len`.

2. Copy the `rtcorpus` directory and these scripts to a Windows host (any
   transport: SMB, scp, shared folder).

3. Run a harness in PowerShell:

   ```powershell
   # Apply our deltas with genuine msdelta.dll and compare hashes:
   powershell -ExecutionPolicy Bypass -File apply_harness.ps1 .\rtcorpus

   # Produce genuine msdelta deltas (.gold) for the same inputs, to diff
   # against ours (RAW=FileTypeSet 1; PE=0xF; MD5 hash=0x8003):
   powershell -ExecutionPolicy Bypass -File gen_golden.ps1 .\rtcorpus

   # Control: confirm genuine CreateDeltaB -> ApplyDeltaB round-trips (sanity
   # check that the P/Invoke marshalling is correct):
   powershell -ExecutionPolicy Bypass -File create_probe.ps1 .\rtcorpus
   ```

## Scripts

- `apply_harness.ps1` — applies each `<name>.delta` to `<name>.ref` via
  `ApplyDeltaB`, prints `name <tab> PASS|FAIL|ERROR <tab> got-sha <tab>
  exp-sha <tab> got-len <tab> exp-len`.
- `gen_golden.ps1` — calls `CreateDeltaB` for each case to emit a genuine
  `<name>.gold` delta. Use `examples/analyze_delta.rs` back on the dev host to
  diff genuine vs. ours.
- `create_probe.ps1` — `CreateDeltaB` then `ApplyDeltaB` on the same pair;
  confirms the harness itself is correct and dumps the genuine delta header.

## Notes

- `DELTA_INPUT`/`DELTA_OUTPUT` are passed by value; byte arrays are pinned with
  `GCHandle`; output is freed with `DeltaFree`. `ApplyFlags` is 0.
- `ApplyDeltaB` returns a null output pointer for a zero-length target; the
  harness handles that.
- This `msdelta.dll` does not implement PA31 or SHA-256 hashing via
  `CreateDeltaB`/`ApplyDeltaB` (those live in `UpdateCompression.dll`).
