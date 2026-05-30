# Windows cross-check

The hand-run, single-purpose PowerShell harnesses that used to live here
(`apply_harness.ps1`, `gen_golden.ps1`, `create_probe.ps1`) have been
superseded by the **differential oracle** in [`crates/oracle`](../../crates/oracle).

The oracle generates diverse test cases, runs them through both this crate and
the genuine reference DLLs (`msdelta.dll` / `UpdateCompression.dll`) in both
directions, and scores the results. See `crates/oracle/lab/oracle_harness.ps1`
(the universal P/Invoke executor) and `crates/oracle/lab/run.sh` (the lab
orchestrator).

Typical use, from the repo root:

```sh
cargo build --release -p oracle
./target/release/oracle gen --seed 0x5EED --count 4 --out /tmp/job
bash crates/oracle/lab/run.sh /tmp/job          # runs against both DLLs
./target/release/oracle report --job /tmp/job   # scored summary + failure buckets
```

To shrink a failing case to a small repro:

```sh
./target/release/oracle minimize --job /tmp/job --id <case-id> --dll msdelta.dll
```

Lab coordinates are read from the environment (see the top of `run.sh`);
authentication is key-based.
