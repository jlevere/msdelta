//! `oracle` CLI: drives the differential-testing harness.
//!
//! Subcommands:
//!   gen      --seed <u64> --count <n> --out <dir>   generate a job directory
//!   report   --job <dir>                            score + bucket lab results
//!   minimize --job <dir> --id <case> [--dll d] [--rounds n] [--run path]
//!                                                   shrink a failing case
//!
//! Generation is local and deterministic; the lab round-trip is driven by
//! `lab/run.sh`. `report` reads the pulled-back result.<dll>.json, runs the
//! local decode oracle on the golds, and prints a scored summary + buckets.
//! `minimize` repeatedly batches shrink candidates through the lab to find a
//! small repro of a failing case.

use std::path::Path;
use std::process::{Command, ExitCode};

use oracle::kernel::report::DllResult;
use oracle::kernel::{Direction, Domain, Job};
use oracle::msdelta::minimize::{ours_from_spec, shrink_candidates};
use oracle::msdelta::report::build_report;
use oracle::msdelta::{default_suite, CreateSpec, MsDeltaCase, MsDeltaDomain};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         oracle gen --seed <u64> --count <per-category> --out <dir>\n  \
         oracle report --job <dir>\n"
    );
    ExitCode::FAILURE
}

/// Minimal `--flag value` parser; returns the value for `name` if present.
fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") => cmd_gen(&args[1..]),
        Some("report") => cmd_report(&args[1..]),
        Some("minimize") => cmd_minimize(&args[1..]),
        _ => usage(),
    }
}

/// Run one lab round: build a job of `cases` in `dir`, invoke run.sh for `dll`,
/// and return the set of case ids whose ours_to_native still failed (the
/// reproduce-the-failure predicate).
fn lab_failures(
    run_sh: &str,
    dir: &Path,
    dll: &str,
    cases: &[MsDeltaCase],
) -> Result<std::collections::BTreeSet<String>, String> {
    let _ = std::fs::remove_dir_all(dir);
    MsDeltaDomain
        .build_job(0, cases, dir)
        .map_err(|e| format!("build mini-job: {e}"))?;

    let status = Command::new("bash")
        .arg(run_sh)
        .arg(dir)
        .arg(dll)
        .status()
        .map_err(|e| format!("spawn run.sh: {e}"))?;
    if !status.success() {
        return Err(format!("run.sh exited {status}"));
    }

    let tag = Path::new(dll)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(dll);
    let result = DllResult::read(&dir.join(format!("result.{tag}.json")))
        .map_err(|e| format!("read result: {e}"))?;
    Ok(result
        .results
        .into_iter()
        .filter(|r| {
            r.ours_to_native
                .as_ref()
                .map(|v| v.status != "PASS")
                .unwrap_or(false)
        })
        .map(|r| r.id)
        .collect())
}

fn cmd_minimize(args: &[String]) -> ExitCode {
    let (Some(job_dir), Some(id)) = (arg(args, "--job"), arg(args, "--id")) else {
        return usage();
    };
    let dll = arg(args, "--dll").unwrap_or("msdelta.dll");
    let rounds: usize = arg(args, "--rounds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let run_sh = arg(args, "--run").unwrap_or("crates/oracle/lab/run.sh");
    let job_dir = Path::new(job_dir);

    // Load the failing case's reference, target, and native spec from the job.
    let job: Job<CreateSpec> = match Job::read(job_dir) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("read job: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(case) = job.cases.iter().find(|c| c.id == id) else {
        eprintln!("case id {id:?} not in job");
        return ExitCode::FAILURE;
    };
    let reference = std::fs::read(job_dir.join(&case.reference)).unwrap_or_default();
    let mut current = std::fs::read(job_dir.join(&case.target)).unwrap_or_default();
    let spec = case.native.clone();
    let ours = ours_from_spec(&spec);

    println!(
        "minimizing {id} on {dll}: ref={}B target={}B (up to {rounds} rounds)",
        reference.len(),
        current.len()
    );

    let work = std::env::temp_dir().join(format!("oracle-min-{}", sanitize(id)));
    for round in 0..rounds {
        let candidates = shrink_candidates(&current);
        if candidates.is_empty() {
            println!("round {round}: cannot shrink {}B further", current.len());
            break;
        }
        let cases: Vec<MsDeltaCase> = candidates
            .iter()
            .map(|c| {
                MsDeltaCase::new(
                    format!("cand.{}", c.label),
                    "minimize",
                    reference.clone(),
                    c.target.clone(),
                    ours.clone(),
                    spec.clone(),
                )
                .with_directions(vec![Direction::OursToNative])
            })
            .collect();

        let failing = match lab_failures(run_sh, &work, dll, &cases) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("round {round}: {e}");
                return ExitCode::FAILURE;
            }
        };

        // Pick the smallest still-failing candidate as the next current.
        let smallest = candidates
            .iter()
            .filter(|c| failing.contains(&format!("cand.{}", c.label)))
            .min_by_key(|c| c.target.len());

        match smallest {
            Some(c) => {
                println!(
                    "round {round}: {}/{} candidates still fail; smallest {}B ({})",
                    failing.len(),
                    candidates.len(),
                    c.target.len(),
                    c.label
                );
                current = c.target.clone();
            }
            None => {
                println!(
                    "round {round}: no smaller candidate still fails; {}B is a local minimum",
                    current.len()
                );
                break;
            }
        }
    }

    // Emit the minimized repro alongside the job.
    let ref_out = job_dir.join(format!("{id}.min.ref"));
    let tgt_out = job_dir.join(format!("{id}.min.target"));
    let _ = std::fs::write(&ref_out, &reference);
    let _ = std::fs::write(&tgt_out, &current);
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "minimal repro: ref={}B target={}B\n  {}\n  {}",
        reference.len(),
        current.len(),
        ref_out.display(),
        tgt_out.display()
    );
    ExitCode::SUCCESS
}

/// Make a case id safe to use as a temp directory name.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn cmd_report(args: &[String]) -> ExitCode {
    let Some(job) = arg(args, "--job") else {
        return usage();
    };
    let report = match build_report(Path::new(job)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("report failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "oracle report  domain={}  seed={:#x}",
        report.domain, report.seed
    );
    println!("\nscore (pass/total, skipped excluded):");
    for (key, [pass, total]) in &report.summary {
        let flag = if pass == total { "" } else { "  <--" };
        println!("  {key:42} {pass:>3}/{total:<3}{flag}");
    }

    if report.buckets.is_empty() {
        println!("\nno failures.");
    } else {
        let n: usize = report.buckets.iter().map(|b| b.count).sum();
        println!("\n{n} failures in {} buckets:", report.buckets.len());
        for b in &report.buckets {
            println!("  [{:>2}x] {}", b.count, b.signature);
            println!("        e.g. {}", b.examples.join(", "));
        }
    }

    // Persist the full structured report alongside the job.
    let out = Path::new(job).join("report.json");
    match serde_json::to_vec_pretty(&report) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&out, bytes) {
                eprintln!("warning: could not write {}: {e}", out.display());
            } else {
                println!("\nfull report: {}", out.display());
            }
        }
        Err(e) => eprintln!("warning: serialize report: {e}"),
    }
    ExitCode::SUCCESS
}

fn cmd_gen(args: &[String]) -> ExitCode {
    let seed: u64 = match arg(args, "--seed") {
        Some(s) => match s.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).unwrap_or(0),
            None => s.parse().unwrap_or(0),
        },
        None => 0,
    };
    let count: usize = arg(args, "--count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let Some(out) = arg(args, "--out") else {
        return usage();
    };

    let suite = default_suite(seed, count);
    let dir = std::path::Path::new(out);
    match MsDeltaDomain.build_job(seed, &suite, dir) {
        Ok(job) => {
            println!(
                "wrote {} cases (seed {seed:#x}, {count}/category) to {}",
                job.cases.len(),
                dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gen failed: {e}");
            ExitCode::FAILURE
        }
    }
}
