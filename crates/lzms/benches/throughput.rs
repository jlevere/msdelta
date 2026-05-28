//! Criterion throughput benchmark for the current (greedy) LZMS encoder and
//! decoder, across a deterministic corpus (see `corpus.rs`).
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p lzms
//! ```
//!
//! Criterion reports time per iteration and, via `Throughput::Bytes`, a MB/s
//! figure keyed to the *uncompressed* input size for both encode and decode.
//! Timings can be noisy if another CPU-heavy process is running concurrently;
//! the harness is trivially re-runnable, and the deterministic corpus means
//! compression ratios (reported separately by the `ratio_report` example) do
//! not move between runs.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// The corpus generators live in a sibling file that is *not* its own bench
// target (see Cargo.toml, which registers only this file). Pulling it in with
// `include!` keeps the deterministic generators shared with the example
// without adding a module to the crate's `src/`.
include!("corpus.rs");

fn bench_encode(c: &mut Criterion) {
    let corpus = corpus();
    let mut group = c.benchmark_group("encode");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    for sample in &corpus {
        group.throughput(Throughput::Bytes(sample.data.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(sample.name),
            &sample.data,
            |b, data| {
                b.iter(|| lzms::compress(std::hint::black_box(data)).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let corpus = corpus();
    let mut group = c.benchmark_group("decode");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    for sample in &corpus {
        let compressed = lzms::compress(&sample.data).unwrap();
        let out_len = sample.data.len();
        group.throughput(Throughput::Bytes(sample.data.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(sample.name),
            &compressed,
            |b, comp| {
                b.iter(|| lzms::decompress(std::hint::black_box(comp), out_len).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
