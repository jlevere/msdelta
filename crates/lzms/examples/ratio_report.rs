//! Deterministic compression-ratio report for the current LZMS encoder.
//!
//! Unlike the criterion timing harness, ratios are noise-free: the corpus is
//! generated from a fixed seed and the encoder is deterministic, so these
//! numbers are reproducible across runs and machines. Run with:
//!
//! ```sh
//! cargo run -p lzms --release --example ratio_report
//! ```

include!("../benches/corpus.rs");

fn main() {
    println!(
        "{:<24} {:>12} {:>12} {:>8}",
        "corpus", "input", "compressed", "ratio"
    );
    println!("{}", "-".repeat(58));

    let mut total_in = 0usize;
    let mut total_out = 0usize;

    for sample in corpus() {
        let compressed = lzms::compress(&sample.data).expect("compress");
        // Sanity: confirm the encoder/decoder round-trips this input, so the
        // reported sizes correspond to a genuinely decodable stream.
        let recovered = lzms::decompress(&compressed, sample.data.len()).expect("decompress");
        assert_eq!(recovered, sample.data, "{} did not round-trip", sample.name);

        let ratio = compressed.len() as f64 / sample.data.len() as f64;
        println!(
            "{:<24} {:>12} {:>12} {:>8.4}",
            sample.name,
            sample.data.len(),
            compressed.len(),
            ratio
        );
        total_in += sample.data.len();
        total_out += compressed.len();
    }

    println!("{}", "-".repeat(58));
    println!(
        "{:<24} {:>12} {:>12} {:>8.4}",
        "TOTAL",
        total_in,
        total_out,
        total_out as f64 / total_in as f64
    );
}
