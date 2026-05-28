// Deterministic benchmark corpus shared by the criterion harness and the
// ratio-report example. Included via `include!`, not compiled as its own
// crate, so every generator must be self-contained and seeded with a fixed
// constant (no entropy, no clock) to keep results reproducible across runs.

/// A single named corpus input.
pub struct Sample {
    pub name: &'static str,
    pub data: Vec<u8>,
}

/// A tiny deterministic xorshift64* PRNG. Seeded with a fixed constant so the
/// "random" corpus is byte-for-byte identical on every run and machine.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state, which xorshift cannot escape.
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }
}

/// Roughly 64 KiB of each kind. Big enough to amortize per-call setup and to
/// trigger several adaptive-code rebuilds, small enough to keep the suite fast
/// and to stay within a single container chunk.
const TARGET_LEN: usize = 64 * 1024;

/// English-ish prose: a fixed word list emitted in a deterministic pseudo
/// random order with spaces and occasional punctuation. Exercises the literal
/// path and short back-references heavily.
fn english() -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "and", "then", "runs",
        "away", "into", "forest", "where", "ancient", "trees", "grow", "tall", "under", "silver",
        "moon", "while", "rivers", "flow", "gently", "toward", "distant", "sea", "carrying",
        "leaves", "from", "autumn", "branches", "down", "stream", "past", "villages", "asleep",
        "beneath", "stars", "that", "shine", "above", "quiet", "fields", "of", "golden", "wheat",
    ];
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    let mut out = Vec::with_capacity(TARGET_LEN + 16);
    let mut sentence_words = 0u32;
    while out.len() < TARGET_LEN {
        let w = WORDS[(rng.next_u64() as usize) % WORDS.len()];
        out.extend_from_slice(w.as_bytes());
        sentence_words += 1;
        if sentence_words >= 8 && (rng.next_u64() & 3) == 0 {
            out.push(b'.');
            out.push(b'\n');
            sentence_words = 0;
        } else {
            out.push(b' ');
        }
    }
    out.truncate(TARGET_LEN);
    out
}

/// Pseudo-random, effectively incompressible bytes. The encoder should fall
/// back to mostly literals; ratio near 1.0 is expected. Exercises the
/// incompressible-fallback decision and worst-case literal throughput.
fn random() -> Vec<u8> {
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);
    (0..TARGET_LEN).map(|_| rng.next_u8()).collect()
}

/// Highly repetitive: long constant runs interleaved with short repeating
/// motifs. Should collapse to a handful of long matches; exercises the
/// long-match / repeat-offset paths and the best-case ratio.
fn repetitive() -> Vec<u8> {
    let mut out = Vec::with_capacity(TARGET_LEN + 16);
    let mut fill = 0u8;
    while out.len() < TARGET_LEN {
        // A long constant run.
        out.extend(std::iter::repeat_n(fill, 4096));
        // A short repeating motif copied many times.
        let motif: [u8; 8] = [fill, b'A', b'B', fill, b'C', b'D', fill, b'E'];
        for _ in 0..256 {
            out.extend_from_slice(&motif);
        }
        fill = fill.wrapping_add(7);
    }
    out.truncate(TARGET_LEN);
    out
}

/// Strided / arithmetic data: a low-degree polynomial sampled over a stride,
/// which produces a constant byte-wise difference pattern and is the textbook
/// case for delta matches.
fn strided() -> Vec<u8> {
    (0..TARGET_LEN as u32)
        .map(|i| {
            // Quadratic-ish so the first difference is itself linear, giving
            // delta matches at more than one power something to bite on.
            (i.wrapping_mul(3).wrapping_add(i >> 4).wrapping_add(7)) as u8
        })
        .collect()
}

/// A manifest-like XML blob resembling a WinSxS component manifest. This is the
/// crate's primary real-world workload: highly structured, repetitive tag and
/// attribute names with varying values. Built deterministically.
fn manifest_xml() -> Vec<u8> {
    let mut rng = Rng::new(0x0F0F_0F0F_1357_9BDF);
    let mut out = Vec::with_capacity(TARGET_LEN + 512);
    out.extend_from_slice(
        b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
          <assembly xmlns=\"urn:schemas-microsoft-com:asm.v3\" manifestVersion=\"1.0\">\n",
    );
    const ARCHS: &[&str] = &["amd64", "x86", "wow64", "arm64"];
    const NAMES: &[&str] = &[
        "Microsoft-Windows-Foo",
        "Microsoft-Windows-Bar-Component",
        "Microsoft-Windows-Networking-Service",
        "Microsoft-Windows-Shell-Experience",
        "Package_for_KB",
    ];
    let mut idx = 0u32;
    while out.len() < TARGET_LEN {
        let name = NAMES[(rng.next_u64() as usize) % NAMES.len()];
        let arch = ARCHS[(rng.next_u64() as usize) % ARCHS.len()];
        let ver_a = 10;
        let ver_b = rng.next_u64() % 65536;
        let ver_c = rng.next_u64() % 65536;
        let token = rng.next_u64();
        out.extend_from_slice(b"  <assemblyIdentity name=\"");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"\" version=\"");
        out.extend_from_slice(format!("{ver_a}.0.{ver_b}.{ver_c}").as_bytes());
        out.extend_from_slice(b"\" processorArchitecture=\"");
        out.extend_from_slice(arch.as_bytes());
        out.extend_from_slice(b"\" language=\"neutral\" publicKeyToken=\"");
        out.extend_from_slice(format!("{token:016x}").as_bytes());
        out.extend_from_slice(b"\" />\n");
        out.extend_from_slice(b"  <file name=\"component.dll\" hash=\"");
        out.extend_from_slice(format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64()).as_bytes());
        out.extend_from_slice(b"\" hashalg=\"SHA256\">\n");
        out.extend_from_slice(b"    <asmv2:hash xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\">\n");
        out.extend_from_slice(b"      <dsig:Transforms><dsig:Transform Algorithm=\"urn:schemas-microsoft-com:HashTransforms.Identity\" /></dsig:Transforms>\n");
        out.extend_from_slice(b"    </asmv2:hash>\n  </file>\n");
        idx += 1;
        if idx % 8 == 0 {
            out.extend_from_slice(b"  <!-- registry keys and dependencies follow -->\n");
        }
    }
    out.extend_from_slice(b"</assembly>\n");
    out.truncate(TARGET_LEN);
    out
}

/// Build the full corpus. Deterministic and allocation-cheap; safe to call
/// once per benchmark group.
pub fn corpus() -> Vec<Sample> {
    vec![
        Sample {
            name: "english_text",
            data: english(),
        },
        Sample {
            name: "random_incompressible",
            data: random(),
        },
        Sample {
            name: "repetitive_runs",
            data: repetitive(),
        },
        Sample {
            name: "strided_delta",
            data: strided(),
        },
        Sample {
            name: "manifest_xml",
            data: manifest_xml(),
        },
    ]
}
