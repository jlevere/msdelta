//! Deterministic case generators for the PA30-delta domain.
//!
//! Each generator implements [`Generator<MsDeltaCase>`] and is a pure function
//! of its seed. Categories cover the artifact classes whose native reference
//! is `msdelta.dll` / `UpdateCompression.dll`:
//!
//! - [`RandomGen`] — incompressible / arbitrary byte pairs.
//! - [`TextGen`] — line-structured text with realistic edits.
//! - [`FuzzDerivedGen`] — a buffer with runs, mutated by insert/delete/overwrite.
//! - [`ManifestPairGen`] — real WinSxS base -> decoded-manifest pairs (the
//!   crate's primary use; where the complex-mode Huffman bug lives).
//! - [`PePairGen`] — cross-version and cross-binary PE pairs.
//! - [`CorpusReplayGen`] — the legacy curated 12-case corpus, so the oracle
//!   subsumes it (incl. bsdiff / MD5 / SHA-256 / PA31 variants).
//!
//! WIM/ESD is intentionally absent: its native reference is `wimgapi`, a
//! separate [`Domain`](crate::kernel::Domain), not msdelta.

use std::fs;
use std::path::PathBuf;

use msdelta::pa30::{Codec, CreateOptions, FileType, FormatVersion, HASH_ALG_MD5, HASH_ALG_SHA256};

use crate::kernel::rng::{derive_seed, SplitMix64};
use crate::kernel::{Direction, Generator};

use super::{CreateSpec, MsDeltaCase};

/// Path to the dev-checkout fixtures (excluded from the published crate, but
/// present in a git tree). Relative to this crate's manifest dir.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    fs::read(fixtures_dir().join(name)).ok()
}

/// PE source binaries live one level down, under `deltas/sources/`.
fn read_source(name: &str) -> Option<Vec<u8>> {
    fs::read(fixtures_dir().join("deltas/sources").join(name)).ok()
}

// --- generic mutation helpers ------------------------------------------------

fn fresh_bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill(&mut v);
    v
}

/// A buffer alternating single-byte runs and random spans (compressible, with
/// match opportunities).
fn build_runs(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        if rng.chance(1, 2) {
            let b = rng.next_u64() as u8;
            let n = rng.range(1, 64);
            out.extend(std::iter::repeat_n(b, n));
        } else {
            let n = rng.range(1, 64);
            out.extend(fresh_bytes(rng, n));
        }
    }
    out.truncate(len);
    out
}

/// Light byte-level mutation: a few XOR flips plus an optional appended tail.
fn mutate_bytes(rng: &mut SplitMix64, src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    let edits = rng.range(1, (src.len() / 32).max(1));
    for _ in 0..edits {
        if out.is_empty() {
            break;
        }
        let pos = rng.below(out.len());
        out[pos] ^= (rng.next_u64() as u8) | 1;
    }
    if rng.chance(1, 3) {
        let n = rng.range(1, 64);
        let tail = fresh_bytes(rng, n);
        out.extend(tail);
    }
    out
}

/// Structural edits: random insert / delete / overwrite of spans.
fn structural_edits(rng: &mut SplitMix64, src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    let edits = rng.range(1, 8);
    for _ in 0..edits {
        if out.is_empty() {
            let n = rng.range(1, 32);
            out = fresh_bytes(rng, n);
            continue;
        }
        match rng.below(3) {
            0 => {
                let pos = rng.below(out.len());
                let n = rng.range(1, 32);
                let ins = fresh_bytes(rng, n);
                out.splice(pos..pos, ins);
            }
            1 => {
                let pos = rng.below(out.len());
                let n = rng.range(1, 32).min(out.len() - pos);
                out.drain(pos..pos + n);
            }
            _ => {
                let pos = rng.below(out.len());
                let n = rng.range(1, 32).min(out.len() - pos);
                for b in &mut out[pos..pos + n] {
                    *b ^= 0xFF;
                }
            }
        }
    }
    out
}

const WORDS: &[&str] = &[
    "the",
    "quick",
    "brown",
    "fox",
    "jumps",
    "over",
    "lazy",
    "dog",
    "component",
    "manifest",
    "assembly",
    "registry",
    "value",
    "boolean",
    "string",
    "version",
    "deployment",
    "display",
    "name",
    "true",
    "false",
    "unsignedInt",
    "multiString",
    "key",
    "local",
    "machine",
];

fn build_text(rng: &mut SplitMix64, lines: usize) -> Vec<u8> {
    let mut s = String::new();
    for _ in 0..lines {
        let wc = rng.range(4, 12);
        for w in 0..wc {
            if w > 0 {
                s.push(' ');
            }
            s.push_str(WORDS[rng.below(WORDS.len())]);
        }
        s.push('\n');
    }
    s.into_bytes()
}

fn mutate_text(rng: &mut SplitMix64, src: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(src);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let edits = rng.range(1, (lines.len() / 4).max(1));
    for _ in 0..edits {
        if lines.is_empty() {
            lines.push("a freshly inserted line of content".into());
            continue;
        }
        let idx = rng.below(lines.len());
        match rng.below(3) {
            0 => {
                let wc = rng.range(4, 12);
                let mut nl = String::new();
                for w in 0..wc {
                    if w > 0 {
                        nl.push(' ');
                    }
                    nl.push_str(WORDS[rng.below(WORDS.len())]);
                }
                lines[idx] = nl;
            }
            1 => lines.insert(idx, "a freshly inserted line of content".into()),
            _ => {
                lines.remove(idx);
            }
        }
    }
    lines.join("\n").into_bytes()
}

// --- generators --------------------------------------------------------------

/// Arbitrary / incompressible byte pairs.
pub struct RandomGen;

impl Generator<MsDeltaCase> for RandomGen {
    fn category(&self) -> &str {
        "random"
    }
    fn generate(&self, seed: u64, count: usize) -> Vec<MsDeltaCase> {
        let mut rng = SplitMix64::new(derive_seed(seed, self.category()));
        (0..count)
            .map(|i| {
                let n = rng.range(16, 8192);
                let reference = fresh_bytes(&mut rng, n);
                let target = if rng.chance(1, 2) {
                    mutate_bytes(&mut rng, &reference)
                } else {
                    let m = rng.range(16, 8192);
                    fresh_bytes(&mut rng, m)
                };
                MsDeltaCase::raw(format!("random.{i:04}"), self.category(), reference, target)
            })
            .collect()
    }
}

/// Line-structured text with realistic edits.
pub struct TextGen;

impl Generator<MsDeltaCase> for TextGen {
    fn category(&self) -> &str {
        "text"
    }
    fn generate(&self, seed: u64, count: usize) -> Vec<MsDeltaCase> {
        let mut rng = SplitMix64::new(derive_seed(seed, self.category()));
        (0..count)
            .map(|i| {
                let lines = rng.range(8, 200);
                let reference = build_text(&mut rng, lines);
                let target = mutate_text(&mut rng, &reference);
                MsDeltaCase::raw(format!("text.{i:04}"), self.category(), reference, target)
            })
            .collect()
    }
}

/// A buffer with runs, mutated structurally — stresses copy/insert encoding.
pub struct FuzzDerivedGen;

impl Generator<MsDeltaCase> for FuzzDerivedGen {
    fn category(&self) -> &str {
        "fuzz_derived"
    }
    fn generate(&self, seed: u64, count: usize) -> Vec<MsDeltaCase> {
        let mut rng = SplitMix64::new(derive_seed(seed, self.category()));
        (0..count)
            .map(|i| {
                let len = rng.range(64, 16384);
                let reference = build_runs(&mut rng, len);
                let target = structural_edits(&mut rng, &reference);
                MsDeltaCase::raw(
                    format!("fuzz_derived.{i:04}"),
                    self.category(),
                    reference,
                    target,
                )
            })
            .collect()
    }
}

/// Real WinSxS base -> decoded-manifest pairs. Skips cleanly if fixtures are
/// absent (e.g. a published-crate checkout).
pub struct ManifestPairGen;

impl Generator<MsDeltaCase> for ManifestPairGen {
    fn category(&self) -> &str {
        "manifest_pair"
    }
    fn generate(&self, _seed: u64, count: usize) -> Vec<MsDeltaCase> {
        let Some(base) = read_fixture("base_manifest.bin") else {
            return Vec::new();
        };
        let dir = fixtures_dir();
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension().and_then(|x| x.to_str()) == Some("manifest"))
                    .then(|| p.file_name()?.to_str().map(str::to_string))
                    .flatten()
            })
            .collect();
        names.sort(); // deterministic order

        let mut cases = Vec::new();
        for name in names.into_iter().take(count) {
            let Some(dcm) = read_fixture(&name) else {
                continue;
            };
            // DCM\x01 wrapper -> PA30 -> apply against the base to recover XML.
            let Ok(pa30) = msdelta::dcm::strip(&dcm) else {
                continue;
            };
            let Ok(xml) = msdelta::pa30::apply(&base, pa30) else {
                continue;
            };
            // A short, stable id from the leading component of the name.
            let short = name.split('_').next().unwrap_or("manifest");
            let id = format!("manifest_pair.{}.{:04}", short, cases.len());
            cases.push(MsDeltaCase::raw(id, self.category(), base.clone(), xml));
        }
        cases
    }
}

/// Cross-version (same binary) and cross-binary PE pairs.
pub struct PePairGen;

impl Generator<MsDeltaCase> for PePairGen {
    fn category(&self) -> &str {
        "pe_pair"
    }
    fn generate(&self, _seed: u64, count: usize) -> Vec<MsDeltaCase> {
        // (id, ref-file, target-file, executable?) — same-binary cross-version
        // uses the PE transform; cross-binary stays raw (no shared structure).
        let specs: &[(&str, &str, &str, bool)] = &[
            ("cmd_selfpatch", "cmd.exe", "cmd_patched.exe", true),
            (
                "advapi32_xver",
                "advapi32_old.dll",
                "advapi32_new.dll",
                true,
            ),
            ("cmd_to_where_raw", "cmd.exe", "where.exe", false),
            ("cmd_to_notepad_raw", "cmd.exe", "notepad.exe", false),
        ];
        specs
            .iter()
            .take(count)
            .filter_map(|&(id, rf, tf, is_exe)| {
                let reference = read_source(rf)?;
                let target = read_source(tf)?;
                let id = format!("pe_pair.{id}");
                Some(if is_exe {
                    MsDeltaCase::executables(id, self.category(), reference, target)
                } else {
                    MsDeltaCase::raw(id, self.category(), reference, target)
                })
            })
            .collect()
    }
}

/// The legacy curated corpus, so the oracle fully subsumes it.
pub struct CorpusReplayGen;

impl Generator<MsDeltaCase> for CorpusReplayGen {
    fn category(&self) -> &str {
        "corpus_replay"
    }
    fn generate(&self, _seed: u64, _count: usize) -> Vec<MsDeltaCase> {
        let cat = self.category();
        let ref_text =
            b"Hello, this is a reference buffer with some repeated content. Hello again! \
            The quick brown fox jumps over the lazy dog. Repeated content repeated content."
                .to_vec();
        let tgt_text =
            b"Hello, this is a MODIFIED buffer with some repeated content. Goodbye now! \
            The quick brown fox jumps over the lazy cat. Repeated content repeated content."
                .to_vec();

        // A larger, compressible body to exercise multi-segment LZX.
        let big_ref: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let mut big_tgt = big_ref.clone();
        for chunk in big_tgt.chunks_mut(4096) {
            if let Some(b) = chunk.get_mut(17) {
                *b ^= 0xAA;
            }
        }
        big_tgt.extend_from_slice(b"appended tail region not present in the reference buffer");

        // OursToNative + OursToOurs only: these exercise whether the genuine
        // DLL *accepts our delta*, where there is no clean documented
        // CreateDeltaB flag to make the DLL emit the same variant (PA31), or
        // where create is only meaningful on one DLL.
        let apply_only = vec![Direction::OursToNative, Direction::OursToOurs];

        let mut cases = vec![
            MsDeltaCase::raw("corpus.text_lzx", cat, ref_text.clone(), tgt_text.clone()),
            MsDeltaCase::new(
                "corpus.text_bsdiff",
                cat,
                ref_text.clone(),
                tgt_text.clone(),
                CreateOptions::new().codec(Codec::BsDiff),
                // bsdiff == LZX patch + SetFlags 0x100 (no distinct codec).
                CreateSpec::raw().with_set_flags(0x100),
            ),
            MsDeltaCase::new(
                "corpus.text_md5",
                cat,
                ref_text.clone(),
                tgt_text.clone(),
                CreateOptions::new().hash_algorithm(HASH_ALG_MD5),
                CreateSpec::raw().with_hash(HASH_ALG_MD5),
            ),
            MsDeltaCase::new(
                "corpus.text_sha256",
                cat,
                ref_text.clone(),
                tgt_text.clone(),
                CreateOptions::new().hash_algorithm(HASH_ALG_SHA256),
                CreateSpec::raw().with_hash(HASH_ALG_SHA256),
            ),
            MsDeltaCase::new(
                "corpus.text_pa31",
                cat,
                ref_text.clone(),
                tgt_text.clone(),
                CreateOptions::new().version(FormatVersion::PA31),
                CreateSpec::raw(),
            )
            .with_directions(apply_only.clone()),
            MsDeltaCase::raw("corpus.bigtext_lzx", cat, big_ref.clone(), big_tgt.clone()),
            MsDeltaCase::new(
                "corpus.bigtext_bsdiff",
                cat,
                big_ref,
                big_tgt,
                CreateOptions::new().codec(Codec::BsDiff),
                CreateSpec::raw().with_set_flags(0x100),
            ),
            MsDeltaCase::raw("corpus.identical", cat, ref_text.clone(), ref_text.clone()),
            MsDeltaCase::raw("corpus.empty_target", cat, ref_text, Vec::new()),
        ];

        // PE corpus cases, if the fixtures are present.
        if let (Some(cmd), Some(cmd_patched)) =
            (read_source("cmd.exe"), read_source("cmd_patched.exe"))
        {
            cases.push(MsDeltaCase::executables(
                "corpus.pe_cmd_amd64",
                cat,
                cmd.clone(),
                cmd_patched.clone(),
            ));
            cases.push(
                MsDeltaCase::new(
                    "corpus.pe_cmd_amd64_pa31",
                    cat,
                    cmd,
                    cmd_patched,
                    CreateOptions::new()
                        .file_type(FileType::Auto)
                        .version(FormatVersion::PA31),
                    CreateSpec::executables(),
                )
                .with_directions(apply_only),
            );
        }
        if let (Some(old), Some(new)) = (
            read_source("advapi32_old.dll"),
            read_source("advapi32_new.dll"),
        ) {
            cases.push(MsDeltaCase::executables(
                "corpus.pe_advapi32",
                cat,
                old,
                new,
            ));
        }
        cases
    }
}

/// Decode-completeness sweep: a few representative inputs run through the FULL
/// genuine `CreateDeltaB` mode matrix, so our decoder is tested against every
/// format variant the genuine encoder can emit. Directions emphasize
/// native_to_ours (genuine create -> our decode) plus the control.
///
/// Mode space (grounded in msdelta.dll): file_type_set {raw, executables} x
/// hash {none, md5, sha256} x set_flags {0, 0x100 "bsdiff"}. Unsupported combos
/// (e.g. sha256 on msdelta.dll) simply ERROR on create -> decode skipped; they
/// succeed on UpdateCompression, so the sweep covers what each DLL emits.
pub struct CreateModeSweepGen;

impl Generator<MsDeltaCase> for CreateModeSweepGen {
    fn category(&self) -> &str {
        "create_mode_sweep"
    }
    fn generate(&self, seed: u64, _count: usize) -> Vec<MsDeltaCase> {
        let mut rng = SplitMix64::new(derive_seed(seed, self.category()));
        // Representative inputs: structured text, a real manifest pair (if
        // present), and a buffer with runs. Kept modest so the unused ours
        // encode during lowering stays cheap.
        let mut inputs: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let r = build_text(&mut rng, 60);
            let t = mutate_text(&mut rng, &r);
            inputs.push(("text".into(), r, t));
        }
        {
            let r = build_runs(&mut rng, 4096);
            let t = structural_edits(&mut rng, &r);
            inputs.push(("runs".into(), r, t));
        }
        if let Some(base) = read_fixture("base_manifest.bin") {
            // The smallest real manifest, decoded, as a realistic raw target.
            if let Some(dcm) = read_fixture(
                "amd64_microsoft-windows-font-truetype-gadugi_31bf3856ad364e35_10.0.26100.1_none_e1326a4c8dcc8ee1.manifest",
            ) {
                if let Some(xml) = msdelta::dcm::strip(&dcm)
                    .ok()
                    .and_then(|p| msdelta::pa30::apply(&base, p).ok())
                {
                    inputs.push(("manifest".into(), base, xml));
                }
            }
        }

        // (label, ours options, genuine CreateDeltaB spec)
        let modes: Vec<(&str, CreateOptions, CreateSpec)> = vec![
            ("raw_lzx", CreateOptions::new(), CreateSpec::raw()),
            (
                "raw_bsdiff",
                CreateOptions::new().codec(Codec::BsDiff),
                CreateSpec::raw().with_set_flags(0x100),
            ),
            (
                "raw_md5",
                CreateOptions::new().hash_algorithm(HASH_ALG_MD5),
                CreateSpec::raw().with_hash(HASH_ALG_MD5),
            ),
            (
                "raw_sha256",
                CreateOptions::new().hash_algorithm(HASH_ALG_SHA256),
                CreateSpec::raw().with_hash(HASH_ALG_SHA256),
            ),
        ];

        let decode_dirs = vec![Direction::NativeToOurs, Direction::NativeToNative];
        let mut cases = Vec::new();
        for (iname, reference, target) in &inputs {
            for (mname, ours, native) in &modes {
                cases.push(
                    MsDeltaCase::new(
                        format!("create_mode_sweep.{iname}.{mname}"),
                        self.category(),
                        reference.clone(),
                        target.clone(),
                        ours.clone(),
                        native.clone(),
                    )
                    .with_directions(decode_dirs.clone()),
                );
            }
        }
        cases
    }
}

/// Reverse-delta cases: representative raw inputs run through the genuine
/// ApplyDeltaGetReverseB round-trip (and our reverse delta checked too). Raw
/// only -- reverse of PE/hash variants is out of scope for now.
pub struct ReverseGen;

impl Generator<MsDeltaCase> for ReverseGen {
    fn category(&self) -> &str {
        "reverse"
    }
    fn generate(&self, seed: u64, _count: usize) -> Vec<MsDeltaCase> {
        let mut rng = SplitMix64::new(derive_seed(seed, self.category()));
        let dirs = vec![Direction::ReverseRoundTrip, Direction::OursToOurs];
        let mut cases = Vec::new();

        let rt = build_text(&mut rng, 80);
        let tt = mutate_text(&mut rng, &rt);
        cases.push(
            MsDeltaCase::raw("reverse.text", "reverse", rt, tt).with_directions(dirs.clone()),
        );

        let rr = build_runs(&mut rng, 8192);
        let tr = structural_edits(&mut rng, &rr);
        cases.push(
            MsDeltaCase::raw("reverse.runs", "reverse", rr, tr).with_directions(dirs.clone()),
        );

        if let Some(base) = read_fixture("base_manifest.bin") {
            if let Some(dcm) = read_fixture(
                "amd64_dual_netvg63a.inf_31bf3856ad364e35_10.0.26100.1_none_9162a10543917fc7.manifest",
            ) {
                if let Some(xml) = msdelta::dcm::strip(&dcm)
                    .ok()
                    .and_then(|p| msdelta::pa30::apply(&base, p).ok())
                {
                    cases.push(
                        MsDeltaCase::raw("reverse.manifest", "reverse", base, xml)
                            .with_directions(dirs),
                    );
                }
            }
        }
        cases
    }
}

/// Generate a full suite from one seed: `per_category` cases from each
/// procedural generator, plus all fixture-backed, corpus, and mode-sweep cases.
pub fn default_suite(seed: u64, per_category: usize) -> Vec<MsDeltaCase> {
    let mut cases = Vec::new();
    cases.extend(RandomGen.generate(seed, per_category));
    cases.extend(TextGen.generate(seed, per_category));
    cases.extend(FuzzDerivedGen.generate(seed, per_category));
    cases.extend(ManifestPairGen.generate(seed, per_category));
    cases.extend(PePairGen.generate(seed, per_category));
    cases.extend(CorpusReplayGen.generate(seed, per_category));
    cases.extend(CreateModeSweepGen.generate(seed, per_category));
    cases.extend(ReverseGen.generate(seed, per_category));
    cases
}
