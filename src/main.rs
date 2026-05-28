//! `msdelta` command-line interface.
//!
//! A thin wrapper over the `msdelta` library: read and write Microsoft MSDelta
//! (PA30/PA31/PA19) binary patches, including the DCM wrapper used for Windows
//! component manifests. Gated behind the `cli` feature so library-only
//! consumers can drop the clap/anyhow dependencies.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use msdelta::pa30::{self, Codec, CreateOptions, FileType, FormatVersion};
use msdelta::pa30::{HASH_ALG_MD5, HASH_ALG_NONE, HASH_ALG_SHA256};
use msdelta::{dcm, pa19};

/// Read and write Microsoft MSDelta (PA30/PA31/PA19) binary patches.
///
/// Deltas are detected automatically: a DCM-wrapped Windows manifest, a raw
/// PA30/PA31 delta, or a legacy PA19 patch all work without extra flags.
#[derive(Debug, Parser)]
#[command(name = "msdelta", version, about, long_about = None)]
#[command(arg_required_else_help = true, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Apply a delta to a reference buffer, producing the target.
    ///
    /// The delta may be a raw PA30/PA31/PA19 buffer or a DCM-wrapped manifest;
    /// the wrapper and format are detected automatically.
    Apply(ApplyArgs),

    /// Decompress DCM-wrapped WinSxS manifests, resolving the base manifest
    /// automatically.
    ///
    /// The base every manifest is delta-encoded against lives inside
    /// `wcp.dll`. With no `--base`/`--wcp-dll`, the base is taken from the
    /// cache, or extracted from the local system `wcp.dll` and cached for
    /// next time. The base is build-specific: when decoding manifests from a
    /// different Windows build than this host, point `--wcp-dll` at that
    /// build's `wcp.dll` (e.g. from its servicing-stack component).
    Decompress(DecompressArgs),

    /// Create a PA30 delta that transforms the reference into the target.
    Create(CreateArgs),

    /// Apply a delta and also emit the reverse delta (target -> reference).
    Reverse(ReverseArgs),

    /// Compute the hash/signature of a buffer.
    Signature(SignatureArgs),

    /// Print the header of a delta.
    Info(InfoArgs),

    /// Generate a shell completion script (write it to your completions dir).
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Reference (base) buffer the delta was built against.
    reference: PathBuf,

    /// Delta to apply (raw PA30/PA31/PA19 or DCM-wrapped).
    delta: PathBuf,

    /// Write the reconstructed target here (default: stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DecompressArgs {
    /// One or more DCM-wrapped `.manifest` files.
    #[arg(required = true)]
    manifests: Vec<PathBuf>,

    /// Use this pre-extracted base manifest directly (skips all resolution).
    #[arg(long, conflicts_with = "wcp_dll")]
    base: Option<PathBuf>,

    /// Extract the base from this `wcp.dll` (and cache it for reuse).
    #[arg(long)]
    wcp_dll: Option<PathBuf>,

    /// Write decompressed XML here. Only valid with a single manifest;
    /// otherwise each manifest is written next to itself as `<name>.xml`.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Re-extract from a `wcp.dll` even if a cached base exists.
    #[arg(long)]
    no_cache: bool,
}

#[derive(Debug, Args)]
struct CreateArgs {
    /// Reference (base) buffer.
    reference: PathBuf,

    /// Target buffer to encode against the reference.
    target: PathBuf,

    /// Write the delta here (default: stdout, if not a terminal).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Target-integrity hash embedded in the delta.
    #[arg(long, value_enum, default_value_t = HashAlg::None)]
    hash: HashAlg,

    /// Compression codec.
    #[arg(long, value_enum, default_value_t = CodecArg::Lzx)]
    codec: CodecArg,

    /// File type. `auto` detects a PE and applies executable preprocessing.
    #[arg(long = "type", value_enum, default_value_t = FileTypeArg::Raw)]
    file_type: FileTypeArg,

    /// Emit a PA31 delta instead of PA30.
    #[arg(long)]
    pa31: bool,

    /// Wrap the output in a DCM container.
    #[arg(long)]
    dcm: bool,
}

#[derive(Debug, Args)]
struct ReverseArgs {
    /// Reference (base) buffer the delta was built against.
    reference: PathBuf,

    /// Forward delta to apply (raw PA30/PA31 or DCM-wrapped).
    delta: PathBuf,

    /// Write the reverse delta here (default: stdout, if not a terminal).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Also write the reconstructed forward target to this path.
    #[arg(long)]
    target: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SignatureArgs {
    /// File to hash.
    file: PathBuf,

    /// Hash algorithm.
    #[arg(long, value_enum, default_value_t = SigHash::Sha256)]
    hash: SigHash,

    /// Zero volatile PE fields (timestamps, checksums) before hashing, for a
    /// signature that is stable across rebuilds.
    #[arg(long)]
    normalize: bool,
}

#[derive(Debug, Args)]
struct InfoArgs {
    /// Delta to inspect (raw PA30/PA31/PA19 or DCM-wrapped).
    delta: PathBuf,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_enum)]
    shell: Shell,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HashAlg {
    None,
    Md5,
    Sha256,
}

impl HashAlg {
    fn id(self) -> u32 {
        match self {
            HashAlg::None => HASH_ALG_NONE,
            HashAlg::Md5 => HASH_ALG_MD5,
            HashAlg::Sha256 => HASH_ALG_SHA256,
        }
    }
}

/// Hash algorithms valid for `signature` (a real digest is required).
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SigHash {
    Md5,
    Sha256,
}

impl SigHash {
    fn id(self) -> u32 {
        match self {
            SigHash::Md5 => HASH_ALG_MD5,
            SigHash::Sha256 => HASH_ALG_SHA256,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CodecArg {
    Lzx,
    Bsdiff,
}

impl From<CodecArg> for Codec {
    fn from(c: CodecArg) -> Self {
        match c {
            CodecArg::Lzx => Codec::PseudoLzx,
            CodecArg::Bsdiff => Codec::BsDiff,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FileTypeArg {
    Raw,
    Auto,
}

impl From<FileTypeArg> for FileType {
    fn from(t: FileTypeArg) -> Self {
        match t {
            FileTypeArg::Raw => FileType::Raw,
            FileTypeArg::Auto => FileType::Auto,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Apply(args) => cmd_apply(args),
        Command::Decompress(args) => cmd_decompress(args),
        Command::Create(args) => cmd_create(args),
        Command::Reverse(args) => cmd_reverse(args),
        Command::Signature(args) => cmd_signature(args),
        Command::Info(args) => cmd_info(args),
        Command::Completions(args) => cmd_completions(args),
    }
}

fn cmd_apply(args: ApplyArgs) -> Result<()> {
    let reference = read(&args.reference)?;
    let raw = read(&args.delta)?;
    let inner = strip_dcm(&raw)?;

    let target = if inner.starts_with(pa19::MAGIC) {
        pa19::apply(&reference, inner).context("applying PA19 patch")?
    } else {
        pa30::apply(&reference, inner).context("applying PA30 delta")?
    };

    // A reconstructed target is frequently text (e.g. a WinSxS manifest), so
    // piping to a terminal is reasonable here; don't guard it.
    write_out(args.output.as_deref(), &target)
}

fn cmd_decompress(args: DecompressArgs) -> Result<()> {
    if args.output.is_some() && args.manifests.len() > 1 {
        bail!("--output is only valid with a single manifest; omit it to write <name>.xml beside each input");
    }

    let base = resolve_base(&args)?;

    for manifest in &args.manifests {
        let raw = read(manifest)?;
        let xml = msdelta::winsxs::decompress(&base, &raw)
            .with_context(|| format!("decompressing {}", manifest.display()))?;

        if !msdelta::winsxs::looks_like_manifest(&xml) {
            eprintln!(
                "warning: {} did not decode to well-formed manifest XML; \
                 the base may not match this manifest's Windows build",
                manifest.display()
            );
        }

        match (&args.output, args.manifests.len()) {
            (Some(out), _) => {
                std::fs::write(out, &xml).with_context(|| format!("writing {}", out.display()))?;
                eprintln!("wrote {}", out.display());
            }
            (None, 1) => write_out(None, &xml)?,
            (None, _) => {
                let out = manifest.with_extension("xml");
                std::fs::write(&out, &xml).with_context(|| format!("writing {}", out.display()))?;
                eprintln!("wrote {}", out.display());
            }
        }
    }
    Ok(())
}

/// Resolve the base manifest for `decompress`, in priority order:
/// explicit `--base`, extraction from `--wcp-dll`, the on-disk cache, then the
/// local system `wcp.dll`. Every filesystem action is logged to stderr.
fn resolve_base(args: &DecompressArgs) -> Result<Vec<u8>> {
    if let Some(path) = &args.base {
        eprintln!("base: using {}", path.display());
        return read(path);
    }

    if let Some(dll) = &args.wcp_dll {
        return extract_and_cache(dll);
    }

    if !args.no_cache {
        let cached = cached_bases()?;
        match cached.len() {
            1 => {
                eprintln!("base: using cached {}", cached[0].display());
                return read(&cached[0]);
            }
            0 => {}
            _ => bail!(
                "multiple cached bases in {}; pass --base <path> or --wcp-dll <path> to pick one:\n{}",
                cache_dir()?.display(),
                cached
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        }
    }

    let candidates = msdelta::winsxs::locate_wcp();
    let dll = candidates.first().ok_or_else(|| {
        anyhow::anyhow!(
            "no base manifest available: no cached base and no system wcp.dll found.\n\
             Supply one with --base <base.bin> or --wcp-dll <wcp.dll> \
             (on a non-Windows host, copy wcp.dll from the target image's \
             servicing-stack component)."
        )
    })?;
    eprintln!("base: located system {}", dll.display());
    extract_and_cache(dll)
}

/// Extract the base from a `wcp.dll`, cache it keyed by content hash, return it.
fn extract_and_cache(dll: &Path) -> Result<Vec<u8>> {
    let bytes = read(dll)?;
    let base = msdelta::winsxs::extract_base(&bytes)
        .with_context(|| format!("extracting base manifest from {}", dll.display()))?;
    eprintln!(
        "base: extracted {} bytes from {}",
        base.len(),
        dll.display()
    );

    match cache_path(&base) {
        Ok(path) => {
            if path.exists() {
                eprintln!("base: already cached at {}", path.display());
            } else if let Err(e) = write_cache(&path, &base) {
                // Caching is a convenience; failure must not abort the decode.
                eprintln!("warning: could not cache base ({e:#})");
            } else {
                eprintln!("base: cached to {}", path.display());
            }
        }
        Err(e) => eprintln!("warning: no cache location ({e:#})"),
    }
    Ok(base)
}

fn write_cache(path: &Path, base: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, base)?;
    Ok(())
}

/// Cache file path for a base, keyed by a short hash of its content so distinct
/// builds' bases coexist and identical ones dedupe.
fn cache_path(base: &[u8]) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(base);
    let short = hex(&digest[..8]);
    Ok(cache_dir()?.join(format!("base-{short}.bin")))
}

/// Existing cached base files (`base-*.bin`).
fn cached_bases() -> Result<Vec<PathBuf>> {
    let dir = cache_dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut bases: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("base-") && n.ends_with(".bin"))
        })
        .collect();
    bases.sort();
    Ok(bases)
}

/// Per-user cache directory for extracted bases, under the platform cache root
/// (`%LOCALAPPDATA%` on Windows, `~/Library/Caches` on macOS, `$XDG_CACHE_HOME`
/// or `~/.cache` on Linux).
fn cache_dir() -> Result<PathBuf> {
    let root = dirs::cache_dir().context("no platform cache directory available")?;
    Ok(root.join("msdelta"))
}

fn cmd_create(args: CreateArgs) -> Result<()> {
    let reference = read(&args.reference)?;
    let target = read(&args.target)?;

    let mut opts = CreateOptions::new()
        .hash_algorithm(args.hash.id())
        .codec(args.codec.into())
        .file_type(args.file_type.into());
    if args.pa31 {
        opts = opts.version(FormatVersion::PA31);
    }

    let delta = opts
        .execute(&reference, &target)
        .context("creating delta")?;
    let delta = if args.dcm { dcm::wrap(&delta) } else { delta };

    write_binary(args.output.as_deref(), &delta, "delta")
}

fn cmd_reverse(args: ReverseArgs) -> Result<()> {
    let reference = read(&args.reference)?;
    let raw = read(&args.delta)?;
    let inner = strip_dcm(&raw)?;

    let (forward, reverse) =
        pa30::apply_get_reverse(&reference, inner).context("computing reverse delta")?;

    if let Some(path) = args.target.as_deref() {
        std::fs::write(path, &forward)
            .with_context(|| format!("writing target {}", path.display()))?;
    }
    write_binary(args.output.as_deref(), &reverse, "reverse delta")
}

fn cmd_signature(args: SignatureArgs) -> Result<()> {
    let mut data = read(&args.file)?;
    if args.normalize {
        pa30::normalize_for_signature(&mut data);
    }
    let sig = pa30::get_signature(&data, args.hash.id()).context("computing signature")?;
    println!("{} {}", hash_name(sig.alg_id as i32), hex(&sig.hash));
    Ok(())
}

fn cmd_info(args: InfoArgs) -> Result<()> {
    let raw = read(&args.delta)?;
    let is_dcm = dcm::is_dcm(&raw);
    let inner = strip_dcm(&raw)?;

    println!("file:         {}", args.delta.display());
    println!("size:         {} bytes", raw.len());
    println!("container:    {}", if is_dcm { "DCM" } else { "raw" });

    if inner.starts_with(pa19::MAGIC) {
        let h = pa19::parse_header(inner).context("parsing PA19 header")?;
        println!("version:      PA19");
        println!(
            "old file:     {} bytes (crc {:#010x})",
            h.old_file_size, h.old_file_crc
        );
        println!(
            "new file:     {} bytes (crc {:#010x})",
            h.new_file_size, h.new_file_crc
        );
        println!("flags:        {:#x}", h.flags);
        println!("lzx window:   {} bytes", h.lzx_window_size);
        println!("interleave:   {} entries", h.interleave_count);
        return Ok(());
    }

    let header = pa30::get_info(inner).context("parsing delta header")?;
    println!("version:      {:?}", header.version);
    println!("target size:  {} bytes", header.target_size);
    println!(
        "file type:    {:#x} (set {:#x})",
        header.file_type, header.file_type_set
    );
    println!("flags:        {:#x}", header.flags);
    println!("hash alg:     {}", hash_name(header.hash_alg_id));
    if !header.target_hash.is_empty() {
        println!("target hash:  {}", hex(&header.target_hash));
    }
    Ok(())
}

fn cmd_completions(args: CompletionsArgs) -> Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

/// Strip a DCM wrapper if present, otherwise return the buffer unchanged.
fn strip_dcm(raw: &[u8]) -> Result<&[u8]> {
    if dcm::is_dcm(raw) {
        dcm::strip(raw).context("stripping DCM wrapper")
    } else {
        Ok(raw)
    }
}

fn hash_name(id: i32) -> String {
    match id as u32 {
        HASH_ALG_NONE => "none".into(),
        HASH_ALG_MD5 => "md5".into(),
        HASH_ALG_SHA256 => "sha256".into(),
        other => format!("{other:#x}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// Write text-or-binary output; stdout when no path is given.
fn write_out(path: Option<&Path>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) => std::fs::write(p, data).with_context(|| format!("writing {}", p.display())),
        None => std::io::stdout()
            .write_all(data)
            .context("writing to stdout"),
    }
}

/// Write binary output, refusing to dump raw bytes onto an interactive
/// terminal so a stray invocation can't scramble the user's session.
fn write_binary(path: Option<&Path>, data: &[u8], what: &str) -> Result<()> {
    if path.is_none() && std::io::stdout().is_terminal() {
        bail!(
            "refusing to write binary {what} to the terminal; \
             pass -o <file> or pipe stdout to a file"
        );
    }
    write_out(path, data)
}
