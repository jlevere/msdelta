//! WinSxS base-manifest extraction (feature `winsxs`).
//!
//! Every DCM-compressed `.manifest` in `WinSxS` is a PA30 delta encoded
//! against a single shared *base manifest* (a small XML skeleton followed by a
//! token dictionary of substrings common to all manifests). At runtime
//! `wcp.dll`'s `DecompressManifest` hands that base to `ApplyDeltaB` as the
//! reference buffer. The base is not on disk as its own file; it lives inside
//! `wcp.dll` as a contiguous, length-prefixed blob in `.rdata`.
//!
//! This module recovers that blob by plain byte-parsing of the PE. It does
//! **not** load or execute the DLL, so it works on any host OS, against a
//! `wcp.dll` from any source (the live system, or — more usefully when you are
//! decoding manifests from a *different* Windows build than the one you are
//! running on — the `wcp.dll` lifted from the target image's servicing-stack
//! component).
//!
//! Two properties to keep in mind:
//!
//! - The base is **build-specific**. Its token dictionary grows across Windows
//!   versions, so a base extracted from build A may not match deltas from
//!   build B. Source the base from the same image as the manifests.
//! - WinSxS manifest deltas carry **no output hash** (`hash_alg_id == 0`), so a
//!   wrong base cannot be detected by an integrity check the way a hashed delta
//!   could. The only practical signal is whether the decoded output is
//!   well-formed XML. [`looks_like_manifest`] is a cheap heuristic for that.
//!
//! Everything here is a pure function over caller-supplied bytes
//! ([`extract_base`]) or an explicit, opt-in filesystem search
//! ([`locate_wcp`]). Nothing runs implicitly and nothing is cached; a caller
//! that wants caching owns that policy itself.

use std::path::PathBuf;

use memchr::memmem;

use crate::pe::parse::PeInfo;
use crate::{Error, Result};

/// Anchor uniquely identifying the base manifest's `<assembly>` element. The
/// short decoy XML literals elsewhere in `wcp.dll` (`<pluginInformation/>`,
/// `<sysprepInformation/>`) do not contain it.
const ANCHOR: &[u8] = br#"asm.v3" manifestVersion="1.0" description="Deployment""#;

/// The XML prolog the base blob begins with. We backtrack to this from the
/// anchor to find the true start of the buffer.
const PROLOG: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#;

/// Bytes between the prolog and the anchor are small and fixed; 256 is a
/// generous window for the backtrack.
const BACKTRACK_WINDOW: usize = 256;

/// Sanity bounds on the recovered length. The base is a few KB in practice;
/// these only exist to reject a bogus descriptor match.
const MIN_LEN: usize = PROLOG.len();
const MAX_LEN: usize = 1 << 20; // 1 MiB

/// Extract the WinSxS base manifest from the bytes of a `wcp.dll`.
///
/// Locates the base blob by its content signature, then recovers its exact
/// length from the `{ rva, len }` descriptor the DLL uses to reference it, so
/// the returned buffer is byte-identical to the reference `DecompressManifest`
/// would pass to `ApplyDeltaB`.
///
/// ```no_run
/// let dll = std::fs::read(r"C:\Windows\System32\wcp.dll").unwrap();
/// let base = msdelta::winsxs::extract_base(&dll).unwrap();
/// let manifest = std::fs::read("some.manifest").unwrap();
/// let pa30 = msdelta::dcm::strip(&manifest).unwrap();
/// let xml = msdelta::pa30::apply(&base, pa30).unwrap();
/// ```
pub fn extract_base(wcp_dll: &[u8]) -> Result<Vec<u8>> {
    let info = PeInfo::parse(wcp_dll)?;

    let anchor = memmem::find(wcp_dll, ANCHOR).ok_or(Error::BaseManifest(
        "base-manifest anchor not found in wcp.dll",
    ))?;

    // Backtrack from the anchor to the XML prolog that begins the buffer.
    let window_lo = anchor.saturating_sub(BACKTRACK_WINDOW);
    let rel = memmem::find(&wcp_dll[window_lo..anchor], PROLOG)
        .ok_or(Error::BaseManifest("XML prolog not found before anchor"))?;
    let start = window_lo + rel;

    let len = recover_len(wcp_dll, &info, start)?;

    let end = start
        .checked_add(len)
        .filter(|&e| e <= wcp_dll.len())
        .ok_or(Error::BaseManifest("base length runs past end of file"))?;

    Ok(wcp_dll[start..end].to_vec())
}

/// Window before the blob to search for its adjacent length descriptor.
const DESCRIPTOR_WINDOW: usize = 64;

/// Recover the base blob's length from the descriptor that references it.
///
/// The DLL stores a `{ u32 rva; u32 len }` record pointing at the blob (the
/// `rva` is the blob's own RVA, not a relocated VA). We compute the blob's RVA
/// from the section table and read the `len` that follows it.
///
/// The blob's RVA appears in several places in the image, but the canonical
/// descriptor sits immediately before the data, so we look there first. If the
/// layout ever differs, we fall back to a whole-image scan and take the
/// smallest valid length (the tight bound that ends the buffer exactly, rather
/// than an over-long reference into trailing data).
fn recover_len(data: &[u8], info: &PeInfo, start: usize) -> Result<usize> {
    let rva = file_offset_to_rva(info, start)
        .ok_or(Error::BaseManifest("base offset not inside any section"))?;
    let needle = rva.to_le_bytes();
    let valid = |len: usize| {
        (MIN_LEN..=MAX_LEN).contains(&len)
            && start + len <= data.len()
            && same_section(info, start, start + len - 1)
    };

    // The canonical descriptor is the rva-match nearest before the data;
    // `rfind` gives the one closest to `start`.
    let lo = start.saturating_sub(DESCRIPTOR_WINDOW);
    if let Some(rel) = memmem::rfind(&data[lo..start], &needle) {
        if let Some(len) = read_len(data, lo + rel) {
            if valid(len) {
                return Ok(len);
            }
        }
    }

    // Fallback: scan the whole image, keep the smallest valid length.
    let best = memmem::find_iter(data, &needle)
        .filter_map(|at| read_len(data, at))
        .filter(|&len| valid(len))
        .min();
    best.ok_or(Error::BaseManifest(
        "length descriptor for base manifest not found",
    ))
}

/// Read the `u32` length that follows an rva field at `at`.
fn read_len(data: &[u8], at: usize) -> Option<usize> {
    let raw = data.get(at + 4..at + 8)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize)
}

/// Map a file offset to its image RVA via the section table.
fn file_offset_to_rva(info: &PeInfo, offset: usize) -> Option<u32> {
    for s in &info.sections {
        let raw = s.raw_offset as usize;
        let size = s.raw_size as usize;
        if offset >= raw && offset < raw + size {
            return Some(s.virtual_address + (offset - raw) as u32);
        }
    }
    None
}

/// True if both file offsets fall in the same PE section.
fn same_section(info: &PeInfo, a: usize, b: usize) -> bool {
    for s in &info.sections {
        let lo = s.raw_offset as usize;
        let hi = lo + s.raw_size as usize;
        if (lo..hi).contains(&a) {
            return (lo..hi).contains(&b);
        }
    }
    false
}

/// Decompress a DCM-wrapped WinSxS `.manifest` against an already-extracted
/// base, returning the reconstructed XML.
///
/// This is the WinSxS-specific convenience over the generic core: it strips the
/// `DCM` wrapper (tolerating a raw PA30 buffer too) and applies the delta. The
/// `base` is the buffer from [`extract_base`]. The core delta machinery
/// ([`crate::pa30::apply`]) has no notion of a manifest or a base — anything
/// manifest-shaped lives here, behind the `winsxs` feature.
pub fn decompress(base: &[u8], manifest: &[u8]) -> Result<Vec<u8>> {
    let pa30 = if crate::dcm::is_dcm(manifest) {
        crate::dcm::strip(manifest)?
    } else {
        manifest
    };
    crate::pa30::apply(base, pa30)
}

/// Cheap heuristic: does a decoded buffer look like a WinSxS manifest? Use
/// after decoding to catch a base/build mismatch, since manifest deltas carry
/// no integrity hash to validate against.
pub fn looks_like_manifest(decoded: &[u8]) -> bool {
    let head = &decoded[..decoded.len().min(512)];
    memmem::find(head, b"<?xml").is_some() && memmem::find(head, b"<assembly").is_some()
}

/// Candidate `wcp.dll` locations on the local system, most-preferred first,
/// filtered to paths that exist. Returns empty on a host with no Windows
/// directory (e.g. Linux/macOS), where the caller is expected to supply a
/// `wcp.dll` (or a pre-extracted base) from the target image instead.
///
/// This reads the filesystem, but only when called: it is the explicit
/// discovery step, never run implicitly.
pub fn locate_wcp() -> Vec<PathBuf> {
    let win = system_root();
    let mut out = Vec::new();

    // On modern builds wcp.dll ships only in the servicing-stack WinSxS
    // component; on older builds it is in System32. Try both.
    let sys32 = win.join("System32").join("wcp.dll");
    if sys32.is_file() {
        out.push(sys32);
    }

    let winsxs = win.join("WinSxS");
    if let Ok(entries) = std::fs::read_dir(&winsxs) {
        let mut stack: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains("servicingstack"))
            })
            .filter(|p| p.join("wcp.dll").is_file())
            .map(|p| p.join("wcp.dll"))
            .collect();
        // Highest version sorts last lexically; prefer it.
        stack.sort();
        out.extend(stack.into_iter().rev());
    }

    out
}

/// The Windows directory (`%SystemRoot%`), defaulting to `C:\Windows`.
fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const REFERENCE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/reference");
    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    /// The extractor recovers the exact base committed as a fixture.
    ///
    /// Skips when `reference/wcp.dll` is absent (it is gitignored, Microsoft
    /// proprietary), so the suite still passes on a clean checkout.
    #[test]
    fn extract_matches_committed_base() {
        let dll = Path::new(REFERENCE_DIR).join("wcp.dll");
        if !dll.is_file() {
            eprintln!("skipping: {} not present", dll.display());
            return;
        }
        let bytes = std::fs::read(&dll).unwrap();
        let extracted = extract_base(&bytes).unwrap();

        let expected = std::fs::read(Path::new(FIXTURES_DIR).join("base_manifest.bin")).unwrap();
        assert_eq!(
            extracted.len(),
            expected.len(),
            "recovered base length mismatch"
        );
        assert_eq!(extracted, expected, "recovered base bytes differ");
    }

    /// The extracted base actually decodes a real DCM manifest.
    #[test]
    fn extracted_base_decodes_a_manifest() {
        let dll = Path::new(REFERENCE_DIR).join("wcp.dll");
        if !dll.is_file() {
            eprintln!("skipping: {} not present", dll.display());
            return;
        }
        let base = extract_base(&std::fs::read(&dll).unwrap()).unwrap();
        let manifest = std::fs::read(
            Path::new(FIXTURES_DIR)
                .join("amd64_microsoft-windows-font-truetype-gadugi_31bf3856ad364e35_10.0.26100.1_none_e1326a4c8dcc8ee1.manifest"),
        )
        .unwrap();
        let pa30 = crate::dcm::strip(&manifest).unwrap();
        let xml = crate::pa30::apply(&base, pa30).unwrap();
        assert!(
            looks_like_manifest(&xml),
            "decoded output is not a manifest"
        );
    }

    #[test]
    fn extract_rejects_non_pe() {
        assert!(extract_base(b"not a PE").is_err());
    }

    #[test]
    fn looks_like_manifest_basics() {
        assert!(looks_like_manifest(
            br#"<?xml version="1.0"?><assembly xmlns="urn">"#
        ));
        assert!(!looks_like_manifest(b"\x00\x01\x02 garbage"));
    }
}
