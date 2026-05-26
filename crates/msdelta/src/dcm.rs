//! DCM wrapper around PA30 deltas, used for `.manifest` files in `WinSxS`.
//!
//! A DCM file is a 4-byte `DCM\x01` magic followed by a PA30 delta. The
//! reference buffer is a base manifest supplied by `wcp.dll`'s
//! `DecompressManifest`; we will need to either embed that base or accept it
//! as a caller-supplied input.

use crate::{Error, Result};

pub const MAGIC: &[u8; 4] = b"DCM\x01";

pub fn is_dcm(buf: &[u8]) -> bool {
    buf.len() >= MAGIC.len() && &buf[..MAGIC.len()] == MAGIC
}

/// Strip the DCM wrapper, returning the inner PA30 payload.
pub fn strip(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < MAGIC.len() {
        return Err(Error::Truncated);
    }
    if &buf[..MAGIC.len()] != MAGIC {
        return Err(Error::BadMagic {
            expected: MAGIC,
            got: buf[..MAGIC.len()].to_vec(),
        });
    }
    Ok(&buf[MAGIC.len()..])
}

/// Prepend the DCM wrapper to a PA30 payload, producing a full DCM blob.
pub fn wrap(pa30: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + pa30.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(pa30);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pa30;

    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture_paths() -> Vec<std::path::PathBuf> {
        std::fs::read_dir(FIXTURES_DIR)
            .expect("fixtures dir must exist")
            .filter_map(|e| {
                let p = e.ok()?.path();
                if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                    Some(p)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn all_fixtures_are_dcm() {
        let paths = fixture_paths();
        assert!(paths.len() >= 7, "expected at least 7 fixtures, got {}", paths.len());
        for path in &paths {
            let data = std::fs::read(path).expect("read fixture");
            assert!(is_dcm(&data), "not DCM: {}", path.display());
        }
    }

    #[test]
    fn all_fixtures_contain_pa30_after_dcm() {
        for path in &fixture_paths() {
            let data = std::fs::read(path).expect("read fixture");
            let inner = strip(&data).expect("strip DCM");
            assert!(
                inner.len() >= pa30::MAGIC.len(),
                "inner too short: {}",
                path.display()
            );
            assert_eq!(
                &inner[..pa30::MAGIC.len()],
                pa30::MAGIC,
                "missing PA30 magic after DCM strip: {}",
                path.display()
            );
        }
    }

    #[test]
    fn strip_returns_everything_after_magic() {
        let data = b"DCM\x01PA30rest_of_payload";
        let inner = strip(data).expect("strip");
        assert_eq!(inner, b"PA30rest_of_payload");
    }

    #[test]
    fn strip_rejects_wrong_magic() {
        let data = b"DCM\x02PA30rest";
        assert!(matches!(strip(data), Err(Error::BadMagic { .. })));
    }

    #[test]
    fn strip_rejects_truncated() {
        assert!(matches!(strip(b"DC"), Err(Error::Truncated)));
        assert!(matches!(strip(b""), Err(Error::Truncated)));
    }

    #[test]
    fn is_dcm_false_for_non_dcm() {
        assert!(!is_dcm(b"PA30xxxx"));
        assert!(!is_dcm(b""));
        assert!(!is_dcm(b"DCM"));
    }

    #[test]
    fn wrap_roundtrip() {
        let payload = b"PA30some_delta_data";
        let wrapped = wrap(payload);
        assert!(is_dcm(&wrapped));
        let inner = strip(&wrapped).expect("strip");
        assert_eq!(inner, payload);
    }

    #[test]
    fn wrap_empty_payload() {
        let wrapped = wrap(b"");
        assert_eq!(wrapped, MAGIC);
        let inner = strip(&wrapped).expect("strip");
        assert!(inner.is_empty());
    }
}
