//! Hash/signature support for PA30 deltas.

use crate::{Error, Result};

/// Hash algorithm IDs (matching Windows ALG_ID values).
pub const HASH_ALG_NONE: u32 = 0;
pub const HASH_ALG_MD5: u32 = 0x8003;
pub const HASH_ALG_SHA256: u32 = 0x800C;

/// Computed delta signature/hash.
#[derive(Debug, Clone)]
pub struct DeltaHash {
    pub alg_id: u32,
    pub hash: Vec<u8>,
}

/// Compute a hash/signature of data using the specified algorithm.
///
/// Equivalent to `GetDeltaSignatureB(...)` on Windows.
pub fn get_signature(data: &[u8], hash_alg_id: u32) -> Result<DeltaHash> {
    use digest::Digest;

    let hash = match hash_alg_id {
        HASH_ALG_MD5 => {
            let mut hasher = md5::Md5::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HASH_ALG_SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => return Err(Error::Malformed("unsupported hash algorithm")),
    };

    Ok(DeltaHash {
        alg_id: hash_alg_id,
        hash,
    })
}

pub(super) fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Normalize a buffer for stable signature computation.
///
/// Equivalent to `DeltaNormalizeProvidedB(...)` on Windows.
/// Zeroes volatile PE fields (timestamps, checksums) so that
/// `get_signature` produces stable results across rebuilds.
pub fn normalize_for_signature(data: &mut [u8]) {
    use crate::pe::transform::{pe_timestamp, pe_timestamp_offsets};

    let ts = pe_timestamp(data);
    if ts == 0 { return; }

    let zeros = [0u8; 4];
    for off in pe_timestamp_offsets(data) {
        if off + 4 <= data.len() {
            let val = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            if val == ts {
                data[off..off + 4].copy_from_slice(&zeros);
            }
        }
    }

    if data.len() >= 0x40 {
        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let cksum_off = pe_off + 0x58;
        if cksum_off + 4 <= data.len() {
            data[cksum_off..cksum_off + 4].copy_from_slice(&zeros);
        }
    }
}
