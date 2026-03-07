//! Data structure heuristics and decryption probes.

use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;

/// Try to decrypt a cluster and check if the result looks like valid data.
///
/// We decrypt the cluster and check if the result is not all-zero and not
/// high-entropy random-looking data (which would suggest wrong key).
///
/// Returns `Ok(true)` if decryption succeeded and the result looks plausible.
pub(super) fn try_decrypt_cluster(
    file: &mut std::fs::File,
    host_offset: u64,
    cluster_size: u64,
    crypt: &qcow2_core::engine::encryption::CryptContext,
) -> Result<bool> {
    let mut buf = vec![0u8; cluster_size as usize];
    file.seek(SeekFrom::Start(host_offset))?;
    file.read_exact(&mut buf)?;

    if crypt.decrypt_cluster(host_offset, &mut buf).is_err() {
        return Ok(false);
    }

    Ok(has_structure(&buf))
}

/// Heuristic: does the decrypted data show any structure?
///
/// Real disk data (filesystems, etc.) typically has runs of identical bytes,
/// zero regions, or recognizable patterns. Random data from a wrong-key
/// decryption has very high entropy with no such patterns.
///
/// We check for:
/// - Any run of 8+ identical bytes (very unlikely in random data: ~1/256^7)
/// - More than 1% zero bytes (common in real filesystem data)
pub fn has_structure(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check for zero byte ratio
    let zero_count = data.iter().filter(|&&b| b == 0).count();
    if zero_count * 100 / data.len() > 1 {
        return true;
    }

    // Check for runs of identical bytes (>= 8)
    let mut run_len = 1u32;
    for i in 1..data.len() {
        if data[i] == data[i - 1] {
            run_len += 1;
            if run_len >= 8 {
                return true;
            }
        } else {
            run_len = 1;
        }
    }

    false
}
