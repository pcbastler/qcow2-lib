//! LUKS header discovery and encryption setup for recovery.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use qcow2_core::engine::encryption::CryptContext;
use qcow2_format::constants::*;

use crate::report::*;
use crate::validate;

use super::RecoverOptions;

/// LUKS magic bytes for scanning.
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// Result of trying to set up encryption for recovery.
pub(crate) struct EncryptionSetup {
    /// CryptContext if password was correct.
    pub(crate) crypt_context: Option<CryptContext>,
    /// Whether we found a LUKS header at all.
    pub(crate) luks_found: bool,
    /// Offset where the LUKS header was found.
    pub(crate) luks_offset: Option<u64>,
    /// Size of the LUKS header data.
    #[allow(dead_code)]
    pub(crate) luks_size: Option<u64>,
    /// Whether the password probe succeeded.
    pub(crate) probe_ok: Option<bool>,
}

/// Set up encryption for recovery: find LUKS header, try password, probe.
#[allow(clippy::too_many_lines)]
pub(crate) fn setup_encryption(
    path: &Path,
    cluster_size: u64,
    mappings: &[MappingEntry],
    options: &RecoverOptions,
) -> EncryptionSetup {
    // Try to find LUKS header
    let luks_data = match find_luks_header(path, cluster_size) {
        Some((offset, data)) => {
            eprintln!("  found LUKS header at offset {offset:#x} ({} bytes)", data.len());
            (offset, data)
        }
        None => {
            eprintln!("  warning: encrypted clusters found but no LUKS header — data will be written raw (encrypted)");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: false,
                luks_offset: None,
                luks_size: None,
                probe_ok: None,
            };
        }
    };

    let (luks_offset, luks_bytes) = luks_data;
    let luks_size = luks_bytes.len() as u64;

    // No password? Write raw encrypted data.
    let password = match &options.password {
        Some(pw) => pw,
        None => {
            eprintln!("  no password provided — encrypted clusters will be written raw");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: true,
                luks_offset: Some(luks_offset),
                luks_size: Some(luks_size),
                probe_ok: None,
            };
        }
    };

    // Try to unlock with password
    let crypt_context = match qcow2::engine::encryption::recover_master_key(&luks_bytes, password) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("  warning: failed to unlock LUKS with provided password: {e}");
            eprintln!("  encrypted clusters will be written raw");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: true,
                luks_offset: Some(luks_offset),
                luks_size: Some(luks_size),
                probe_ok: Some(false),
            };
        }
    };

    // Probe: decrypt a few clusters and check if they look like real data
    let encrypted_mappings: Vec<_> = mappings.iter()
        .filter(|m| m.encrypted && !m.compressed)
        .take(5)
        .collect();

    let mut probe_ok = true;
    let mut probed = 0;
    let mut structured = 0;

    for m in &encrypted_mappings {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => break,
        };
        let mut buf = vec![0u8; cluster_size as usize];
        if file.seek(SeekFrom::Start(m.host_offset)).is_err()
            || file.read_exact(&mut buf).is_err()
        {
            continue;
        }

        if crypt_context.decrypt_cluster(m.host_offset, &mut buf).is_ok() {
            probed += 1;
            if validate::has_structure(&buf) {
                structured += 1;
            }
        }
    }

    if probed > 0 && structured == 0 {
        eprintln!(
            "  warning: decrypted {probed} clusters but none show data structure — password may be wrong"
        );
        eprintln!("  continuing with decryption anyway (use --no-decrypt to skip)");
        probe_ok = false;
    } else if probed > 0 {
        eprintln!("  encryption probe OK: {structured}/{probed} clusters show valid structure");
    }

    EncryptionSetup {
        crypt_context: Some(crypt_context),
        luks_found: true,
        luks_offset: Some(luks_offset),
        luks_size: Some(luks_size),
        probe_ok: Some(probe_ok),
    }
}

/// Find the LUKS header in a QCOW2 image.
///
/// Strategy:
/// 1. Parse QCOW2 header extensions → look for FullDiskEncryption pointing to LUKS data
/// 2. If that fails, scan for LUKS magic bytes at cluster-aligned offsets
#[allow(clippy::cognitive_complexity)]
pub(super) fn find_luks_header(path: &Path, cluster_size: u64) -> Option<(u64, Vec<u8>)> {
    let mut file = std::fs::File::open(path).ok()?;
    let file_size = file.seek(SeekFrom::End(0)).ok()?;

    // Strategy 1: Parse header extensions
    let header_cluster_size = cluster_size.min(4096) as usize;
    let mut header_buf = vec![0u8; header_cluster_size.max(4096)];
    file.seek(SeekFrom::Start(0)).ok()?;
    let n = file.read(&mut header_buf).ok()?;
    header_buf.truncate(n);

    if let Ok(header) = qcow2_format::Header::read_from(&header_buf) {
        if header.crypt_method == CRYPT_LUKS {
            // Parse header extensions to find FullDiskEncryption
            let ext_start = header.header_length as usize;
            if ext_start < header_buf.len() {
                if let Ok(extensions) =
                    qcow2_format::HeaderExtension::read_all(&header_buf[ext_start..])
                {
                    for ext in &extensions {
                        if let qcow2_format::HeaderExtension::FullDiskEncryption {
                            offset,
                            length,
                        } = ext
                        {
                            if offset + length <= file_size {
                                let mut luks_data = vec![0u8; *length as usize];
                                if file.seek(SeekFrom::Start(*offset)).is_ok()
                                    && file.read_exact(&mut luks_data).is_ok()
                                {
                                    // Verify it starts with LUKS magic
                                    if luks_data.len() >= 6 && &luks_data[..6] == LUKS_MAGIC {
                                        return Some((*offset, luks_data));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: Scan for LUKS magic at cluster-aligned offsets
    // LUKS header is typically at cluster 1 or after the QCOW2 header
    let scan_limit = file_size.min(64 * cluster_size);
    let mut offset = cluster_size; // start after header cluster

    while offset < scan_limit {
        let mut magic_buf = [0u8; 6];
        if file.seek(SeekFrom::Start(offset)).is_err()
            || file.read_exact(&mut magic_buf).is_err()
        {
            offset += cluster_size;
            continue;
        }

        if &magic_buf == LUKS_MAGIC {
            // Found LUKS magic — read enough data for the full header + key material
            // LUKS1 header is 592 bytes, but key material can extend much further.
            // Read up to 2MB (typical max for LUKS1 with 8 key slots).
            let max_luks_size = (2 * 1024 * 1024u64).min(file_size - offset);
            let mut luks_data = vec![0u8; max_luks_size as usize];
            if file.seek(SeekFrom::Start(offset)).is_ok()
                && file.read_exact(&mut luks_data).is_ok()
            {
                return Some((offset, luks_data));
            }
        }

        offset += cluster_size;
    }

    None
}

/// Build encryption info for the recovery report.
pub(crate) fn build_encryption_info(
    encryption: &EncryptionSetup,
    crypt: Option<&CryptContext>,
) -> Option<EncryptionRecoveryInfo> {
    if !encryption.luks_found {
        return None;
    }

    Some(EncryptionRecoveryInfo {
        luks_header_found: true,
        luks_header_offset: encryption.luks_offset,
        decrypted: crypt.is_some(),
        probe_ok: encryption.probe_ok,
    })
}
