//! LUKS encryption primitives for QCOW2 images.
//!
//! Provides per-cluster AES-XTS-plain64 and AES-CBC-ESSIV encryption
//! as used by QEMU's LUKS-in-QCOW2 format (crypt_method=2).
//!
//! This module contains the `no_std`-compatible core: cipher operations,
//! key derivation (PBKDF2), and AF splitting. Higher-level operations
//! (LUKS header parsing, master key recovery, header creation) live in
//! the `qcow2` userspace crate.
//!
//! IVs are derived from the **host** cluster offset (physical), not the
//! guest offset, matching QEMU's `crypt_physical_offset=true` behavior.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::fmt;

#[allow(missing_docs)]
pub mod af_splitter;
pub mod cipher;
#[allow(missing_docs)]
pub mod key_derivation;

use crate::error::{Error, Result};

/// Supported cipher modes for QCOW2 encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// AES-XTS with plain64 IV generation. QEMU default.
    AesXtsPlain64,
    /// AES-CBC with ESSIV (Encrypted Salt-Sector IV).
    AesCbcEssiv,
}

/// Encryption context holding the decrypted master key and cipher parameters.
///
/// Created once during image open (after password verification) and stored
/// in the image handle. Thread-safe (all fields are owned, no interior mutability).
#[derive(Clone)]
pub struct CryptContext {
    /// Decrypted master key.
    master_key: Vec<u8>,
    /// Which cipher mode to use.
    cipher_mode: CipherMode,
    /// Sector size for IV calculation (always 512 for QCOW2).
    sector_size: u32,
}

impl CryptContext {
    /// Create a new encryption context.
    pub fn new(master_key: Vec<u8>, cipher_mode: CipherMode) -> Self {
        Self {
            master_key,
            cipher_mode,
            sector_size: 512,
        }
    }

    /// The cipher mode in use.
    pub fn cipher_mode(&self) -> CipherMode {
        self.cipher_mode
    }

    /// The master key length in bytes.
    pub fn key_len(&self) -> usize {
        self.master_key.len()
    }

    /// The raw master key bytes. Exposed for key material operations
    /// (AF splitting, key slot encryption) in the userspace crate.
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Decrypt a cluster in-place.
    ///
    /// `host_offset` is the physical byte offset of this cluster in the image,
    /// used to derive the per-sector IV/tweak. `data` must be cluster-aligned
    /// (multiple of sector_size).
    pub fn decrypt_cluster(&self, host_offset: u64, data: &mut [u8]) -> Result<()> {
        self.process_cluster(host_offset, data, false)
    }

    /// Encrypt a cluster in-place.
    ///
    /// `host_offset` is the physical byte offset where this cluster will be written.
    pub fn encrypt_cluster(&self, host_offset: u64, data: &mut [u8]) -> Result<()> {
        self.process_cluster(host_offset, data, true)
    }

    /// Process (encrypt or decrypt) a cluster sector-by-sector.
    fn process_cluster(
        &self,
        host_offset: u64,
        data: &mut [u8],
        encrypt: bool,
    ) -> Result<()> {
        let sector_size = self.sector_size as usize;
        if data.len() % sector_size != 0 {
            return Err(Error::EncryptionFailed {
                guest_offset: 0,
                message: format!(
                    "data length {} is not a multiple of sector size {}",
                    data.len(),
                    sector_size,
                ),
            });
        }

        let base_sector = host_offset / self.sector_size as u64;

        for (i, sector) in data.chunks_mut(sector_size).enumerate() {
            let sector_num = base_sector + i as u64;
            match self.cipher_mode {
                CipherMode::AesXtsPlain64 => {
                    if encrypt {
                        cipher::encrypt_sector_xts(&self.master_key, sector_num, sector)?;
                    } else {
                        cipher::decrypt_sector_xts(&self.master_key, sector_num, sector)?;
                    }
                }
                CipherMode::AesCbcEssiv => {
                    if encrypt {
                        cipher::encrypt_sector_cbc_essiv(&self.master_key, sector_num, sector)?;
                    } else {
                        cipher::decrypt_sector_cbc_essiv(&self.master_key, sector_num, sector)?;
                    }
                }
            }
        }

        Ok(())
    }
}

impl fmt::Debug for CryptContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptContext")
            .field("cipher_mode", &self.cipher_mode)
            .field("key_len", &self.master_key.len())
            .field("sector_size", &self.sector_size)
            .finish()
    }
}
