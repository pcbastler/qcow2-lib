//! LUKS encryption support for QCOW2 images.
//!
//! Implements per-cluster AES-XTS-plain64 and AES-CBC-ESSIV encryption
//! as used by QEMU's LUKS-in-QCOW2 format (crypt_method=2).
//!
//! The encryption layer sits between the cluster mapping and I/O:
//! - Reads: raw data → decrypt → plaintext
//! - Writes: plaintext → encrypt → raw data
//!
//! IVs are derived from the **host** cluster offset (physical), not the
//! guest offset, matching QEMU's `crypt_physical_offset=true` behavior.

#[allow(missing_docs)]
pub mod af_splitter;
pub mod cipher;
#[allow(missing_docs)]
pub mod create;
#[allow(missing_docs)]
pub mod key_derivation;
#[allow(missing_docs)]
pub mod luks_header;

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
/// in `Qcow2Image`. Thread-safe (all fields are owned, no interior mutability).
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

/// Recover the master key from a LUKS header using a password.
///
/// Tries each active key slot until one succeeds. Returns a `CryptContext`
/// ready for encryption/decryption, or `WrongPassword` if none match.
pub fn recover_master_key(
    luks_data: &[u8],
    password: &[u8],
) -> Result<CryptContext> {
    let header = luks_header::LuksHeader::parse(luks_data)?;
    let cipher_mode = header.cipher_mode()?;

    match header {
        luks_header::LuksHeader::V1(ref h) => recover_luks1(h, luks_data, password, cipher_mode),
        luks_header::LuksHeader::V2(ref h) => recover_luks2(h, luks_data, password, cipher_mode),
    }
}

/// LUKS1 master key recovery.
fn recover_luks1(
    header: &luks_header::Luks1Header,
    luks_data: &[u8],
    password: &[u8],
    cipher_mode: CipherMode,
) -> Result<CryptContext> {
    let af_hash = header.af_hash()?;
    let key_bytes = header.key_bytes as usize;

    for (i, slot) in header.key_slots.iter().enumerate() {
        if !slot.active {
            continue;
        }

        // 1. Derive the split key from the password
        let slot_kdf = header.key_slot_kdf(i)?;
        let split_key = key_derivation::derive_key(&slot_kdf, password, key_bytes)?;

        // 2. Read and decrypt the key material from the image
        let km_offset = slot.key_material_offset as usize * 512;
        let km_size = slot.stripes as usize * key_bytes;
        if km_offset + km_size > luks_data.len() {
            continue; // Skip slots with out-of-bounds material
        }
        let mut key_material = luks_data[km_offset..km_offset + km_size].to_vec();
        create::decrypt_key_material(&split_key, cipher_mode, &mut key_material)?;

        // 3. AF merge to recover candidate master key
        let candidate = af_splitter::af_merge(&key_material, key_bytes, slot.stripes, af_hash)?;

        // 4. Verify: PBKDF2(candidate, mk_digest_salt, mk_digest_iter) == mk_digest
        let verify_kdf = header.mk_digest_kdf()?;
        let digest = key_derivation::derive_key(&verify_kdf, &candidate, 20)?;

        if digest == header.mk_digest {
            return Ok(CryptContext::new(candidate, cipher_mode));
        }
    }

    Err(Error::WrongPassword)
}

/// LUKS2 master key recovery.
fn recover_luks2(
    header: &luks_header::Luks2Header,
    luks_data: &[u8],
    password: &[u8],
    cipher_mode: CipherMode,
) -> Result<CryptContext> {
    let key_bytes = header.key_bytes as usize;

    // Sort keyslot IDs for deterministic iteration
    let mut slot_ids: Vec<&String> = header.metadata.keyslots.keys().collect();
    slot_ids.sort();

    for slot_id in slot_ids {
        let ks = &header.metadata.keyslots[slot_id];

        // 1. Derive the split key from the password
        let kdf = header.keyslot_kdf(slot_id)?;
        let split_key = key_derivation::derive_key(&kdf, password, ks.area.key_size as usize)?;

        // 2. Read key material from the area
        let km_offset: usize = ks.area.offset.parse().map_err(|_| Error::InvalidLuksHeader {
            message: format!("invalid area offset: {}", ks.area.offset),
        })?;
        let km_size: usize = ks.area.size.parse().map_err(|_| Error::InvalidLuksHeader {
            message: format!("invalid area size: {}", ks.area.size),
        })?;
        if km_offset + km_size > luks_data.len() {
            continue;
        }
        let mut key_material = luks_data[km_offset..km_offset + km_size].to_vec();

        // Decrypt the key material
        create::decrypt_key_material(&split_key, cipher_mode, &mut key_material)?;

        // 3. AF merge
        let af_hash = header.keyslot_af_hash(slot_id)?;
        let candidate = af_splitter::af_merge(
            &key_material,
            key_bytes,
            ks.af.stripes,
            af_hash,
        )?;

        // 4. Verify against digest
        let (digest_obj, salt, expected) = header.digest_for_keyslot(slot_id)?;
        let verify_kdf = key_derivation::Kdf::Pbkdf2 {
            hash: key_derivation::KdfHash::from_spec(&digest_obj.hash)?,
            iterations: digest_obj.iterations,
            salt,
        };
        let computed = key_derivation::derive_key(&verify_kdf, &candidate, expected.len())?;

        if computed == expected {
            return Ok(CryptContext::new(candidate, cipher_mode));
        }
    }

    Err(Error::WrongPassword)
}

impl std::fmt::Debug for CryptContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptContext")
            .field("cipher_mode", &self.cipher_mode)
            .field("key_len", &self.master_key.len())
            .field("sector_size", &self.sector_size)
            .finish()
    }
}
