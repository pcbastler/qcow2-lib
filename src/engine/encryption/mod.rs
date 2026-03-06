//! LUKS encryption support for QCOW2 images.
//!
//! Re-exports core encryption types from [`qcow2_core::engine::encryption`]
//! and adds std-only functionality:
//! - LUKS header parsing (`luks_header`)
//! - Encryption creation helpers (`create`)
//! - Master key recovery (`recover_master_key`)

// Re-export core types and sub-modules
pub use qcow2_core::engine::encryption::{
    cipher, key_derivation, CipherMode, CryptContext,
};

// Local af_splitter with working af_split (uses rand, not available in no_std core)
pub mod af_splitter;

// Std-only modules
#[allow(missing_docs)]
pub mod create;
#[allow(missing_docs)]
pub mod luks_header;

use crate::error::{Error, Result};

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
