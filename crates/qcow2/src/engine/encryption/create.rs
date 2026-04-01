//! LUKS header creation for new encrypted QCOW2 images.

use rand::Rng;

use super::af_splitter::{self, AfHash};
use super::key_derivation::{self, Kdf, KdfHash};
use super::luks_header::{Luks1Header, Luks1KeySlot, LUKS1_NUM_KEY_SLOTS};
use super::CipherMode;
use crate::error::{Error, Result};

/// Default PBKDF2 iteration count for key slots.
/// Lower than production LUKS defaults for practical use; callers can override.
const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;
/// Default number of AF stripes.
const DEFAULT_STRIPES: u32 = 4000;

/// Create a LUKS1 header with one active key slot protected by the given password.
///
/// Returns (header_bytes, master_key) where header_bytes includes the full
/// LUKS1 header and all key material areas, ready to be written to the image.
pub fn create_luks1_header(
    password: &[u8],
    cipher_mode: CipherMode,
    key_bytes: u32,
    iterations: Option<u32>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand::rng();

    // Generate random master key
    let mut master_key = vec![0u8; key_bytes as usize];
    rng.fill(master_key.as_mut_slice());

    // Generate header parameters
    let (cipher_name, cipher_mode_str) = cipher_mode_strings(cipher_mode);
    let hash_spec = "sha256".to_string();
    let af_hash = AfHash::Sha256;
    let kdf_hash = KdfHash::Sha256;

    // Compute mk-digest: PBKDF2(master_key, mk_digest_salt, mk_digest_iter)
    let mut mk_digest_salt = [0u8; 32];
    rng.fill(&mut mk_digest_salt);
    let mk_digest_iter = iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);

    let mk_digest_kdf = Kdf::Pbkdf2 {
        hash: kdf_hash,
        iterations: mk_digest_iter,
        salt: mk_digest_salt.to_vec(),
    };
    let mk_digest_full = key_derivation::derive_key(&mk_digest_kdf, &master_key, 20)?;
    let mut mk_digest = [0u8; 20];
    mk_digest.copy_from_slice(&mk_digest_full);

    // UUID
    let uuid = uuid::Uuid::new_v4().to_string();

    // Key slot 0 setup
    let slot_iterations = iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
    let mut slot_salt = [0u8; 32];
    rng.fill(&mut slot_salt);

    // Key material for slot 0 starts at sector 8 (after 4096 bytes = 8 * 512)
    let key_material_offset = 8u32; // in 512-byte sectors

    // AF split the master key
    let split_material =
        af_splitter::af_split(&master_key, DEFAULT_STRIPES, af_hash)?;

    // Derive the slot key from the password
    let slot_kdf = Kdf::Pbkdf2 {
        hash: kdf_hash,
        iterations: slot_iterations,
        salt: slot_salt.to_vec(),
    };
    let slot_key = key_derivation::derive_key(&slot_kdf, password, key_bytes as usize)?;

    // Encrypt the split material with the slot key.
    // QEMU uses the same cipher mode for key material as for data.
    let mut encrypted_material = split_material;
    encrypt_key_material(&slot_key, cipher_mode, &mut encrypted_material)?;

    // Calculate key slot offsets and payload offset (in 512-byte sectors).
    // Key material per slot = stripes * key_bytes bytes.
    // Each slot's offset must be 4096-byte (8-sector) aligned (QEMU convention).
    let material_size = DEFAULT_STRIPES as u64 * key_bytes as u64;
    let material_sectors = ((material_size + 511) / 512) as u32;

    // Build key slot offsets: each aligned to 8-sector boundary
    let mut key_slots: [Luks1KeySlot; LUKS1_NUM_KEY_SLOTS] = Default::default();
    let mut next_offset = key_material_offset;
    for slot in key_slots.iter_mut() {
        slot.key_material_offset = next_offset;
        next_offset = (next_offset + material_sectors + 7) & !7;
    }
    key_slots[0].active = true;
    key_slots[0].iterations = slot_iterations;
    key_slots[0].salt = slot_salt;
    key_slots[0].stripes = DEFAULT_STRIPES;

    // Payload offset = after all 8 slot areas (already 8-sector aligned)
    let payload_offset = next_offset;

    let header = Luks1Header {
        cipher_name,
        cipher_mode_str,
        hash_spec,
        payload_offset,
        key_bytes,
        mk_digest,
        mk_digest_salt,
        mk_digest_iter,
        uuid,
        key_slots,
    };

    // Serialize: header + key material areas
    let total_size = payload_offset as usize * 512;
    let mut buf = vec![0u8; total_size];
    let header_bytes = header.serialize();
    buf[..header_bytes.len()].copy_from_slice(&header_bytes);

    // Write slot 0 key material
    let km_offset = key_material_offset as usize * 512;
    let km_len = encrypted_material.len();
    buf[km_offset..km_offset + km_len].copy_from_slice(&encrypted_material);

    Ok((buf, master_key))
}

/// Encrypt key material in 512-byte sectors.
///
/// QEMU uses the same cipher mode for key material encryption as for data.
/// For XTS: AES-XTS with full key and sector-number tweak.
/// For CBC: AES-CBC with sector-number plain IV.
pub fn encrypt_key_material(key: &[u8], cipher_mode: CipherMode, material: &mut [u8]) -> Result<()> {
    for (i, sector) in material.chunks_mut(512).enumerate() {
        if sector.len() < 512 {
            break;
        }
        match cipher_mode {
            CipherMode::AesXtsPlain64 => {
                super::cipher::encrypt_sector_xts(key, i as u64, sector)?;
            }
            CipherMode::AesCbcEssiv => {
                let iv = make_plain_iv(i as u64);
                encrypt_sector_cbc_plain(key, &iv, sector)?;
            }
        }
    }
    Ok(())
}

/// Decrypt key material (inverse of encrypt_key_material).
///
/// Uses the same cipher mode as data encryption, matching QEMU behavior.
pub fn decrypt_key_material(key: &[u8], cipher_mode: CipherMode, material: &mut [u8]) -> Result<()> {
    for (i, sector) in material.chunks_mut(512).enumerate() {
        if sector.len() < 512 {
            break;
        }
        match cipher_mode {
            CipherMode::AesXtsPlain64 => {
                super::cipher::decrypt_sector_xts(key, i as u64, sector)?;
            }
            CipherMode::AesCbcEssiv => {
                let iv = make_plain_iv(i as u64);
                decrypt_sector_cbc_plain(key, &iv, sector)?;
            }
        }
    }
    Ok(())
}

/// AES-CBC encrypt a sector with a plain IV (for CBC key material encryption).
fn encrypt_sector_cbc_plain(key: &[u8], iv: &[u8; 16], sector: &mut [u8]) -> Result<()> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::cipher::block_padding::NoPadding;
    match key.len() {
        16 => {
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            let enc = Aes128CbcEnc::new_from_slices(key, iv).map_err(|e| {
                Error::EncryptionFailed { guest_offset: 0, message: format!("key material CBC init: {e}") }
            })?;
            enc.encrypt_padded_mut::<NoPadding>(sector, 512)
                .map_err(|e| Error::EncryptionFailed { guest_offset: 0, message: format!("key material CBC encrypt: {e}") })?;
        }
        32 => {
            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            let enc = Aes256CbcEnc::new_from_slices(key, iv).map_err(|e| {
                Error::EncryptionFailed { guest_offset: 0, message: format!("key material CBC init: {e}") }
            })?;
            enc.encrypt_padded_mut::<NoPadding>(sector, 512)
                .map_err(|e| Error::EncryptionFailed { guest_offset: 0, message: format!("key material CBC encrypt: {e}") })?;
        }
        _ => {
            return Err(Error::EncryptionFailed {
                guest_offset: 0,
                message: format!("unsupported CBC key length for key material: {}", key.len()),
            });
        }
    }
    Ok(())
}

/// AES-CBC decrypt a sector with a plain IV (for CBC key material decryption).
fn decrypt_sector_cbc_plain(key: &[u8], iv: &[u8; 16], sector: &mut [u8]) -> Result<()> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::cipher::block_padding::NoPadding;
    match key.len() {
        16 => {
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            let dec = Aes128CbcDec::new_from_slices(key, iv).map_err(|e| {
                Error::DecryptionFailed { guest_offset: 0, message: format!("key material CBC init: {e}") }
            })?;
            dec.decrypt_padded_mut::<NoPadding>(sector)
                .map_err(|e| Error::DecryptionFailed { guest_offset: 0, message: format!("key material CBC decrypt: {e}") })?;
        }
        32 => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            let dec = Aes256CbcDec::new_from_slices(key, iv).map_err(|e| {
                Error::DecryptionFailed { guest_offset: 0, message: format!("key material CBC init: {e}") }
            })?;
            dec.decrypt_padded_mut::<NoPadding>(sector)
                .map_err(|e| Error::DecryptionFailed { guest_offset: 0, message: format!("key material CBC decrypt: {e}") })?;
        }
        _ => {
            return Err(Error::DecryptionFailed {
                guest_offset: 0,
                message: format!("unsupported CBC key length for key material: {}", key.len()),
            });
        }
    }
    Ok(())
}

/// Build a plain-mode IV (sector number as LE in a 16-byte block).
fn make_plain_iv(sector_num: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&sector_num.to_le_bytes());
    iv
}

/// Get cipher name/mode strings for LUKS header.
fn cipher_mode_strings(mode: CipherMode) -> (String, String) {
    match mode {
        CipherMode::AesXtsPlain64 => ("aes".to_string(), "xts-plain64".to_string()),
        CipherMode::AesCbcEssiv => ("aes".to_string(), "cbc-essiv:sha256".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::encryption::luks_header::LuksHeader;
    use crate::engine::encryption::recover_master_key;

    #[test]
    fn create_luks1_header_valid() {
        let (header_bytes, master_key) = create_luks1_header(
            b"testpassword",
            CipherMode::AesXtsPlain64,
            64, // AES-256-XTS
            Some(1000), // Fast iterations for test
        )
        .unwrap();

        assert!(!header_bytes.is_empty());
        assert_eq!(master_key.len(), 64);

        // Parse it back
        let header = LuksHeader::parse(&header_bytes).unwrap();
        assert!(matches!(header, LuksHeader::V1(_)));
        assert_eq!(header.key_bytes(), 64);
        assert_eq!(header.cipher_mode().unwrap(), CipherMode::AesXtsPlain64);
    }

    #[test]
    fn create_luks1_header_cbc() {
        let (header_bytes, _master_key) = create_luks1_header(
            b"password",
            CipherMode::AesCbcEssiv,
            32, // AES-256-CBC
            Some(1000),
        )
        .unwrap();

        let header = LuksHeader::parse(&header_bytes).unwrap();
        assert_eq!(header.key_bytes(), 32);
        assert_eq!(header.cipher_mode().unwrap(), CipherMode::AesCbcEssiv);
    }

    #[test]
    fn key_material_encrypt_decrypt_round_trip_cbc() {
        let key = vec![0x42u8; 32];
        let original = vec![0xAA; 4096]; // 8 sectors
        let mut data = original.clone();

        encrypt_key_material(&key, CipherMode::AesCbcEssiv, &mut data).unwrap();
        assert_ne!(data, original, "encrypted should differ");

        decrypt_key_material(&key, CipherMode::AesCbcEssiv, &mut data).unwrap();
        assert_eq!(data, original, "round-trip should recover original");
    }

    /// Round-trip with 64-byte XTS key using XTS cipher (matching QEMU).
    #[test]
    fn key_material_encrypt_decrypt_xts_key() {
        let key = vec![0x55u8; 64]; // XTS key length
        let original = vec![0xBB; 2048]; // 4 sectors
        let mut data = original.clone();

        encrypt_key_material(&key, CipherMode::AesXtsPlain64, &mut data).unwrap();
        assert_ne!(data, original, "encrypted should differ");

        decrypt_key_material(&key, CipherMode::AesXtsPlain64, &mut data).unwrap();
        assert_eq!(data, original, "round-trip should recover original");
    }

    /// End-to-end: create LUKS1 header → recover master key from raw bytes.
    /// This tests the full pipeline without any image/file layer.
    #[test]
    fn create_then_recover_master_key_xts() {
        let password = b"test-password-123";
        let (header_bytes, _original_master_key) = create_luks1_header(
            password,
            CipherMode::AesXtsPlain64,
            64,         // AES-256-XTS
            Some(1000), // fast iterations
        )
        .unwrap();

        // Recover using the public API
        let ctx = recover_master_key(&header_bytes, password).unwrap();
        assert_eq!(ctx.cipher_mode(), CipherMode::AesXtsPlain64);
        assert_eq!(ctx.key_len(), 64);

        // Verify the recovered key matches by encrypting/decrypting
        let plaintext = vec![0xAA; 512];
        let mut data = plaintext.clone();
        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, plaintext);
        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, plaintext);
    }

    /// End-to-end: create LUKS1 header → recover master key (CBC mode).
    #[test]
    fn create_then_recover_master_key_cbc() {
        let password = b"cbc-pw";
        let (header_bytes, _master_key) = create_luks1_header(
            password,
            CipherMode::AesCbcEssiv,
            32,         // AES-256-CBC
            Some(1000),
        )
        .unwrap();

        let ctx = recover_master_key(&header_bytes, password).unwrap();
        assert_eq!(ctx.cipher_mode(), CipherMode::AesCbcEssiv);
        assert_eq!(ctx.key_len(), 32);
    }

    /// Wrong password should fail recovery.
    #[test]
    fn create_then_wrong_password_fails() {
        let (header_bytes, _) = create_luks1_header(
            b"correct",
            CipherMode::AesXtsPlain64,
            64,
            Some(1000),
        )
        .unwrap();

        let result = recover_master_key(&header_bytes, b"wrong");
        assert!(result.is_err(), "wrong password should fail");
    }

    /// Step-by-step verification of the key recovery pipeline.
    /// Traces each intermediate value to catch subtle bugs.
    #[test]
    fn create_then_recover_step_by_step() {
        use crate::engine::encryption::af_splitter;
        use crate::engine::encryption::key_derivation;
        use crate::engine::encryption::luks_header::LuksHeader;

        let password = b"debug-pw";
        let (header_bytes, original_mk) = create_luks1_header(
            password,
            CipherMode::AesXtsPlain64,
            64,
            Some(500),
        )
        .unwrap();

        // Step 1: Parse header
        let header = LuksHeader::parse(&header_bytes).unwrap();
        let h = match &header {
            LuksHeader::V1(h) => h,
            _ => panic!("expected LUKS1"),
        };
        assert_eq!(h.key_bytes, 64);
        assert_eq!(h.hash_spec, "sha256");

        // Step 2: Find active slot
        let slot = &h.key_slots[0];
        assert!(slot.active, "slot 0 should be active");
        assert_eq!(slot.stripes, DEFAULT_STRIPES);

        // Step 3: Derive split key
        let slot_kdf = h.key_slot_kdf(0).unwrap();
        let split_key = key_derivation::derive_key(&slot_kdf, password, 64).unwrap();
        assert_eq!(split_key.len(), 64);

        // Step 4: Read + decrypt key material
        let km_offset = slot.key_material_offset as usize * 512;
        let km_size = slot.stripes as usize * 64;
        assert!(km_offset + km_size <= header_bytes.len(),
            "key material out of bounds: offset={km_offset} size={km_size} total={}",
            header_bytes.len());

        let mut key_material = header_bytes[km_offset..km_offset + km_size].to_vec();
        decrypt_key_material(&split_key, CipherMode::AesXtsPlain64, &mut key_material).unwrap();

        // Step 5: AF merge
        let af_hash = h.af_hash().unwrap();
        let candidate = af_splitter::af_merge(&key_material, 64, slot.stripes, af_hash).unwrap();
        assert_eq!(candidate.len(), 64);
        assert_eq!(candidate, original_mk, "recovered master key should match original");

        // Step 6: Verify digest
        let verify_kdf = h.mk_digest_kdf().unwrap();
        let digest = key_derivation::derive_key(&verify_kdf, &candidate, 20).unwrap();
        assert_eq!(digest, h.mk_digest.to_vec(), "digest verification should match");
    }

    // ---- key material encrypt/decrypt edge cases ----

    #[test]
    fn key_material_encrypt_decrypt_round_trip_cbc_128() {
        let key = vec![0x42u8; 16]; // AES-128-CBC
        let original = vec![0xAA; 2048]; // 4 sectors
        let mut data = original.clone();

        encrypt_key_material(&key, CipherMode::AesCbcEssiv, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt_key_material(&key, CipherMode::AesCbcEssiv, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn key_material_partial_last_sector_skipped() {
        // Data with a trailing partial sector (< 512 bytes)
        let key = vec![0x42u8; 64];
        let original = vec![0xBB; 512 + 100]; // 1 full sector + 100 bytes
        let mut data = original.clone();

        encrypt_key_material(&key, CipherMode::AesXtsPlain64, &mut data).unwrap();
        // First 512 bytes should be encrypted
        assert_ne!(&data[..512], &original[..512]);
        // Trailing 100 bytes should be untouched (skipped)
        assert_eq!(&data[512..], &original[512..]);
    }

    #[test]
    fn encrypt_sector_cbc_plain_invalid_key_length() {
        let key = vec![0u8; 24]; // Not 16 or 32
        let iv = [0u8; 16];
        let mut sector = [0u8; 512];
        let err = encrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap_err();
        assert!(err.to_string().contains("unsupported CBC key length"));
    }

    #[test]
    fn decrypt_sector_cbc_plain_invalid_key_length() {
        let key = vec![0u8; 24];
        let iv = [0u8; 16];
        let mut sector = [0u8; 512];
        let err = decrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap_err();
        assert!(err.to_string().contains("unsupported CBC key length"));
    }

    #[test]
    fn encrypt_decrypt_sector_cbc_plain_128_round_trip() {
        let key = vec![0x55u8; 16];
        let iv = make_plain_iv(42);
        let original = [0xAA; 512];
        let mut sector = original;

        encrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap();
        assert_ne!(sector, original);

        decrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap();
        assert_eq!(sector, original);
    }

    #[test]
    fn encrypt_decrypt_sector_cbc_plain_256_round_trip() {
        let key = vec![0x55u8; 32];
        let iv = make_plain_iv(0);
        let original = [0xBB; 512];
        let mut sector = original;

        encrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap();
        assert_ne!(sector, original);

        decrypt_sector_cbc_plain(&key, &iv, &mut sector).unwrap();
        assert_eq!(sector, original);
    }

    #[test]
    fn make_plain_iv_sector_zero() {
        let iv = make_plain_iv(0);
        assert_eq!(iv, [0u8; 16]);
    }

    #[test]
    fn make_plain_iv_sector_one() {
        let iv = make_plain_iv(1);
        let mut expected = [0u8; 16];
        expected[0] = 1;
        assert_eq!(iv, expected);
    }

    #[test]
    fn make_plain_iv_large_sector() {
        let iv = make_plain_iv(0x0102_0304_0506_0708);
        assert_eq!(&iv[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&iv[8..], &[0u8; 8]);
    }

    #[test]
    fn cipher_mode_strings_xts() {
        let (name, mode) = cipher_mode_strings(CipherMode::AesXtsPlain64);
        assert_eq!(name, "aes");
        assert_eq!(mode, "xts-plain64");
    }

    #[test]
    fn cipher_mode_strings_cbc() {
        let (name, mode) = cipher_mode_strings(CipherMode::AesCbcEssiv);
        assert_eq!(name, "aes");
        assert_eq!(mode, "cbc-essiv:sha256");
    }

    #[test]
    fn create_luks1_header_default_iterations() {
        // Test without explicit iterations (uses default)
        let (header_bytes, _master_key) = create_luks1_header(
            b"pass",
            CipherMode::AesXtsPlain64,
            64,
            None,
        )
        .unwrap();

        let header = LuksHeader::parse(&header_bytes).unwrap();
        if let LuksHeader::V1(h) = header {
            assert_eq!(h.mk_digest_iter, DEFAULT_PBKDF2_ITERATIONS);
            assert_eq!(h.key_slots[0].iterations, DEFAULT_PBKDF2_ITERATIONS);
        } else {
            panic!("expected V1");
        }
    }

    #[test]
    fn create_luks1_header_key_slot_alignment() {
        let (header_bytes, _) = create_luks1_header(
            b"pass",
            CipherMode::AesXtsPlain64,
            64,
            Some(100),
        )
        .unwrap();

        let header = LuksHeader::parse(&header_bytes).unwrap();
        if let LuksHeader::V1(h) = header {
            // All key material offsets should be 8-sector (4KB) aligned
            for slot in &h.key_slots {
                assert_eq!(slot.key_material_offset % 8, 0,
                    "offset {} not 8-sector aligned", slot.key_material_offset);
            }
            // Only slot 0 active
            assert!(h.key_slots[0].active);
            for slot in &h.key_slots[1..] {
                assert!(!slot.active);
            }
        }
    }
}
