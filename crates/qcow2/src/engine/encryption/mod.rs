//! LUKS encryption support for QCOW2 images.
//!
//! Re-exports core encryption types from [`qcow2_core::engine::encryption`]
//! and adds std-only functionality:
//! - LUKS header parsing (`luks_header`)
//! - Encryption creation helpers (`create`)
//! - Master key recovery (`recover_master_key`)

// Re-export core types and sub-modules
pub use qcow2_core::engine::encryption::{
    cipher, CipherMode, CryptContext,
};

// Local af_splitter with working af_split (uses rand, not available in no_std core)
pub mod af_splitter;
// Local key_derivation with Argon2id support (not available in no_std core)
pub mod key_derivation;

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

    Err(Error::WrongPassword) // luks1 no match
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use byteorder::{BigEndian, ByteOrder};

    /// Write a null-terminated string into a fixed-size buffer.
    fn write_str(buf: &mut [u8], s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(buf.len() - 1);
        buf[..len].copy_from_slice(&bytes[..len]);
    }

    /// Build a LUKS2 binary blob with a single keyslot protecting `master_key`.
    ///
    /// Layout:
    ///  0..4096    : LUKS2 binary header (first copy)
    ///  4096..16384: JSON metadata (null-terminated)
    ///  16384..32768: (secondary header placeholder, zeroed)
    ///  32768..end : encrypted key material
    ///
    /// Returns the full blob.
    #[allow(clippy::too_many_lines)]
    fn build_luks2_blob(
        password: &[u8],
        master_key: &[u8],
        cipher_mode: CipherMode,
    ) -> Vec<u8> {
        use af_splitter::AfHash;
        use key_derivation::{Kdf, KdfHash};

        let key_bytes = master_key.len();
        let stripes = 4000u32;
        let km_offset: usize = 32768; // after two 16384-byte header copies
        let km_size: usize = key_bytes * stripes as usize;

        // Salts for KDF and digest (fixed for determinism)
        let kdf_salt = vec![0x11u8; 32];
        let digest_salt = vec![0x22u8; 32];

        // 1. Derive the slot key from the password
        let slot_kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: kdf_salt.clone(),
        };
        let split_key =
            key_derivation::derive_key(&slot_kdf, password, key_bytes).unwrap();

        // 2. AF-split the master key
        let mut split_material =
            af_splitter::af_split(master_key, stripes, AfHash::Sha256).unwrap();

        // 3. Encrypt the split material
        create::encrypt_key_material(&split_key, cipher_mode, &mut split_material).unwrap();

        // 4. Compute the digest: PBKDF2(master_key, digest_salt, 1000) → 32 bytes
        let digest_kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: digest_salt.clone(),
        };
        let digest_bytes =
            key_derivation::derive_key(&digest_kdf, master_key, 32).unwrap();

        // 5. Base64-encode salts and digest for JSON
        let kdf_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode(kdf_salt.as_slice());
        let digest_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode(digest_salt.as_slice());
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(digest_bytes.as_slice());

        // Encryption string for the segment and area
        let enc_string = match cipher_mode {
            CipherMode::AesXtsPlain64 => "aes-xts-plain64",
            CipherMode::AesCbcEssiv => "aes-cbc-essiv:sha256",
        };

        let json = format!(
            r#"{{
    "keyslots": {{
        "0": {{
            "type": "luks2",
            "key_size": {key_bytes},
            "af": {{ "type": "luks1", "hash": "sha256", "stripes": {stripes} }},
            "kdf": {{ "type": "pbkdf2", "salt": "{kdf_salt_b64}", "hash": "sha256", "iterations": 1000 }},
            "area": {{ "type": "raw", "offset": "{km_offset}", "size": "{km_size}", "encryption": "{enc_string}", "key_size": {key_bytes} }}
        }}
    }},
    "segments": {{
        "0": {{
            "type": "crypt",
            "offset": "65536",
            "size": "dynamic",
            "encryption": "{enc_string}",
            "sector_size": 512
        }}
    }},
    "digests": {{
        "0": {{
            "type": "pbkdf2",
            "keyslots": ["0"],
            "segments": ["0"],
            "hash": "sha256",
            "iterations": 1000,
            "salt": "{digest_salt_b64}",
            "digest": "{digest_b64}"
        }}
    }}
}}"#
        );

        // Assemble the full blob:
        // [binary header 4096 B][JSON up to 16384 B][secondary header 16384 B][key material]
        let hdr_size: u64 = 16384;
        let total_size = km_offset + km_size;
        let mut blob = vec![0u8; total_size];

        // Binary header
        blob[..6].copy_from_slice(b"LUKS\xba\xbe");
        BigEndian::write_u16(&mut blob[6..8], 2u16);
        BigEndian::write_u64(&mut blob[8..16], hdr_size);
        BigEndian::write_u64(&mut blob[16..24], 1u64); // seqid
        write_str(&mut blob[24..72], "test");
        write_str(&mut blob[72..104], "sha256");
        // salt at 104..168 (zeroed)
        write_str(&mut blob[168..208], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        BigEndian::write_u64(&mut blob[208..216], 0u64); // hdr_offset

        // JSON metadata starting at offset 4096
        let json_bytes = json.as_bytes();
        assert!(
            json_bytes.len() < hdr_size as usize - 4096,
            "JSON too large for header area"
        );
        blob[4096..4096 + json_bytes.len()].copy_from_slice(json_bytes);

        // Key material at km_offset
        blob[km_offset..km_offset + km_size].copy_from_slice(&split_material);

        blob
    }

    #[test]
    fn recover_luks2_xts_roundtrip() {
        let master_key = vec![0xABu8; 64]; // 64-byte key for XTS
        let password = b"luks2-xts-password";

        let blob = build_luks2_blob(password, &master_key, CipherMode::AesXtsPlain64);
        let ctx = recover_master_key(&blob, password).expect("should recover key");

        assert_eq!(ctx.cipher_mode(), CipherMode::AesXtsPlain64);
        assert_eq!(ctx.key_len(), 64);

        // Verify the recovered key is actually correct by encrypt/decrypt roundtrip
        let plaintext = vec![0x55u8; 512];
        let mut data = plaintext.clone();
        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, plaintext, "encrypted data should differ");
        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, plaintext, "decrypted data should match original");
    }

    #[test]
    fn recover_luks2_cbc_roundtrip() {
        let master_key = vec![0xCDu8; 32]; // 32-byte key for CBC
        let password = b"luks2-cbc-password";

        let blob = build_luks2_blob(password, &master_key, CipherMode::AesCbcEssiv);
        let ctx = recover_master_key(&blob, password).expect("should recover key");

        assert_eq!(ctx.cipher_mode(), CipherMode::AesCbcEssiv);
        assert_eq!(ctx.key_len(), 32);

        // Verify the recovered key is actually correct
        let plaintext = vec![0x77u8; 512];
        let mut data = plaintext.clone();
        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, plaintext);
        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, plaintext);
    }

    #[test]
    fn recover_luks2_wrong_password() {
        let master_key = vec![0xABu8; 64];
        let blob = build_luks2_blob(b"correct", &master_key, CipherMode::AesXtsPlain64);

        let result = recover_master_key(&blob, b"wrong-password");
        assert!(
            matches!(result, Err(Error::WrongPassword)),
            "expected WrongPassword, got: {result:?}"
        );
    }

    #[test]
    fn recover_luks2_out_of_bounds_key_material() {
        // Build JSON where area.offset+size points beyond the blob
        let kdf_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let digest_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
        // Dummy digest — won't be reached since the slot is skipped
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x00u8; 32]);

        let json = format!(
            r#"{{
    "keyslots": {{
        "0": {{
            "type": "luks2",
            "key_size": 64,
            "af": {{ "type": "luks1", "hash": "sha256", "stripes": 4000 }},
            "kdf": {{ "type": "pbkdf2", "salt": "{kdf_salt_b64}", "hash": "sha256", "iterations": 1000 }},
            "area": {{ "type": "raw", "offset": "999999999", "size": "262144000", "encryption": "aes-xts-plain64", "key_size": 64 }}
        }}
    }},
    "segments": {{
        "0": {{
            "type": "crypt",
            "offset": "65536",
            "size": "dynamic",
            "encryption": "aes-xts-plain64",
            "sector_size": 512
        }}
    }},
    "digests": {{
        "0": {{
            "type": "pbkdf2",
            "keyslots": ["0"],
            "segments": ["0"],
            "hash": "sha256",
            "iterations": 1000,
            "salt": "{digest_salt_b64}",
            "digest": "{digest_b64}"
        }}
    }}
}}"#
        );

        let hdr_size: u64 = 16384;
        let mut blob = vec![0u8; 32768]; // Small blob — km_offset will be OOB
        blob[..6].copy_from_slice(b"LUKS\xba\xbe");
        BigEndian::write_u16(&mut blob[6..8], 2u16);
        BigEndian::write_u64(&mut blob[8..16], hdr_size);
        BigEndian::write_u64(&mut blob[16..24], 1u64);
        write_str(&mut blob[72..104], "sha256");
        write_str(&mut blob[168..208], "test-uuid");
        let json_bytes = json.as_bytes();
        blob[4096..4096 + json_bytes.len()].copy_from_slice(json_bytes);

        // The slot should be skipped (OOB), so we expect WrongPassword
        let result = recover_master_key(&blob, b"any-password");
        assert!(
            matches!(result, Err(Error::WrongPassword)),
            "expected WrongPassword for OOB slot, got: {result:?}"
        );
    }

    #[test]
    fn recover_luks2_invalid_area_offset() {
        // Build JSON where area.offset is not a valid integer
        let kdf_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let digest_salt_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode([0x00u8; 32]);

        let json = format!(
            r#"{{
    "keyslots": {{
        "0": {{
            "type": "luks2",
            "key_size": 64,
            "af": {{ "type": "luks1", "hash": "sha256", "stripes": 4000 }},
            "kdf": {{ "type": "pbkdf2", "salt": "{kdf_salt_b64}", "hash": "sha256", "iterations": 1000 }},
            "area": {{ "type": "raw", "offset": "abc", "size": "262144", "encryption": "aes-xts-plain64", "key_size": 64 }}
        }}
    }},
    "segments": {{
        "0": {{
            "type": "crypt",
            "offset": "65536",
            "size": "dynamic",
            "encryption": "aes-xts-plain64",
            "sector_size": 512
        }}
    }},
    "digests": {{
        "0": {{
            "type": "pbkdf2",
            "keyslots": ["0"],
            "segments": ["0"],
            "hash": "sha256",
            "iterations": 1000,
            "salt": "{digest_salt_b64}",
            "digest": "{digest_b64}"
        }}
    }}
}}"#
        );

        let hdr_size: u64 = 16384;
        let mut blob = vec![0u8; 65536];
        blob[..6].copy_from_slice(b"LUKS\xba\xbe");
        BigEndian::write_u16(&mut blob[6..8], 2u16);
        BigEndian::write_u64(&mut blob[8..16], hdr_size);
        BigEndian::write_u64(&mut blob[16..24], 1u64);
        write_str(&mut blob[72..104], "sha256");
        write_str(&mut blob[168..208], "test-uuid");
        let json_bytes = json.as_bytes();
        blob[4096..4096 + json_bytes.len()].copy_from_slice(json_bytes);

        let result = recover_master_key(&blob, b"any-password");
        assert!(
            result.is_err(),
            "expected error for invalid area offset, got Ok"
        );
        // Should be an InvalidLuksHeader error (not WrongPassword)
        assert!(
            !matches!(result, Err(Error::WrongPassword)),
            "expected InvalidLuksHeader, not WrongPassword"
        );
    }
}
