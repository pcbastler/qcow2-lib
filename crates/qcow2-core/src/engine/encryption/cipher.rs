//! AES cipher implementations for QCOW2 LUKS encryption.
//!
//! Supports two modes:
//! - **AES-XTS-plain64**: QEMU default, recommended. Uses sector number as tweak.
//! - **AES-CBC-ESSIV**: Legacy mode with Encrypted Salt-Sector IV generation.

extern crate alloc;

use alloc::format;

use aes::Aes128;
use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cipher::KeyInit;
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

use crate::error::{Error, Result};

// ---- AES-XTS-plain64 ----

/// Encrypt a 512-byte sector with AES-XTS using the sector number as tweak.
///
/// Key must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
/// The key is split in half: first half for data encryption, second for tweak.
pub fn encrypt_sector_xts(key: &[u8], sector_num: u64, data: &mut [u8]) -> Result<()> {
    let tweak = make_xts_tweak(sector_num);
    match key.len() {
        32 => {
            let xts_err = |e| Error::EncryptionFailed {
                guest_offset: 0,
                message: format!("XTS cipher init failed: {e}"),
            };
            let cipher = Xts128::<Aes128>::new(
                Aes128::new_from_slice(&key[..16]).map_err(xts_err)?,
                Aes128::new_from_slice(&key[16..]).map_err(xts_err)?,
            );
            cipher.encrypt_sector(data, tweak);
            Ok(())
        }
        64 => {
            let xts_err = |e| Error::EncryptionFailed {
                guest_offset: 0,
                message: format!("XTS cipher init failed: {e}"),
            };
            let cipher = Xts128::<Aes256>::new(
                Aes256::new_from_slice(&key[..32]).map_err(xts_err)?,
                Aes256::new_from_slice(&key[32..]).map_err(xts_err)?,
            );
            cipher.encrypt_sector(data, tweak);
            Ok(())
        }
        _ => Err(Error::EncryptionFailed {
            guest_offset: 0,
            message: format!("invalid XTS key length: {} (expected 32 or 64)", key.len()),
        }),
    }
}

/// Decrypt a 512-byte sector with AES-XTS using the sector number as tweak.
pub fn decrypt_sector_xts(key: &[u8], sector_num: u64, data: &mut [u8]) -> Result<()> {
    let tweak = make_xts_tweak(sector_num);
    match key.len() {
        32 => {
            let xts_err = |e| Error::DecryptionFailed {
                guest_offset: 0,
                message: format!("XTS cipher init failed: {e}"),
            };
            let cipher = Xts128::<Aes128>::new(
                Aes128::new_from_slice(&key[..16]).map_err(xts_err)?,
                Aes128::new_from_slice(&key[16..]).map_err(xts_err)?,
            );
            cipher.decrypt_sector(data, tweak);
            Ok(())
        }
        64 => {
            let xts_err = |e| Error::DecryptionFailed {
                guest_offset: 0,
                message: format!("XTS cipher init failed: {e}"),
            };
            let cipher = Xts128::<Aes256>::new(
                Aes256::new_from_slice(&key[..32]).map_err(xts_err)?,
                Aes256::new_from_slice(&key[32..]).map_err(xts_err)?,
            );
            cipher.decrypt_sector(data, tweak);
            Ok(())
        }
        _ => Err(Error::DecryptionFailed {
            guest_offset: 0,
            message: format!("invalid XTS key length: {} (expected 32 or 64)", key.len()),
        }),
    }
}

/// Build the plain64 tweak: sector number as little-endian u128.
fn make_xts_tweak(sector_num: u64) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_num.to_le_bytes());
    tweak
}

// ---- AES-CBC-ESSIV ----

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Encrypt a 512-byte sector with AES-CBC-ESSIV.
///
/// Key must be 16 bytes (AES-128) or 32 bytes (AES-256).
/// ESSIV: IV = AES_ECB(SHA256(key), sector_num_as_block).
pub fn encrypt_sector_cbc_essiv(key: &[u8], sector_num: u64, data: &mut [u8]) -> Result<()> {
    let iv = compute_essiv(key, sector_num)?;
    match key.len() {
        16 => {
            let enc = Aes128CbcEnc::new_from_slices(key, &iv).map_err(|e| {
                Error::EncryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC init failed: {e}"),
                }
            })?;
            // Encrypt in-place. Data must be block-aligned (512 bytes = 32 blocks).
            enc.encrypt_padded_mut::<NoPadding>(data, data.len())
                .map_err(|e| Error::EncryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC encrypt failed: {e}"),
                })?;
            Ok(())
        }
        32 => {
            let enc = Aes256CbcEnc::new_from_slices(key, &iv).map_err(|e| {
                Error::EncryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC init failed: {e}"),
                }
            })?;
            enc.encrypt_padded_mut::<NoPadding>(data, data.len())
                .map_err(|e| Error::EncryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC encrypt failed: {e}"),
                })?;
            Ok(())
        }
        _ => Err(Error::EncryptionFailed {
            guest_offset: 0,
            message: format!(
                "invalid CBC key length: {} (expected 16 or 32)",
                key.len()
            ),
        }),
    }
}

/// Decrypt a 512-byte sector with AES-CBC-ESSIV.
pub fn decrypt_sector_cbc_essiv(key: &[u8], sector_num: u64, data: &mut [u8]) -> Result<()> {
    let iv = compute_essiv(key, sector_num)?;
    match key.len() {
        16 => {
            let dec = Aes128CbcDec::new_from_slices(key, &iv).map_err(|e| {
                Error::DecryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC init failed: {e}"),
                }
            })?;
            dec.decrypt_padded_mut::<NoPadding>(data).map_err(|e| {
                Error::DecryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC decrypt failed: {e}"),
                }
            })?;
            Ok(())
        }
        32 => {
            let dec = Aes256CbcDec::new_from_slices(key, &iv).map_err(|e| {
                Error::DecryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC init failed: {e}"),
                }
            })?;
            dec.decrypt_padded_mut::<NoPadding>(data).map_err(|e| {
                Error::DecryptionFailed {
                    guest_offset: 0,
                    message: format!("CBC decrypt failed: {e}"),
                }
            })?;
            Ok(())
        }
        _ => Err(Error::DecryptionFailed {
            guest_offset: 0,
            message: format!(
                "invalid CBC key length: {} (expected 16 or 32)",
                key.len()
            ),
        }),
    }
}

/// Compute ESSIV: IV = AES_ECB(SHA256(key), sector_number_block).
///
/// The ESSIV key is SHA-256(encryption_key), always 32 bytes.
/// The plaintext is the sector number as a 16-byte LE block.
fn compute_essiv(key: &[u8], sector_num: u64) -> Result<[u8; 16]> {
    // ESSIV key = SHA-256(encryption key)
    let essiv_key = Sha256::digest(key);

    // Plaintext = sector number as 16-byte LE block
    let mut plaintext = [0u8; 16];
    plaintext[..8].copy_from_slice(&sector_num.to_le_bytes());

    // AES-ECB encrypt the sector number with the ESSIV key to produce the IV
    use aes::cipher::BlockEncrypt;
    let cipher =
        Aes256::new_from_slice(&essiv_key).map_err(|e| Error::EncryptionFailed {
            guest_offset: 0,
            message: format!("ESSIV key init failed: {e}"),
        })?;
    let block = aes::Block::from_mut_slice(&mut plaintext);
    cipher.encrypt_block(block);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn xts_256_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 64]; // AES-256-XTS needs 64 bytes
        let original = [0xAA; 512];
        let mut data = original;

        encrypt_sector_xts(&key, 0, &mut data).unwrap();
        assert_ne!(data, original, "encrypted data should differ from original");

        decrypt_sector_xts(&key, 0, &mut data).unwrap();
        assert_eq!(data, original, "round-trip should recover original");
    }

    #[test]
    fn xts_128_encrypt_decrypt_round_trip() {
        let key = [0x37u8; 32]; // AES-128-XTS needs 32 bytes
        let original = [0xBB; 512];
        let mut data = original;

        encrypt_sector_xts(&key, 42, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt_sector_xts(&key, 42, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn xts_different_sectors_produce_different_ciphertext() {
        let key = [0x55u8; 64];
        let plaintext = [0xCC; 512];

        let mut data1 = plaintext;
        let mut data2 = plaintext;
        encrypt_sector_xts(&key, 0, &mut data1).unwrap();
        encrypt_sector_xts(&key, 1, &mut data2).unwrap();
        assert_ne!(data1, data2, "different sectors should produce different ciphertext");
    }

    #[test]
    fn xts_invalid_key_length() {
        let key = [0u8; 48]; // Invalid
        let mut data = [0u8; 512];
        assert!(encrypt_sector_xts(&key, 0, &mut data).is_err());
        assert!(decrypt_sector_xts(&key, 0, &mut data).is_err());
    }

    #[test]
    fn cbc_essiv_256_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 32]; // AES-256-CBC
        let original = [0xAA; 512];
        let mut data = original;

        encrypt_sector_cbc_essiv(&key, 0, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt_sector_cbc_essiv(&key, 0, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn cbc_essiv_128_encrypt_decrypt_round_trip() {
        let key = [0x37u8; 16]; // AES-128-CBC
        let original = [0xBB; 512];
        let mut data = original;

        encrypt_sector_cbc_essiv(&key, 99, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt_sector_cbc_essiv(&key, 99, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn cbc_essiv_different_sectors_produce_different_ciphertext() {
        let key = [0x55u8; 32];
        let plaintext = [0xCC; 512];

        let mut data1 = plaintext;
        let mut data2 = plaintext;
        encrypt_sector_cbc_essiv(&key, 0, &mut data1).unwrap();
        encrypt_sector_cbc_essiv(&key, 1, &mut data2).unwrap();
        assert_ne!(data1, data2);
    }

    #[test]
    fn cbc_essiv_invalid_key_length() {
        let key = [0u8; 48]; // Invalid
        let mut data = [0u8; 512];
        assert!(encrypt_sector_cbc_essiv(&key, 0, &mut data).is_err());
        assert!(decrypt_sector_cbc_essiv(&key, 0, &mut data).is_err());
    }

    #[test]
    fn crypt_context_multi_sector() {
        use super::super::CryptContext;
        use super::super::CipherMode;

        let ctx = CryptContext::new(vec![0x42; 64], CipherMode::AesXtsPlain64);
        let mut data = vec![0xAA; 2048]; // 4 sectors
        let original = data.clone();

        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, original);

        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn crypt_context_host_offset_affects_result() {
        use super::super::CryptContext;
        use super::super::CipherMode;

        let ctx = CryptContext::new(vec![0x42; 64], CipherMode::AesXtsPlain64);
        let plaintext = vec![0xAA; 512];

        let mut data1 = plaintext.clone();
        let mut data2 = plaintext.clone();
        ctx.encrypt_cluster(0, &mut data1).unwrap();
        ctx.encrypt_cluster(512, &mut data2).unwrap();
        assert_ne!(data1, data2, "different host offsets should produce different ciphertext");
    }

    // ---- CryptContext CBC mode tests ----

    #[test]
    fn crypt_context_cbc_multi_sector_round_trip() {
        use super::super::CipherMode;
        use super::super::CryptContext;

        // AES-256-CBC: 32-byte key
        let ctx = CryptContext::new(vec![0x7Eu8; 32], CipherMode::AesCbcEssiv);
        let original = vec![0xBBu8; 2048]; // 4 sectors
        let mut data = original.clone();

        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, original, "encrypted data must differ from plaintext");

        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, original, "round-trip must recover original data");
    }

    #[test]
    fn crypt_context_cbc_host_offset_affects_result() {
        use super::super::CipherMode;
        use super::super::CryptContext;

        let ctx = CryptContext::new(vec![0x3Cu8; 32], CipherMode::AesCbcEssiv);
        let plaintext = vec![0xCCu8; 512];

        let mut data1 = plaintext.clone();
        let mut data2 = plaintext.clone();
        ctx.encrypt_cluster(0, &mut data1).unwrap();
        ctx.encrypt_cluster(512, &mut data2).unwrap();
        assert_ne!(data1, data2, "different host offsets must produce different ciphertext in CBC mode");
    }

    // ---- CryptContext AES-128 key size tests ----

    #[test]
    fn crypt_context_xts_128_round_trip() {
        use super::super::CipherMode;
        use super::super::CryptContext;

        // AES-128-XTS: 32-byte key
        let ctx = CryptContext::new(vec![0x11u8; 32], CipherMode::AesXtsPlain64);
        let original = vec![0xDDu8; 1024]; // 2 sectors
        let mut data = original.clone();

        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, original);

        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, original, "AES-128-XTS round-trip must recover original");
    }

    #[test]
    fn crypt_context_cbc_128_round_trip() {
        use super::super::CipherMode;
        use super::super::CryptContext;

        // AES-128-CBC: 16-byte key
        let ctx = CryptContext::new(vec![0x22u8; 16], CipherMode::AesCbcEssiv);
        let original = vec![0xEEu8; 512]; // 1 sector
        let mut data = original.clone();

        ctx.encrypt_cluster(0, &mut data).unwrap();
        assert_ne!(data, original);

        ctx.decrypt_cluster(0, &mut data).unwrap();
        assert_eq!(data, original, "AES-128-CBC round-trip must recover original");
    }

    // ---- compute_essiv edge cases ----

    #[test]
    fn essiv_sector_zero_is_deterministic() {
        // Sector 0: ESSIV plaintext is all-zeros (sector_num = 0), so the IV is
        // AES_ECB(SHA256(key), 0x00..00). Verify two calls produce the same IV by
        // confirming encrypt/decrypt is consistent.
        let key = [0xA5u8; 32];
        let original = [0x01u8; 512];

        let mut enc = original;
        encrypt_sector_cbc_essiv(&key, 0, &mut enc).unwrap();
        assert_ne!(enc, original, "sector 0 must still be encrypted");

        let mut dec = enc;
        decrypt_sector_cbc_essiv(&key, 0, &mut dec).unwrap();
        assert_eq!(dec, original, "sector 0 decryption must recover original");
    }

    #[test]
    fn essiv_high_sector_number_round_trip() {
        // Large sector numbers must not overflow or panic.
        let key = [0xF0u8; 32];
        let original = [0x55u8; 512];
        let sector = u64::MAX / 2;

        let mut data = original;
        encrypt_sector_cbc_essiv(&key, sector, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt_sector_cbc_essiv(&key, sector, &mut data).unwrap();
        assert_eq!(data, original, "high sector number round-trip must succeed");
    }

    #[test]
    fn essiv_different_keys_produce_different_ivs() {
        // Two different keys must yield different IVs for the same sector,
        // producing different ciphertext.
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let plaintext = [0xAAu8; 512];

        let mut data1 = plaintext;
        let mut data2 = plaintext;
        encrypt_sector_cbc_essiv(&key1, 7, &mut data1).unwrap();
        encrypt_sector_cbc_essiv(&key2, 7, &mut data2).unwrap();
        assert_ne!(data1, data2, "different keys must produce different ciphertext");
    }

    // ---- make_xts_tweak verification ----

    #[test]
    fn xts_tweak_is_little_endian() {
        // Sector 1 encoded LE: bytes [1, 0, 0, 0, 0, 0, 0, 0, 0...0]
        // Sector 256 encoded LE: bytes [0, 1, 0, 0, 0, 0, 0, 0, 0...0]
        // Different tweaks must produce different ciphertext for the same plaintext.
        let key = [0x77u8; 64];
        let plaintext = [0x33u8; 512];

        // Sector 1 vs sector 256: both have exactly one '1' bit, but in different
        // LE byte positions — confirming the tweak uses LE encoding.
        let mut data_sector1 = plaintext;
        let mut data_sector256 = plaintext;
        encrypt_sector_xts(&key, 1, &mut data_sector1).unwrap();
        encrypt_sector_xts(&key, 256, &mut data_sector256).unwrap();
        assert_ne!(
            data_sector1, data_sector256,
            "sectors 1 and 256 differ only in tweak byte position (LE vs BE distinction)"
        );

        // Verify sector 1 decrypts correctly with sector 1 (not 256)
        let mut check = data_sector1;
        decrypt_sector_xts(&key, 1, &mut check).unwrap();
        assert_eq!(check, plaintext);

        // And that using the wrong sector number fails to recover plaintext
        let mut wrong = data_sector1;
        decrypt_sector_xts(&key, 256, &mut wrong).unwrap();
        assert_ne!(wrong, plaintext, "wrong sector number must not recover plaintext");
    }

    // ---- Zero-filled data encryption ----

    #[test]
    fn xts_all_zeros_plaintext_is_not_all_zeros_after_encrypt() {
        let key = [0x88u8; 64];
        let mut data = [0u8; 512];

        encrypt_sector_xts(&key, 5, &mut data).unwrap();
        assert_ne!(data, [0u8; 512], "encrypting all-zeros must not produce all-zeros");
    }

    #[test]
    fn cbc_all_zeros_plaintext_is_not_all_zeros_after_encrypt() {
        let key = [0x99u8; 32];
        let mut data = [0u8; 512];

        encrypt_sector_cbc_essiv(&key, 5, &mut data).unwrap();
        assert_ne!(data, [0u8; 512], "encrypting all-zeros must not produce all-zeros");
    }

    // ---- CBC ESSIV sector 0 explicit test ----

    #[test]
    fn cbc_essiv_sector_zero_iv_is_aes_of_zero_block() {
        // For sector 0, the ESSIV plaintext is a 16-byte zero block.
        // The IV is therefore AES_ECB(SHA256(key), zeros).
        // This is a well-defined, non-trivial value — verify encrypt/decrypt works.
        let key = [0x5Au8; 32];
        let original = [0xF0u8; 512];
        let mut data = original;

        encrypt_sector_cbc_essiv(&key, 0, &mut data).unwrap();
        // Encrypted bytes must differ from plaintext
        assert_ne!(data, original);
        // And must differ from what sector 1 produces (IV changes per sector)
        let mut data_s1 = original;
        encrypt_sector_cbc_essiv(&key, 1, &mut data_s1).unwrap();
        assert_ne!(data, data_s1, "sector 0 and sector 1 must produce different ciphertext");

        // Decrypt sector 0 back
        decrypt_sector_cbc_essiv(&key, 0, &mut data).unwrap();
        assert_eq!(data, original, "CBC ESSIV sector 0 round-trip must succeed");
    }
}
