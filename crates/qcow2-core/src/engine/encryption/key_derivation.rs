//! Key derivation functions for LUKS master key recovery.
//!
//! LUKS1 uses PBKDF2 exclusively. LUKS2 supports both PBKDF2 and Argon2id.
//!
//! In `no_std` mode, only PBKDF2 is available. Argon2id requires the `argon2`
//! crate which depends on `std`. The `qcow2` userspace crate provides the
//! Argon2id implementation for LUKS2 support.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hmac::Hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// Supported key derivation functions.
#[derive(Debug, Clone)]
pub enum Kdf {
    /// PBKDF2 with the specified hash algorithm.
    Pbkdf2 {
        /// Hash algorithm to use.
        hash: KdfHash,
        /// Number of iterations.
        iterations: u32,
        /// Salt bytes.
        salt: Vec<u8>,
    },
    /// Argon2id (LUKS2). Not available in `no_std` mode.
    Argon2id {
        /// Time cost parameter.
        time: u32,
        /// Memory cost parameter (in KiB).
        memory: u32,
        /// Parallelism parameter.
        cpus: u32,
        /// Salt bytes.
        salt: Vec<u8>,
    },
}

/// Hash algorithms for PBKDF2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    /// SHA-1 (legacy, used by LUKS1 default).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl KdfHash {
    /// Parse from LUKS header hash_spec string.
    pub fn from_spec(spec: &str) -> Result<Self> {
        match spec {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(Error::InvalidLuksHeader {
                message: format!("unsupported KDF hash: {spec}"),
            }),
        }
    }
}

/// Derive a key using the specified KDF.
///
/// Returns `output_len` bytes of derived key material.
///
/// **Note:** Argon2id is not available in `no_std` mode and will return
/// [`Error::KeyDerivationFailed`]. Use the `qcow2` crate's extended
/// version for LUKS2 support.
pub fn derive_key(
    kdf: &Kdf,
    password: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    match kdf {
        Kdf::Pbkdf2 {
            hash,
            iterations,
            salt,
        } => pbkdf2_derive(password, salt, *iterations, output_len, *hash),
        Kdf::Argon2id { .. } => Err(Error::KeyDerivationFailed {
            message: String::from(
                "Argon2id is not available in no_std mode (requires qcow2 crate)"
            ),
        }),
    }
}

/// PBKDF2 key derivation.
fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
    hash: KdfHash,
) -> Result<Vec<u8>> {
    let mut output = vec![0u8; output_len];

    match hash {
        KdfHash::Sha1 => {
            pbkdf2::pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output)
                .map_err(|e| Error::KeyDerivationFailed {
                    message: format!("PBKDF2-SHA1: {e}"),
                })?;
        }
        KdfHash::Sha256 => {
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output)
                .map_err(|e| Error::KeyDerivationFailed {
                    message: format!("PBKDF2-SHA256: {e}"),
                })?;
        }
        KdfHash::Sha512 => {
            pbkdf2::pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut output)
                .map_err(|e| Error::KeyDerivationFailed {
                    message: format!("PBKDF2-SHA512: {e}"),
                })?;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn pbkdf2_sha256_produces_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: vec![0x42; 32],
        };
        let result = derive_key(&kdf, b"password", 32).unwrap();
        assert_eq!(result.len(), 32);
        assert_ne!(result, vec![0u8; 32], "output should not be all zeros");
    }

    #[test]
    fn pbkdf2_sha1_produces_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha1,
            iterations: 1000,
            salt: vec![0x42; 32],
        };
        let result = derive_key(&kdf, b"password", 32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn pbkdf2_sha512_produces_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha512,
            iterations: 1000,
            salt: vec![0x42; 32],
        };
        let result = derive_key(&kdf, b"password", 64).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: vec![0x42; 32],
        };
        let r1 = derive_key(&kdf, b"password", 32).unwrap();
        let r2 = derive_key(&kdf, b"password", 32).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn argon2id_not_available_in_no_std() {
        let kdf = Kdf::Argon2id {
            time: 1,
            memory: 64,
            cpus: 1,
            salt: vec![0x42; 16],
        };
        let result = derive_key(&kdf, b"password", 32);
        assert!(result.is_err());
    }

    /// RFC 6070 Test Vector #2: PBKDF2-HMAC-SHA1
    #[test]
    fn pbkdf2_sha1_rfc6070_vector() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha1,
            iterations: 2,
            salt: b"salt".to_vec(),
        };
        let result = derive_key(&kdf, b"password", 20).unwrap();
        let expected: [u8; 20] = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
            0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        assert_eq!(result, expected);
    }

    /// RFC 6070 Test Vector #1: PBKDF2-HMAC-SHA1
    #[test]
    fn pbkdf2_sha1_rfc6070_vector_1iter() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha1,
            iterations: 1,
            salt: b"salt".to_vec(),
        };
        let result = derive_key(&kdf, b"password", 20).unwrap();
        let expected: [u8; 20] = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
            0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn kdf_hash_from_spec_sha1() {
        assert_eq!(KdfHash::from_spec("sha1").unwrap(), KdfHash::Sha1);
    }

    #[test]
    fn kdf_hash_from_spec_sha256() {
        assert_eq!(KdfHash::from_spec("sha256").unwrap(), KdfHash::Sha256);
    }

    #[test]
    fn kdf_hash_from_spec_sha512() {
        assert_eq!(KdfHash::from_spec("sha512").unwrap(), KdfHash::Sha512);
    }

    #[test]
    fn kdf_hash_from_spec_unknown() {
        let err = KdfHash::from_spec("md5").unwrap_err();
        assert!(err.to_string().contains("unsupported KDF hash"));
    }

    #[test]
    fn pbkdf2_different_salts_different_output() {
        let kdf1 = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 100,
            salt: vec![0x11; 32],
        };
        let kdf2 = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 100,
            salt: vec![0x22; 32],
        };
        let r1 = derive_key(&kdf1, b"password", 32).unwrap();
        let r2 = derive_key(&kdf2, b"password", 32).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn pbkdf2_different_iterations_different_output() {
        let kdf1 = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 100,
            salt: vec![0x42; 16],
        };
        let kdf2 = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 200,
            salt: vec![0x42; 16],
        };
        let r1 = derive_key(&kdf1, b"password", 32).unwrap();
        let r2 = derive_key(&kdf2, b"password", 32).unwrap();
        assert_ne!(r1, r2);
    }

    /// PBKDF2-HMAC-SHA256 with 64-byte output (two HMAC blocks).
    #[test]
    fn pbkdf2_sha256_64byte_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: b"saltsalt".to_vec(),
        };
        let result = derive_key(&kdf, b"password", 64).unwrap();
        assert_eq!(result.len(), 64);
        let r2 = derive_key(&kdf, b"password", 64).unwrap();
        assert_eq!(result, r2);
        assert_ne!(&result[..32], &result[32..], "two PBKDF2 blocks should differ");
    }
}
