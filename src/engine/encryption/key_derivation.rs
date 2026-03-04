//! Key derivation functions for LUKS master key recovery.
//!
//! LUKS1 uses PBKDF2 exclusively. LUKS2 supports both PBKDF2 and Argon2id.

use hmac::Hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// Supported key derivation functions.
#[derive(Debug, Clone)]
pub enum Kdf {
    /// PBKDF2 with the specified hash algorithm.
    Pbkdf2 {
        hash: KdfHash,
        iterations: u32,
        salt: Vec<u8>,
    },
    /// Argon2id (LUKS2).
    Argon2id {
        time: u32,
        memory: u32,
        cpus: u32,
        salt: Vec<u8>,
    },
}

/// Hash algorithms for PBKDF2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    Sha1,
    Sha256,
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
        Kdf::Argon2id {
            time,
            memory,
            cpus,
            salt,
        } => argon2id_derive(password, salt, *time, *memory, *cpus, output_len),
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

/// Argon2id key derivation (LUKS2).
fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    let params = argon2::Params::new(memory_cost, time_cost, parallelism, Some(output_len))
        .map_err(|e| Error::KeyDerivationFailed {
            message: format!("Argon2 params: {e}"),
        })?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| Error::KeyDerivationFailed {
            message: format!("Argon2id: {e}"),
        })?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pbkdf2_different_passwords_different_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: vec![0x42; 32],
        };
        let r1 = derive_key(&kdf, b"password1", 32).unwrap();
        let r2 = derive_key(&kdf, b"password2", 32).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn argon2id_produces_output() {
        // Use minimal parameters for test speed
        let kdf = Kdf::Argon2id {
            time: 1,
            memory: 64, // 64 KiB minimum
            cpus: 1,
            salt: vec![0x42; 16],
        };
        let result = derive_key(&kdf, b"password", 32).unwrap();
        assert_eq!(result.len(), 32);
        assert_ne!(result, vec![0u8; 32]);
    }

    #[test]
    fn argon2id_deterministic() {
        let kdf = Kdf::Argon2id {
            time: 1,
            memory: 64,
            cpus: 1,
            salt: vec![0x42; 16],
        };
        let r1 = derive_key(&kdf, b"password", 32).unwrap();
        let r2 = derive_key(&kdf, b"password", 32).unwrap();
        assert_eq!(r1, r2);
    }

    /// RFC 6070 Test Vector #2: PBKDF2-HMAC-SHA1
    /// P = "password", S = "salt", c = 2, dkLen = 20
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
        assert_eq!(result, expected, "PBKDF2-SHA1 RFC 6070 vector #2 mismatch");
    }

    /// RFC 6070 Test Vector #1: PBKDF2-HMAC-SHA1
    /// P = "password", S = "salt", c = 1, dkLen = 20
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
        assert_eq!(result, expected, "PBKDF2-SHA1 RFC 6070 vector #1 mismatch");
    }

    /// PBKDF2-HMAC-SHA256 with 64-byte output (two HMAC blocks).
    /// Verifies multi-block PBKDF2 derivation works correctly
    /// (needed for XTS key_bytes=64).
    #[test]
    fn pbkdf2_sha256_64byte_output() {
        let kdf = Kdf::Pbkdf2 {
            hash: KdfHash::Sha256,
            iterations: 1000,
            salt: b"saltsalt".to_vec(),
        };
        let result = derive_key(&kdf, b"password", 64).unwrap();
        assert_eq!(result.len(), 64);

        // Verify it's deterministic and the two halves differ
        // (they come from different HMAC-SHA256 blocks with counter 1 vs 2)
        let r2 = derive_key(&kdf, b"password", 64).unwrap();
        assert_eq!(result, r2);
        assert_ne!(&result[..32], &result[32..], "two PBKDF2 blocks should differ");
    }
}
