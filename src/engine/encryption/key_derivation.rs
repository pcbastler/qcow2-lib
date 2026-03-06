//! Key derivation wrapper that adds Argon2id support.
//!
//! Re-exports everything from `qcow2_core::engine::encryption::key_derivation`
//! but replaces `derive_key` with a version that supports Argon2id via the
//! `argon2` crate.

pub use qcow2_core::engine::encryption::key_derivation::{Kdf, KdfHash};

use qcow2_core::error::{Error, Result};

/// Derive a key using the specified KDF.
///
/// Supports both PBKDF2 (delegated to core) and Argon2id (std-only).
pub fn derive_key(kdf: &Kdf, password: &[u8], output_len: usize) -> Result<Vec<u8>> {
    match kdf {
        Kdf::Argon2id {
            time,
            memory,
            cpus,
            salt,
        } => argon2id_derive(password, salt, *time, *memory, *cpus, output_len),
        // PBKDF2 is handled by core
        _ => qcow2_core::engine::encryption::key_derivation::derive_key(kdf, password, output_len),
    }
}

/// Argon2id key derivation using the `argon2` crate.
fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    cpus: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(memory, time, cpus, Some(output_len)).map_err(|e| {
        Error::KeyDerivationFailed {
            message: format!("argon2 params error: {e}"),
        }
    })?;

    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; output_len];
    ctx.hash_password_into(password, salt, &mut output)
        .map_err(|e| Error::KeyDerivationFailed {
            message: format!("argon2 derivation error: {e}"),
        })?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let kdf = Kdf::Argon2id {
            time: 1,
            memory: 64,
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

    #[test]
    fn argon2id_derive_key_works() {
        let kdf = Kdf::Argon2id {
            time: 1,
            memory: 64,
            cpus: 1,
            salt: vec![0x42; 16],
        };
        let result = derive_key(&kdf, b"test_password", 64).unwrap();
        assert_eq!(result.len(), 64);
    }
}
