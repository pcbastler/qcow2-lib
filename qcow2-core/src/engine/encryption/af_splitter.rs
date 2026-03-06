//! Anti-forensic information splitter for LUKS key material.
//!
//! LUKS uses AF splitting to spread the master key across many disk sectors,
//! making partial recovery impossible. The key is inflated by a factor of
//! `stripes` using a hash-based diffuse function.
//!
//! Reference: LUKS On-Disk Format Specification, Section 2.4.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// Hash algorithm used for the diffuse function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfHash {
    Sha1,
    Sha256,
    Sha512,
}

impl AfHash {
    /// Parse from LUKS header hash_spec string.
    pub fn from_spec(spec: &str) -> Result<Self> {
        match spec {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(Error::InvalidLuksHeader {
                message: format!("unsupported hash spec: {spec}"),
            }),
        }
    }

    /// Digest size in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Hash a block of data.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Apply the diffuse function to a data block.
///
/// Splits the block into hash-sized chunks, hashes each chunk with its
/// index prepended, and reassembles. This creates interdependencies
/// between all parts of the data.
fn diffuse(data: &[u8], hash: AfHash) -> Vec<u8> {
    let digest_size = hash.digest_size();
    let mut result = Vec::with_capacity(data.len());
    let full_blocks = data.len() / digest_size;
    let remainder = data.len() % digest_size;

    for i in 0..full_blocks {
        let start = i * digest_size;
        let chunk = &data[start..start + digest_size];
        let mut input = Vec::with_capacity(4 + digest_size);
        input.extend_from_slice(&(i as u32).to_be_bytes());
        input.extend_from_slice(chunk);
        result.extend_from_slice(&hash.hash(&input));
    }

    if remainder > 0 {
        let start = full_blocks * digest_size;
        let chunk = &data[start..];
        let mut input = Vec::with_capacity(4 + remainder);
        input.extend_from_slice(&(full_blocks as u32).to_be_bytes());
        input.extend_from_slice(chunk);
        let h = hash.hash(&input);
        result.extend_from_slice(&h[..remainder]);
    }

    result
}

/// XOR two equal-length byte slices, writing the result into `dst`.
fn xor_buffers(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// AF merge: recover the original key from split key material.
///
/// This is the inverse of AF split. Takes `stripes * key_len` bytes of
/// decrypted key material and recovers the original `key_len` bytes.
///
/// Algorithm:
/// 1. d = stripe[0]
/// 2. for i in 1..stripes-1: d = diffuse(d) XOR stripe[i]
/// 3. result = diffuse(d) XOR stripe[stripes-1]
pub fn af_merge(
    split_material: &[u8],
    key_len: usize,
    stripes: u32,
    hash: AfHash,
) -> Result<Vec<u8>> {
    if split_material.len() != key_len * stripes as usize {
        return Err(Error::InvalidLuksHeader {
            message: format!(
                "AF material size {} != key_len {} * stripes {}",
                split_material.len(),
                key_len,
                stripes
            ),
        });
    }

    let mut d = split_material[..key_len].to_vec();

    for i in 1..stripes as usize {
        let diffused = diffuse(&d, hash);
        d.copy_from_slice(&diffused);
        let stripe = &split_material[i * key_len..(i + 1) * key_len];
        xor_buffers(&mut d, stripe);
    }

    Ok(d)
}

/// AF split: split a key into `stripes` stripes for storage.
///
/// Generates `stripes - 1` random stripes and computes the final stripe
/// such that `af_merge` recovers the original key.
///
/// **Note:** Not available in `no_std` mode (requires `rand` crate).
/// Use the `qcow2` crate for LUKS key creation.
pub fn af_split(
    _key: &[u8],
    _stripes: u32,
    _hash: AfHash,
) -> Result<Vec<u8>> {
    Err(Error::KeyDerivationFailed {
        message: alloc::string::String::from(
            "af_split is not available in no_std mode (requires rand crate)"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn af_split_not_available_in_no_std() {
        let key = b"0123456789abcdef0123456789abcdef";
        let result = af_split(key, 4000, AfHash::Sha256);
        assert!(result.is_err());
    }

    #[test]
    fn af_merge_wrong_size_returns_error() {
        let result = af_merge(&[0u8; 100], 32, 4, AfHash::Sha256);
        assert!(result.is_err());
    }

    #[test]
    fn diffuse_deterministic() {
        let data = vec![0x42; 32];
        let d1 = diffuse(&data, AfHash::Sha256);
        let d2 = diffuse(&data, AfHash::Sha256);
        assert_eq!(d1, d2);
    }

    #[test]
    fn diffuse_changes_data() {
        let data = vec![0x42; 32];
        let diffused = diffuse(&data, AfHash::Sha256);
        assert_ne!(diffused, data);
    }
}
