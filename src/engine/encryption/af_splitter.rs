//! Anti-forensic information splitter for LUKS key material.
//!
//! LUKS uses AF splitting to spread the master key across many disk sectors,
//! making partial recovery impossible. The key is inflated by a factor of
//! `stripes` using a hash-based diffuse function.
//!
//! Reference: LUKS On-Disk Format Specification, Section 2.4.

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
pub fn af_split(
    key: &[u8],
    stripes: u32,
    hash: AfHash,
) -> Result<Vec<u8>> {
    use rand::RngCore;

    let key_len = key.len();
    let mut material = vec![0u8; key_len * stripes as usize];

    // Generate random stripes for all but the last
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut material[..key_len * (stripes as usize - 1)]);

    // Compute the accumulated diffuse of all random stripes
    let mut d = material[..key_len].to_vec();
    for i in 1..stripes as usize - 1 {
        let diffused = diffuse(&d, hash);
        d.copy_from_slice(&diffused);
        let stripe = &material[i * key_len..(i + 1) * key_len];
        xor_buffers(&mut d, stripe);
    }

    // Last stripe = diffuse(d) XOR original_key
    let diffused = diffuse(&d, hash);
    d.copy_from_slice(&diffused);
    xor_buffers(&mut d, key);
    material[(stripes as usize - 1) * key_len..].copy_from_slice(&d);

    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_split_merge_round_trip_sha256() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let stripes = 4000;
        let hash = AfHash::Sha256;

        let split = af_split(key, stripes, hash).unwrap();
        assert_eq!(split.len(), 32 * 4000);

        let recovered = af_merge(&split, 32, stripes, hash).unwrap();
        assert_eq!(&recovered, key);
    }

    #[test]
    fn af_split_merge_round_trip_sha1() {
        let key = vec![0xAA; 32];
        let stripes = 4000;
        let hash = AfHash::Sha1;

        let split = af_split(&key, stripes, hash).unwrap();
        let recovered = af_merge(&split, 32, stripes, hash).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn af_split_merge_round_trip_sha512() {
        let key = vec![0xBB; 64];
        let stripes = 4000;
        let hash = AfHash::Sha512;

        let split = af_split(&key, stripes, hash).unwrap();
        let recovered = af_merge(&split, 64, stripes, hash).unwrap();
        assert_eq!(recovered, key);
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

    #[test]
    fn af_split_produces_different_material_each_time() {
        let key = vec![0xCC; 32];
        let split1 = af_split(&key, 100, AfHash::Sha256).unwrap();
        let split2 = af_split(&key, 100, AfHash::Sha256).unwrap();
        // Random stripes should differ (astronomically unlikely to match)
        assert_ne!(split1, split2);
    }
}
