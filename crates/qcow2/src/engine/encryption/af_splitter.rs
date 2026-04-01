//! AF splitter wrapper that provides a working `af_split` using `rand`.
//!
//! Re-exports everything from `qcow2_core::engine::encryption::af_splitter`
//! but replaces the stubbed `af_split` with a real implementation.

pub use qcow2_core::engine::encryption::af_splitter::{af_merge, AfHash};

use qcow2_core::error::Result;
use rand::Rng;

/// AF split: split a key into `stripes` stripes for storage.
///
/// Generates `stripes - 1` random stripes and computes the final stripe
/// such that `af_merge` recovers the original key.
pub fn af_split(key: &[u8], stripes: u32, hash: AfHash) -> Result<Vec<u8>> {
    let key_len = key.len();
    let total_len = key_len * stripes as usize;
    let mut material = vec![0u8; total_len];

    // Fill stripes 0..stripes-2 with random data
    let random_len = key_len * (stripes as usize - 1);
    rand::rng().fill(&mut material[..random_len]);

    // Compute running diffuse-XOR for stripes 0..stripes-2
    let mut d = material[..key_len].to_vec();
    for i in 1..(stripes as usize - 1) {
        let diffused = diffuse(&d, hash);
        d.copy_from_slice(&diffused);
        let stripe = &material[i * key_len..(i + 1) * key_len];
        xor_buffers(&mut d, stripe);
    }

    // Final stripe: diffuse(d) XOR key
    let diffused = diffuse(&d, hash);
    d.copy_from_slice(&diffused);
    let last_stripe = &mut material[(stripes as usize - 1) * key_len..];
    last_stripe.copy_from_slice(key);
    xor_buffers(last_stripe, &d);

    Ok(material)
}

// Local copies of helpers needed by af_split (these are private in core)

fn diffuse(data: &[u8], hash: AfHash) -> Vec<u8> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha512};

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
        let h = match hash {
            AfHash::Sha1 => Sha1::digest(&input).to_vec(),
            AfHash::Sha256 => Sha256::digest(&input).to_vec(),
            AfHash::Sha512 => Sha512::digest(&input).to_vec(),
        };
        result.extend_from_slice(&h);
    }

    if remainder > 0 {
        let start = full_blocks * digest_size;
        let chunk = &data[start..];
        let mut input = Vec::with_capacity(4 + remainder);
        input.extend_from_slice(&(full_blocks as u32).to_be_bytes());
        input.extend_from_slice(chunk);
        let h = match hash {
            AfHash::Sha1 => Sha1::digest(&input).to_vec(),
            AfHash::Sha256 => Sha256::digest(&input).to_vec(),
            AfHash::Sha512 => Sha512::digest(&input).to_vec(),
        };
        result.extend_from_slice(&h[..remainder]);
    }

    result
}

fn xor_buffers(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_split_merge_round_trip_sha256() {
        let key = b"0123456789abcdef0123456789abcdef";
        let material = af_split(key, 4000, AfHash::Sha256).unwrap();
        assert_eq!(material.len(), 32 * 4000);
        let recovered = af_merge(&material, 32, 4000, AfHash::Sha256).unwrap();
        assert_eq!(&recovered, key);
    }

    #[test]
    fn af_split_merge_round_trip_sha1() {
        let key = vec![0xAA; 32];
        let material = af_split(&key, 4000, AfHash::Sha1).unwrap();
        let recovered = af_merge(&material, 32, 4000, AfHash::Sha1).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn af_split_merge_round_trip_sha512() {
        let key = vec![0xBB; 64];
        let material = af_split(&key, 4000, AfHash::Sha512).unwrap();
        let recovered = af_merge(&material, 64, 4000, AfHash::Sha512).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn af_split_produces_different_material_each_time() {
        let key = vec![0xCC; 32];
        let split1 = af_split(&key, 100, AfHash::Sha256).unwrap();
        let split2 = af_split(&key, 100, AfHash::Sha256).unwrap();
        assert_ne!(split1, split2);
    }
}
