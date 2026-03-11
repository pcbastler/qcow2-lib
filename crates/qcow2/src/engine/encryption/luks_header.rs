//! LUKS1 and LUKS2 header parsing and serialization.
//!
//! LUKS headers are stored at a cluster-aligned offset within the QCOW2 image,
//! pointed to by the FullDiskEncryption header extension.
//!
//! LUKS1: Fixed binary format (592 bytes header + key material areas).
//! LUKS2: Binary header (4096 bytes) + JSON metadata areas.

use byteorder::{BigEndian, ByteOrder};
use serde::Deserialize;

use super::af_splitter::AfHash;
use super::key_derivation::{Kdf, KdfHash};
use super::CipherMode;
use crate::error::{Error, Result};

/// LUKS magic bytes: "LUKS\xba\xbe"
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
/// LUKS1 version
const LUKS_VERSION_1: u16 = 1;
/// LUKS2 version
const LUKS_VERSION_2: u16 = 2;

/// Active key slot marker
const LUKS_KEY_ENABLED: u32 = 0x00AC_71F3;
/// Inactive key slot marker
const LUKS_KEY_DISABLED: u32 = 0x0000_DEAD;

/// LUKS1 header size (fixed binary format)
const LUKS1_HEADER_SIZE: usize = 592;
/// LUKS1 key slot size in the header
const LUKS1_KEY_SLOT_SIZE: usize = 48;
/// Number of key slots in LUKS1
pub const LUKS1_NUM_KEY_SLOTS: usize = 8;

/// Parsed LUKS header (version-independent).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LuksHeader {
    V1(Luks1Header),
    V2(Luks2Header),
}

impl LuksHeader {
    /// Parse a LUKS header from raw bytes.
    ///
    /// Detects LUKS1 vs LUKS2 from the version field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(Error::InvalidLuksHeader {
                message: "data too short for LUKS magic".to_string(),
            });
        }

        if &data[..6] != LUKS_MAGIC {
            return Err(Error::InvalidLuksHeader {
                message: format!(
                    "bad magic: expected {:02x?}, found {:02x?}",
                    LUKS_MAGIC,
                    &data[..6]
                ),
            });
        }

        let version = BigEndian::read_u16(&data[6..8]);
        match version {
            LUKS_VERSION_1 => Ok(LuksHeader::V1(Luks1Header::parse(data)?)),
            LUKS_VERSION_2 => Ok(LuksHeader::V2(Luks2Header::parse(data)?)),
            _ => Err(Error::InvalidLuksHeader {
                message: format!("unsupported LUKS version: {version}"),
            }),
        }
    }

    /// Get the cipher mode parsed from the header.
    pub fn cipher_mode(&self) -> Result<CipherMode> {
        match self {
            LuksHeader::V1(h) => h.cipher_mode(),
            LuksHeader::V2(h) => h.cipher_mode(),
        }
    }

    /// Get the master key length in bytes.
    pub fn key_bytes(&self) -> u32 {
        match self {
            LuksHeader::V1(h) => h.key_bytes,
            LuksHeader::V2(h) => h.key_bytes,
        }
    }

    /// The UUID of this LUKS container.
    pub fn uuid(&self) -> &str {
        match self {
            LuksHeader::V1(h) => &h.uuid,
            LuksHeader::V2(h) => &h.uuid,
        }
    }
}

// ---- LUKS1 ----

/// Parsed LUKS1 header.
#[derive(Debug)]
pub struct Luks1Header {
    pub cipher_name: String,
    pub cipher_mode_str: String,
    pub hash_spec: String,
    pub payload_offset: u32,
    pub key_bytes: u32,
    pub mk_digest: [u8; 20],
    pub mk_digest_salt: [u8; 32],
    pub mk_digest_iter: u32,
    pub uuid: String,
    pub key_slots: [Luks1KeySlot; LUKS1_NUM_KEY_SLOTS],
}

/// A LUKS1 key slot.
#[derive(Debug, Clone)]
pub struct Luks1KeySlot {
    pub active: bool,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub key_material_offset: u32,
    pub stripes: u32,
}

impl Default for Luks1KeySlot {
    fn default() -> Self {
        Self {
            active: false,
            iterations: 0,
            salt: [0; 32],
            key_material_offset: 0,
            stripes: 4000,
        }
    }
}

impl Luks1Header {
    /// Parse a LUKS1 header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < LUKS1_HEADER_SIZE {
            return Err(Error::InvalidLuksHeader {
                message: format!(
                    "LUKS1 header too short: {} < {}",
                    data.len(),
                    LUKS1_HEADER_SIZE
                ),
            });
        }

        let cipher_name = read_string(&data[8..40]);
        let cipher_mode_str = read_string(&data[40..72]);
        let hash_spec = read_string(&data[72..104]);
        let payload_offset = BigEndian::read_u32(&data[104..108]);
        let key_bytes = BigEndian::read_u32(&data[108..112]);

        let mut mk_digest = [0u8; 20];
        mk_digest.copy_from_slice(&data[112..132]);
        let mut mk_digest_salt = [0u8; 32];
        mk_digest_salt.copy_from_slice(&data[132..164]);
        let mk_digest_iter = BigEndian::read_u32(&data[164..168]);

        let uuid = read_string(&data[168..208]);

        // Parse 8 key slots starting at offset 208
        let mut key_slots: [Luks1KeySlot; LUKS1_NUM_KEY_SLOTS] = Default::default();
        for (i, slot) in key_slots.iter_mut().enumerate() {
            let off = 208 + i * LUKS1_KEY_SLOT_SIZE;
            let active_raw = BigEndian::read_u32(&data[off..off + 4]);
            slot.active = active_raw == LUKS_KEY_ENABLED;
            slot.iterations = BigEndian::read_u32(&data[off + 4..off + 8]);
            slot.salt.copy_from_slice(&data[off + 8..off + 40]);
            slot.key_material_offset = BigEndian::read_u32(&data[off + 40..off + 44]);
            slot.stripes = BigEndian::read_u32(&data[off + 44..off + 48]);
        }

        Ok(Self {
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
        })
    }

    /// Serialize a LUKS1 header to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8; LUKS1_HEADER_SIZE];

        buf[..6].copy_from_slice(LUKS_MAGIC);
        BigEndian::write_u16(&mut buf[6..8], LUKS_VERSION_1);
        write_string(&mut buf[8..40], &self.cipher_name);
        write_string(&mut buf[40..72], &self.cipher_mode_str);
        write_string(&mut buf[72..104], &self.hash_spec);
        BigEndian::write_u32(&mut buf[104..108], self.payload_offset);
        BigEndian::write_u32(&mut buf[108..112], self.key_bytes);
        buf[112..132].copy_from_slice(&self.mk_digest);
        buf[132..164].copy_from_slice(&self.mk_digest_salt);
        BigEndian::write_u32(&mut buf[164..168], self.mk_digest_iter);
        write_string(&mut buf[168..208], &self.uuid);

        for (i, slot) in self.key_slots.iter().enumerate() {
            let off = 208 + i * LUKS1_KEY_SLOT_SIZE;
            let active_raw = if slot.active {
                LUKS_KEY_ENABLED
            } else {
                LUKS_KEY_DISABLED
            };
            BigEndian::write_u32(&mut buf[off..off + 4], active_raw);
            BigEndian::write_u32(&mut buf[off + 4..off + 8], slot.iterations);
            buf[off + 8..off + 40].copy_from_slice(&slot.salt);
            BigEndian::write_u32(&mut buf[off + 40..off + 44], slot.key_material_offset);
            BigEndian::write_u32(&mut buf[off + 44..off + 48], slot.stripes);
        }

        buf
    }

    /// Determine the cipher mode from header strings.
    pub fn cipher_mode(&self) -> Result<CipherMode> {
        parse_cipher_mode(&self.cipher_name, &self.cipher_mode_str)
    }

    /// Get the hash spec for AF splitter.
    pub fn af_hash(&self) -> Result<AfHash> {
        AfHash::from_spec(&self.hash_spec)
    }

    /// Build the KDF for master key digest verification.
    pub fn mk_digest_kdf(&self) -> Result<Kdf> {
        Ok(Kdf::Pbkdf2 {
            hash: KdfHash::from_spec(&self.hash_spec)?,
            iterations: self.mk_digest_iter,
            salt: self.mk_digest_salt.to_vec(),
        })
    }

    /// Build the KDF for a specific key slot.
    pub fn key_slot_kdf(&self, slot_index: usize) -> Result<Kdf> {
        let slot = &self.key_slots[slot_index];
        Ok(Kdf::Pbkdf2 {
            hash: KdfHash::from_spec(&self.hash_spec)?,
            iterations: slot.iterations,
            salt: slot.salt.to_vec(),
        })
    }

    /// Total size of the LUKS header on disk (header + all key material areas).
    ///
    /// This is `payload_offset * 512` (payload_offset is in 512-byte sectors).
    pub fn total_header_size(&self) -> u64 {
        self.payload_offset as u64 * 512
    }
}

// ---- LUKS2 ----

/// Parsed LUKS2 header (binary + JSON metadata).
#[derive(Debug)]
pub struct Luks2Header {
    pub hdr_size: u64,
    pub seqid: u64,
    pub label: String,
    pub csum_alg: String,
    pub salt: Vec<u8>,
    pub uuid: String,
    pub hdr_offset: u64,
    /// Parsed JSON metadata.
    pub metadata: Luks2Metadata,
    /// Cached key_bytes from the first segment.
    pub key_bytes: u32,
}

/// LUKS2 JSON metadata top-level structure.
#[derive(Debug, Deserialize)]
pub struct Luks2Metadata {
    pub keyslots: std::collections::HashMap<String, Luks2Keyslot>,
    pub segments: std::collections::HashMap<String, Luks2Segment>,
    pub digests: std::collections::HashMap<String, Luks2Digest>,
    #[serde(default)]
    pub config: Option<Luks2Config>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Keyslot {
    #[serde(rename = "type")]
    pub slot_type: String,
    pub key_size: u32,
    pub af: Luks2Af,
    pub kdf: Luks2Kdf,
    pub area: Luks2Area,
    #[serde(default)]
    pub priority: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Af {
    #[serde(rename = "type")]
    pub af_type: String,
    pub hash: String,
    pub stripes: u32,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Kdf {
    #[serde(rename = "type")]
    pub kdf_type: String,
    pub salt: String, // base64
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub iterations: Option<u32>,
    #[serde(default)]
    pub time: Option<u32>,
    #[serde(default)]
    pub memory: Option<u32>,
    #[serde(default)]
    pub cpus: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Area {
    #[serde(rename = "type")]
    pub area_type: String,
    pub offset: String,       // decimal string
    pub size: String,         // decimal string
    pub encryption: String,   // e.g. "aes-xts-plain64"
    pub key_size: u32,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Segment {
    #[serde(rename = "type")]
    pub seg_type: String,
    pub offset: String,       // decimal string
    pub size: String,         // "dynamic" or decimal
    pub encryption: String,
    pub sector_size: u32,
    #[serde(default)]
    pub iv_tweak: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Digest {
    #[serde(rename = "type")]
    pub digest_type: String,
    pub keyslots: Vec<String>,
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: u32,
    pub salt: String,         // base64
    pub digest: String,       // base64
}

#[derive(Debug, Deserialize)]
pub struct Luks2Config {
    #[serde(default)]
    pub json_size: Option<String>,
    #[serde(default)]
    pub keyslots_size: Option<String>,
}

impl Luks2Header {
    /// Parse a LUKS2 header from raw bytes.
    ///
    /// The data must include the binary header (4096 bytes) and the JSON
    /// metadata area that follows it.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4096 {
            return Err(Error::InvalidLuksHeader {
                message: format!("LUKS2 header too short: {} < 4096", data.len()),
            });
        }

        let hdr_size = BigEndian::read_u64(&data[8..16]);
        let seqid = BigEndian::read_u64(&data[16..24]);
        let label = read_string(&data[24..72]);
        let csum_alg = read_string(&data[72..104]);
        let mut salt = vec![0u8; 64];
        salt.copy_from_slice(&data[104..168]);
        let uuid = read_string(&data[168..208]);
        let hdr_offset = BigEndian::read_u64(&data[208..216]);
        // csum at 216..280

        // JSON metadata follows the 4096-byte binary header
        let json_start = 4096usize;
        let json_end = (hdr_size as usize).min(data.len());
        if json_start >= json_end {
            return Err(Error::InvalidLuksHeader {
                message: "no JSON metadata area".to_string(),
            });
        }

        let json_data = &data[json_start..json_end];
        // Find the end of JSON (null-terminated)
        let json_len = json_data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(json_data.len());
        let json_str = std::str::from_utf8(&json_data[..json_len]).map_err(|_| {
            Error::InvalidLuksHeader {
                message: "JSON metadata is not valid UTF-8".to_string(),
            }
        })?;

        let metadata: Luks2Metadata =
            serde_json::from_str(json_str).map_err(|e| Error::InvalidLuksHeader {
                message: format!("JSON parse error: {e}"),
            })?;

        // Get key_bytes from the first segment
        let key_bytes = metadata
            .segments
            .values()
            .next()
            .map(|_s| {
                // key_bytes is stored in the keyslots, not directly in segments
                metadata
                    .keyslots
                    .values()
                    .next()
                    .map(|ks| ks.key_size)
                    .unwrap_or(32)
            })
            .unwrap_or(32);

        Ok(Self {
            hdr_size,
            seqid,
            label,
            csum_alg,
            salt,
            uuid,
            hdr_offset,
            metadata,
            key_bytes,
        })
    }

    /// Determine the cipher mode from the first segment's encryption string.
    pub fn cipher_mode(&self) -> Result<CipherMode> {
        let seg = self
            .metadata
            .segments
            .values()
            .next()
            .ok_or_else(|| Error::InvalidLuksHeader {
                message: "no segments in LUKS2 metadata".to_string(),
            })?;

        // encryption string is like "aes-xts-plain64" or "aes-cbc-essiv:sha256"
        let parts: Vec<&str> = seg.encryption.splitn(2, '-').collect();
        if parts.len() < 2 {
            return Err(Error::UnsupportedCipher {
                cipher_name: seg.encryption.clone(),
                cipher_mode: String::new(),
            });
        }
        parse_cipher_mode(parts[0], parts[1])
    }

    /// Total size of the LUKS2 header on disk (including both copies).
    pub fn total_header_size(&self) -> u64 {
        // LUKS2 has primary and secondary headers, each hdr_size bytes.
        // The data starts after both headers.
        self.hdr_size * 2
    }

    /// Build the KDF for a specific keyslot.
    pub fn keyslot_kdf(&self, slot_id: &str) -> Result<Kdf> {
        let ks = self.metadata.keyslots.get(slot_id).ok_or_else(|| {
            Error::InvalidLuksHeader {
                message: format!("keyslot {slot_id} not found"),
            }
        })?;

        let salt = base64_decode(&ks.kdf.salt)?;

        match ks.kdf.kdf_type.as_str() {
            "pbkdf2" => {
                let hash = KdfHash::from_spec(
                    ks.kdf.hash.as_deref().unwrap_or("sha256"),
                )?;
                let iterations = ks.kdf.iterations.unwrap_or(1000);
                Ok(Kdf::Pbkdf2 {
                    hash,
                    iterations,
                    salt,
                })
            }
            "argon2id" | "argon2i" | "argon2d" => {
                let time = ks.kdf.time.unwrap_or(4);
                let memory = ks.kdf.memory.unwrap_or(1048576);
                let cpus = ks.kdf.cpus.unwrap_or(4);
                Ok(Kdf::Argon2id { time, memory, cpus, salt })
            }
            other => Err(Error::InvalidLuksHeader {
                message: format!("unsupported KDF type: {other}"),
            }),
        }
    }

    /// Get the AF hash for a specific keyslot.
    pub fn keyslot_af_hash(&self, slot_id: &str) -> Result<AfHash> {
        let ks = self.metadata.keyslots.get(slot_id).ok_or_else(|| {
            Error::InvalidLuksHeader {
                message: format!("keyslot {slot_id} not found"),
            }
        })?;
        AfHash::from_spec(&ks.af.hash)
    }

    /// Get the digest verification parameters for a keyslot.
    pub fn digest_for_keyslot(&self, slot_id: &str) -> Result<(&Luks2Digest, Vec<u8>, Vec<u8>)> {
        for digest in self.metadata.digests.values() {
            if digest.keyslots.iter().any(|k| k == slot_id) {
                let salt = base64_decode(&digest.salt)?;
                let expected = base64_decode(&digest.digest)?;
                return Ok((digest, salt, expected));
            }
        }
        Err(Error::InvalidLuksHeader {
            message: format!("no digest found for keyslot {slot_id}"),
        })
    }
}

// ---- Helpers ----

/// Parse cipher name + mode string into a CipherMode enum.
fn parse_cipher_mode(cipher_name: &str, cipher_mode: &str) -> Result<CipherMode> {
    match (cipher_name, cipher_mode) {
        ("aes", m) if m.starts_with("xts-plain64") || m == "xts-plain" || m == "xts" => {
            Ok(CipherMode::AesXtsPlain64)
        }
        ("aes", m) if m.starts_with("cbc-essiv") => Ok(CipherMode::AesCbcEssiv),
        _ => Err(Error::UnsupportedCipher {
            cipher_name: cipher_name.to_string(),
            cipher_mode: cipher_mode.to_string(),
        }),
    }
}

/// Read a null-terminated string from a fixed-size field.
fn read_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Write a string into a fixed-size field, null-terminated.
fn write_string(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
    // Rest is already zeroed
}

/// Decode a base64 string (standard encoding with padding).
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::InvalidLuksHeader {
            message: format!("base64 decode error: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn luks1_header_round_trip() {
        let mut header = Luks1Header {
            cipher_name: "aes".to_string(),
            cipher_mode_str: "xts-plain64".to_string(),
            hash_spec: "sha256".to_string(),
            payload_offset: 4096,
            key_bytes: 64,
            mk_digest: [0x42; 20],
            mk_digest_salt: [0xAA; 32],
            mk_digest_iter: 100000,
            uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
            key_slots: Default::default(),
        };
        header.key_slots[0].active = true;
        header.key_slots[0].iterations = 50000;
        header.key_slots[0].salt = [0xBB; 32];
        header.key_slots[0].key_material_offset = 8;
        header.key_slots[0].stripes = 4000;

        let serialized = header.serialize();
        assert_eq!(serialized.len(), LUKS1_HEADER_SIZE);

        let parsed = Luks1Header::parse(&serialized).unwrap();
        assert_eq!(parsed.cipher_name, "aes");
        assert_eq!(parsed.cipher_mode_str, "xts-plain64");
        assert_eq!(parsed.hash_spec, "sha256");
        assert_eq!(parsed.payload_offset, 4096);
        assert_eq!(parsed.key_bytes, 64);
        assert_eq!(parsed.mk_digest, [0x42; 20]);
        assert_eq!(parsed.mk_digest_salt, [0xAA; 32]);
        assert_eq!(parsed.mk_digest_iter, 100000);
        assert!(parsed.uuid.starts_with("12345678"));
        assert!(parsed.key_slots[0].active);
        assert_eq!(parsed.key_slots[0].iterations, 50000);
        assert_eq!(parsed.key_slots[0].stripes, 4000);
        assert!(!parsed.key_slots[1].active);
    }

    #[test]
    fn luks1_cipher_mode_xts() {
        let mut data = vec![0u8; LUKS1_HEADER_SIZE];
        data[..6].copy_from_slice(LUKS_MAGIC);
        BigEndian::write_u16(&mut data[6..8], 1);
        write_string(&mut data[8..40], "aes");
        write_string(&mut data[40..72], "xts-plain64");
        write_string(&mut data[72..104], "sha256");

        let header = Luks1Header::parse(&data).unwrap();
        assert_eq!(header.cipher_mode().unwrap(), CipherMode::AesXtsPlain64);
    }

    #[test]
    fn luks1_cipher_mode_cbc_essiv() {
        let mut data = vec![0u8; LUKS1_HEADER_SIZE];
        data[..6].copy_from_slice(LUKS_MAGIC);
        BigEndian::write_u16(&mut data[6..8], 1);
        write_string(&mut data[8..40], "aes");
        write_string(&mut data[40..72], "cbc-essiv:sha256");
        write_string(&mut data[72..104], "sha256");

        let header = Luks1Header::parse(&data).unwrap();
        assert_eq!(header.cipher_mode().unwrap(), CipherMode::AesCbcEssiv);
    }

    #[test]
    fn luks_header_detect_version() {
        // LUKS1
        let mut data = vec![0u8; LUKS1_HEADER_SIZE];
        data[..6].copy_from_slice(LUKS_MAGIC);
        BigEndian::write_u16(&mut data[6..8], 1);
        write_string(&mut data[8..40], "aes");
        write_string(&mut data[40..72], "xts-plain64");
        write_string(&mut data[72..104], "sha256");

        let header = LuksHeader::parse(&data).unwrap();
        assert!(matches!(header, LuksHeader::V1(_)));
    }

    #[test]
    fn luks_bad_magic_rejected() {
        let data = vec![0u8; 100];
        assert!(LuksHeader::parse(&data).is_err());
    }

    #[test]
    fn unsupported_cipher_returns_error() {
        let result = parse_cipher_mode("serpent", "cbc-plain64");
        assert!(result.is_err());
    }
}
