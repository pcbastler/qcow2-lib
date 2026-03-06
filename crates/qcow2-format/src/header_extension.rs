//! QCOW2 header extension parsing (type-length-value format).
//!
//! Header extensions appear immediately after the main header in the first
//! cluster. They use a simple TLV encoding: 4-byte type, 4-byte length,
//! then `length` bytes of data padded to an 8-byte boundary.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::bitmap::BitmapExtension;
use crate::constants::*;
use crate::hash::Blake3Extension;

/// Minimum size of a TLV header (4-byte type + 4-byte length).
const TLV_HEADER_SIZE: usize = 8;

/// A single header extension entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderExtension {
    /// Backing file format name (e.g., "qcow2", "raw").
    BackingFileFormat(String),

    /// Feature name table: maps (type, bit) pairs to human-readable names.
    FeatureNameTable(Vec<FeatureNameEntry>),

    /// Bitmaps extension (persistent dirty tracking bitmaps).
    Bitmaps(BitmapExtension),

    /// BLAKE3 per-cluster hash extension.
    Blake3Hashes(Blake3Extension),

    /// Full disk encryption header pointer.
    FullDiskEncryption {
        /// Byte offset of the encryption header in the image.
        offset: u64,
        /// Length of the encryption header.
        length: u64,
    },

    /// External data file name.
    ExternalDataFile(String),

    /// Unknown extension type (preserved for round-trip fidelity).
    Unknown {
        /// The extension type ID.
        extension_type: u32,
        /// Raw extension data.
        data: Vec<u8>,
    },
}

/// A single entry in the feature name table extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureNameEntry {
    /// Feature type: 0=incompatible, 1=compatible, 2=autoclear.
    pub feature_type: u8,
    /// Bit number within the feature flag field.
    pub bit_number: u8,
    /// Human-readable feature name (up to 46 bytes on disk).
    pub name: String,
}

/// Size of each feature name table entry on disk.
const FEATURE_NAME_ENTRY_SIZE: usize = 48;

impl HeaderExtension {
    /// Parse all header extensions from a byte slice.
    ///
    /// The slice should start immediately after the main header (at the
    /// offset `header_length` within the first cluster). Parsing stops
    /// when the end-of-extensions marker (type 0) is encountered or
    /// the data is exhausted.
    pub fn read_all(bytes: &[u8]) -> Result<Vec<Self>> {
        let mut extensions = Vec::new();
        let mut pos = 0;

        loop {
            if pos + TLV_HEADER_SIZE > bytes.len() {
                break; // Not enough data for another extension header
            }

            let ext_type = BigEndian::read_u32(&bytes[pos..]);
            let ext_len = BigEndian::read_u32(&bytes[pos + 4..]) as usize;

            if ext_type == EXT_END_OF_EXTENSIONS {
                break;
            }

            let data_start = pos + TLV_HEADER_SIZE;
            let data_end = data_start
                .checked_add(ext_len)
                .ok_or(Error::ArithmeticOverflow {
                    context: "header extension data length",
                })?;

            if data_end > bytes.len() {
                return Err(Error::ExtensionTruncated {
                    offset: pos,
                    expected: ext_len + TLV_HEADER_SIZE,
                    actual: bytes.len() - pos,
                });
            }

            let data = &bytes[data_start..data_end];
            let extension = Self::decode(ext_type, data)?;
            extensions.push(extension);

            // Advance past data + padding to next 8-byte boundary
            let padded_len = ext_len
                .checked_add(7)
                .ok_or(Error::ArithmeticOverflow {
                    context: "header extension padding",
                })?
                & !7;
            pos = data_start + padded_len;
        }

        Ok(extensions)
    }

    /// Serialize all extensions into a byte vector, including the
    /// end-of-extensions marker.
    pub fn write_all(extensions: &[Self]) -> Vec<u8> {
        let mut buf = Vec::new();

        for ext in extensions {
            let (ext_type, data) = ext.encode();
            let mut header = [0u8; TLV_HEADER_SIZE];
            BigEndian::write_u32(&mut header[0..], ext_type);
            BigEndian::write_u32(&mut header[4..], data.len() as u32);
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&data);

            // Pad to 8-byte boundary
            let padding = (8 - (data.len() % 8)) % 8;
            buf.resize(buf.len() + padding, 0);
        }

        // Write end-of-extensions marker
        buf.extend_from_slice(&[0u8; TLV_HEADER_SIZE]);
        buf
    }

    /// Decode extension data based on the type ID.
    fn decode(ext_type: u32, data: &[u8]) -> Result<Self> {
        match ext_type {
            EXT_BACKING_FILE_FORMAT => {
                let name = String::from_utf8_lossy(data).into_owned();
                Ok(Self::BackingFileFormat(name))
            }
            EXT_FEATURE_NAME_TABLE => {
                let mut entries = Vec::new();
                let mut pos = 0;
                while pos + FEATURE_NAME_ENTRY_SIZE <= data.len() {
                    let feature_type = data[pos];
                    let bit_number = data[pos + 1];
                    // Name is 46 bytes, zero-padded
                    let name_bytes = &data[pos + 2..pos + FEATURE_NAME_ENTRY_SIZE];
                    let name_end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

                    entries.push(FeatureNameEntry {
                        feature_type,
                        bit_number,
                        name,
                    });
                    pos += FEATURE_NAME_ENTRY_SIZE;
                }
                Ok(Self::FeatureNameTable(entries))
            }
            EXT_BITMAPS => match BitmapExtension::read_from(data) {
                Ok(ext) => Ok(Self::Bitmaps(ext)),
                Err(_) => Ok(Self::Unknown {
                    extension_type: ext_type,
                    data: data.to_vec(),
                }),
            },
            EXT_BLAKE3_HASHES => match Blake3Extension::read_from(data) {
                Ok(ext) => Ok(Self::Blake3Hashes(ext)),
                Err(_) => Ok(Self::Unknown {
                    extension_type: ext_type,
                    data: data.to_vec(),
                }),
            },
            EXT_FULL_DISK_ENCRYPTION => {
                if data.len() >= 16 {
                    let offset = BigEndian::read_u64(data);
                    let length = BigEndian::read_u64(&data[8..]);
                    Ok(Self::FullDiskEncryption { offset, length })
                } else {
                    Ok(Self::Unknown {
                        extension_type: ext_type,
                        data: data.to_vec(),
                    })
                }
            }
            EXT_EXTERNAL_DATA_FILE => {
                let name = String::from_utf8_lossy(data).into_owned();
                Ok(Self::ExternalDataFile(name))
            }
            _ => Ok(Self::Unknown {
                extension_type: ext_type,
                data: data.to_vec(),
            }),
        }
    }

    /// Encode an extension into (type_id, data_bytes).
    fn encode(&self) -> (u32, Vec<u8>) {
        match self {
            Self::BackingFileFormat(name) => (EXT_BACKING_FILE_FORMAT, name.as_bytes().to_vec()),
            Self::FeatureNameTable(entries) => {
                let mut data = Vec::with_capacity(entries.len() * FEATURE_NAME_ENTRY_SIZE);
                for entry in entries {
                    let mut entry_buf = vec![0u8; FEATURE_NAME_ENTRY_SIZE];
                    entry_buf[0] = entry.feature_type;
                    entry_buf[1] = entry.bit_number;
                    let name_bytes = entry.name.as_bytes();
                    let copy_len = name_bytes.len().min(46);
                    entry_buf[2..2 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
                    data.extend_from_slice(&entry_buf);
                }
                (EXT_FEATURE_NAME_TABLE, data)
            }
            Self::Bitmaps(ext) => (EXT_BITMAPS, ext.write_to()),
            Self::Blake3Hashes(ext) => (EXT_BLAKE3_HASHES, ext.write_to()),
            Self::FullDiskEncryption { offset, length } => {
                let mut data = vec![0u8; 16];
                BigEndian::write_u64(&mut data[0..], *offset);
                BigEndian::write_u64(&mut data[8..], *length);
                (EXT_FULL_DISK_ENCRYPTION, data)
            }
            Self::ExternalDataFile(name) => (EXT_EXTERNAL_DATA_FILE, name.as_bytes().to_vec()),
            Self::Unknown {
                extension_type,
                data,
            } => (*extension_type, data.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn parse_empty_extensions() {
        // Just an end marker
        let buf = [0u8; 8];
        let exts = HeaderExtension::read_all(&buf).unwrap();
        assert!(exts.is_empty());
    }

    #[test]
    fn parse_backing_file_format() {
        let mut buf = Vec::new();
        // Type: EXT_BACKING_FILE_FORMAT
        buf.extend_from_slice(&EXT_BACKING_FILE_FORMAT.to_be_bytes());
        // Length: 5 bytes ("qcow2")
        buf.extend_from_slice(&5u32.to_be_bytes());
        // Data
        buf.extend_from_slice(b"qcow2");
        // Padding to 8-byte boundary (5 bytes data -> 3 bytes padding)
        buf.extend_from_slice(&[0, 0, 0]);
        // End marker
        buf.extend_from_slice(&[0u8; 8]);

        let exts = HeaderExtension::read_all(&buf).unwrap();
        assert_eq!(exts.len(), 1);
        match &exts[0] {
            HeaderExtension::BackingFileFormat(name) => assert_eq!(name, "qcow2"),
            other => panic!("expected BackingFileFormat, got {other:?}"),
        }
    }

    #[test]
    fn parse_feature_name_table() {
        let mut data = vec![0u8; FEATURE_NAME_ENTRY_SIZE];
        data[0] = 0; // incompatible
        data[1] = 0; // bit 0
        data[2..7].copy_from_slice(b"dirty");

        let mut buf = Vec::new();
        buf.extend_from_slice(&EXT_FEATURE_NAME_TABLE.to_be_bytes());
        buf.extend_from_slice(&(FEATURE_NAME_ENTRY_SIZE as u32).to_be_bytes());
        buf.extend_from_slice(&data);
        buf.extend_from_slice(&[0u8; 8]); // end marker

        let exts = HeaderExtension::read_all(&buf).unwrap();
        assert_eq!(exts.len(), 1);
        match &exts[0] {
            HeaderExtension::FeatureNameTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].feature_type, 0);
                assert_eq!(entries[0].bit_number, 0);
                assert_eq!(entries[0].name, "dirty");
            }
            other => panic!("expected FeatureNameTable, got {other:?}"),
        }
    }

    #[test]
    fn parse_multiple_extensions() {
        let mut buf = Vec::new();

        // Extension 1: BackingFileFormat "raw"
        buf.extend_from_slice(&EXT_BACKING_FILE_FORMAT.to_be_bytes());
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"raw");
        buf.extend_from_slice(&[0; 5]); // pad to 8

        // Extension 2: Unknown type
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        // Already 8-byte aligned

        // End marker
        buf.extend_from_slice(&[0u8; 8]);

        let exts = HeaderExtension::read_all(&buf).unwrap();
        assert_eq!(exts.len(), 2);
        assert!(matches!(&exts[0], HeaderExtension::BackingFileFormat(n) if n == "raw"));
        assert!(matches!(&exts[1], HeaderExtension::Unknown { extension_type: 0xDEAD_BEEF, .. }));
    }

    #[test]
    fn round_trip_extensions() {
        let original = vec![
            HeaderExtension::BackingFileFormat("qcow2".to_string()),
            HeaderExtension::FeatureNameTable(vec![FeatureNameEntry {
                feature_type: 0,
                bit_number: 0,
                name: "dirty".to_string(),
            }]),
            HeaderExtension::Unknown {
                extension_type: 0xFF,
                data: vec![42, 43, 44],
            },
        ];

        let serialized = HeaderExtension::write_all(&original);
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn truncated_extension_returns_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&EXT_BACKING_FILE_FORMAT.to_be_bytes());
        buf.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes
        buf.extend_from_slice(b"short"); // only 5 bytes

        match HeaderExtension::read_all(&buf) {
            Err(Error::ExtensionTruncated { .. }) => {}
            other => panic!("expected ExtensionTruncated, got {other:?}"),
        }
    }

    #[test]
    fn full_disk_encryption_extension() {
        let ext = HeaderExtension::FullDiskEncryption {
            offset: 0x1_0000,
            length: 4096,
        };
        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ext);
    }

    // ---- Edge cases ----

    #[test]
    fn extension_data_exactly_8_byte_aligned() {
        // Data length 8 → no padding needed (8 % 8 == 0).
        let ext = HeaderExtension::BackingFileFormat("raw12345".to_string()); // 8 bytes
        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ext);
    }

    #[test]
    fn extension_data_length_1_needs_7_padding() {
        // Data length 1 → 7 bytes of padding to reach 8-byte boundary.
        let ext = HeaderExtension::BackingFileFormat("r".to_string());
        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));

        // TLV header (8) + data (1) + padding (7) + end marker (8) = 24
        assert_eq!(serialized.len(), 24);

        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ext);
    }

    #[test]
    fn end_marker_only_empty_list() {
        // An end marker alone produces an empty extension list.
        let serialized = HeaderExtension::write_all(&[]);
        assert_eq!(serialized.len(), TLV_HEADER_SIZE); // Just the end marker
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn unknown_extension_round_trip() {
        let ext = HeaderExtension::Unknown {
            extension_type: 0xCAFE_BABE,
            data: vec![10, 20, 30, 40, 50],
        };
        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ext);
    }

    #[test]
    fn feature_name_max_length_46_bytes() {
        // Feature names are stored in a 46-byte field (zero-padded).
        let long_name = "a".repeat(46);
        let entry = FeatureNameEntry {
            feature_type: 2, // autoclear
            bit_number: 3,
            name: long_name.clone(),
        };
        let ext = HeaderExtension::FeatureNameTable(vec![entry]);

        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            HeaderExtension::FeatureNameTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, long_name);
            }
            other => panic!("expected FeatureNameTable, got {other:?}"),
        }
    }

    #[test]
    fn feature_name_truncated_at_46_bytes() {
        // A name longer than 46 bytes should be truncated on encode.
        let too_long = "b".repeat(50);
        let entry = FeatureNameEntry {
            feature_type: 0,
            bit_number: 0,
            name: too_long,
        };
        let ext = HeaderExtension::FeatureNameTable(vec![entry]);

        let serialized = HeaderExtension::write_all(&[ext]);
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        match &parsed[0] {
            HeaderExtension::FeatureNameTable(entries) => {
                assert_eq!(entries[0].name.len(), 46);
                assert_eq!(entries[0].name, "b".repeat(46));
            }
            other => panic!("expected FeatureNameTable, got {other:?}"),
        }
    }

    #[test]
    fn external_data_file_round_trip() {
        let ext = HeaderExtension::ExternalDataFile("/path/to/data.raw".to_string());
        let serialized = HeaderExtension::write_all(core::slice::from_ref(&ext));
        let parsed = HeaderExtension::read_all(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ext);
    }

    #[test]
    fn reject_overflow_extension_length() {
        // Extension claims u32::MAX length. On 64-bit, data_start + u32::MAX
        // won't overflow usize but will exceed bytes.len() → ExtensionTruncated.
        // On 32-bit, the checked_add catches the arithmetic overflow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // some type
        buf.extend_from_slice(&u32::MAX.to_be_bytes()); // huge length
        buf.extend_from_slice(&[0u8; 16]); // a bit of data

        let result = HeaderExtension::read_all(&buf);
        assert!(result.is_err(), "should reject overflowing extension length");
    }

    #[test]
    fn not_enough_data_for_header() {
        // Less than 8 bytes: should just stop (no error, empty list).
        let buf = [0u8; 4];
        let exts = HeaderExtension::read_all(&buf).unwrap();
        assert!(exts.is_empty());
    }
}
