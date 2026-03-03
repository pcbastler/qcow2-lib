//! QCOW2 image header parsing and serialization.
//!
//! Supports both v2 (72-byte) and v3 (104+ byte) headers. The [`Header`]
//! struct uses a unified representation: v2 fields that don't exist in v3
//! are filled with spec-defined defaults so downstream code avoids `Option`
//! noise.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::feature_flags::*;
use crate::format::types::ClusterOffset;

/// Parsed QCOW2 image header (supports v2 and v3).
///
/// All fields are stored in host byte order after parsing. For v2 images,
/// v3-only fields are populated with spec-defined defaults (e.g., empty
/// feature flags, 16-bit refcounts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    // ---- Common fields (v2 and v3) ----
    /// QCOW2 version number (2 or 3).
    pub version: u32,
    /// Byte offset of the backing file name in the image file (0 = no backing file).
    pub backing_file_offset: u64,
    /// Length of the backing file name in bytes.
    pub backing_file_size: u32,
    /// Log2 of the cluster size in bytes (e.g., 16 for 64 KB clusters).
    pub cluster_bits: u32,
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Encryption method (0=none, 1=AES-CBC, 2=LUKS).
    pub crypt_method: u32,
    /// Number of entries in the L1 table.
    pub l1_table_entries: u32,
    /// Host file offset of the L1 table.
    pub l1_table_offset: ClusterOffset,
    /// Host file offset of the refcount table.
    pub refcount_table_offset: ClusterOffset,
    /// Number of clusters occupied by the refcount table.
    pub refcount_table_clusters: u32,
    /// Number of snapshots in the image.
    pub snapshot_count: u32,
    /// Host file offset of the snapshot table.
    pub snapshots_offset: ClusterOffset,

    // ---- v3 extensions (defaults for v2) ----
    /// Incompatible feature flags.
    pub incompatible_features: IncompatibleFeatures,
    /// Compatible feature flags.
    pub compatible_features: CompatibleFeatures,
    /// Autoclear feature flags.
    pub autoclear_features: AutoclearFeatures,
    /// Refcount order: refcount width = `1 << refcount_order` bits (v2: always 4 = 16-bit).
    pub refcount_order: u32,
    /// Total header length in bytes (v2: 72, v3: at least 104).
    pub header_length: u32,
    /// Compression type (0=deflate, 1=zstd). Only valid if COMPRESSION_TYPE feature is set.
    pub compression_type: u8,
}

// ---- Field offsets within the header (byte positions from spec) ----
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_BACKING_FILE_OFFSET: usize = 8;
const OFF_BACKING_FILE_SIZE: usize = 16;
const OFF_CLUSTER_BITS: usize = 20;
const OFF_VIRTUAL_SIZE: usize = 24;
const OFF_CRYPT_METHOD: usize = 32;
const OFF_L1_TABLE_ENTRIES: usize = 36;
const OFF_L1_TABLE_OFFSET: usize = 40;
const OFF_REFCOUNT_TABLE_OFFSET: usize = 48;
const OFF_REFCOUNT_TABLE_CLUSTERS: usize = 56;
const OFF_SNAPSHOT_COUNT: usize = 60;
const OFF_SNAPSHOTS_OFFSET: usize = 64;
// v3 only
const OFF_INCOMPATIBLE_FEATURES: usize = 72;
const OFF_COMPATIBLE_FEATURES: usize = 80;
const OFF_AUTOCLEAR_FEATURES: usize = 88;
const OFF_REFCOUNT_ORDER: usize = 96;
const OFF_HEADER_LENGTH: usize = 100;
const OFF_COMPRESSION_TYPE: usize = 104;

impl Header {
    /// Parse a QCOW2 header from a byte slice.
    ///
    /// The slice must be at least [`HEADER_V2_LENGTH`] bytes. For v3 images,
    /// at least [`HEADER_V3_MIN_LENGTH`] bytes are required.
    ///
    /// Returns an error if:
    /// - The magic number is incorrect
    /// - The version is unsupported
    /// - The header data is too short
    /// - Any field fails validation
    pub fn read_from(bytes: &[u8]) -> Result<Self> {
        // Check minimum length for v2
        if bytes.len() < HEADER_V2_LENGTH {
            return Err(Error::HeaderTooShort {
                expected: HEADER_V2_LENGTH,
                actual: bytes.len(),
            });
        }

        // Validate magic
        let magic = BigEndian::read_u32(&bytes[OFF_MAGIC..]);
        if magic != QCOW2_MAGIC {
            return Err(Error::InvalidMagic {
                expected: QCOW2_MAGIC,
                found: magic,
            });
        }

        // Read version
        let version = BigEndian::read_u32(&bytes[OFF_VERSION..]);
        if version != VERSION_2 && version != VERSION_3 {
            return Err(Error::UnsupportedVersion { version });
        }

        // For v3, ensure we have enough data
        if version == VERSION_3 && bytes.len() < HEADER_V3_MIN_LENGTH {
            return Err(Error::HeaderTooShort {
                expected: HEADER_V3_MIN_LENGTH,
                actual: bytes.len(),
            });
        }

        // Read common fields
        let backing_file_offset = BigEndian::read_u64(&bytes[OFF_BACKING_FILE_OFFSET..]);
        let backing_file_size = BigEndian::read_u32(&bytes[OFF_BACKING_FILE_SIZE..]);
        let cluster_bits = BigEndian::read_u32(&bytes[OFF_CLUSTER_BITS..]);
        let virtual_size = BigEndian::read_u64(&bytes[OFF_VIRTUAL_SIZE..]);
        let crypt_method = BigEndian::read_u32(&bytes[OFF_CRYPT_METHOD..]);
        let l1_table_entries = BigEndian::read_u32(&bytes[OFF_L1_TABLE_ENTRIES..]);
        let l1_table_offset = ClusterOffset(BigEndian::read_u64(&bytes[OFF_L1_TABLE_OFFSET..]));
        let refcount_table_offset =
            ClusterOffset(BigEndian::read_u64(&bytes[OFF_REFCOUNT_TABLE_OFFSET..]));
        let refcount_table_clusters = BigEndian::read_u32(&bytes[OFF_REFCOUNT_TABLE_CLUSTERS..]);
        let snapshot_count = BigEndian::read_u32(&bytes[OFF_SNAPSHOT_COUNT..]);
        let snapshots_offset =
            ClusterOffset(BigEndian::read_u64(&bytes[OFF_SNAPSHOTS_OFFSET..]));

        // Read v3 fields or use v2 defaults
        let (
            incompatible_features,
            compatible_features,
            autoclear_features,
            refcount_order,
            header_length,
            compression_type,
        ) = if version == VERSION_3 {
            let incompat_bits = BigEndian::read_u64(&bytes[OFF_INCOMPATIBLE_FEATURES..]);
            let compat_bits = BigEndian::read_u64(&bytes[OFF_COMPATIBLE_FEATURES..]);
            let auto_bits = BigEndian::read_u64(&bytes[OFF_AUTOCLEAR_FEATURES..]);
            let refcount_order = BigEndian::read_u32(&bytes[OFF_REFCOUNT_ORDER..]);
            let header_length = BigEndian::read_u32(&bytes[OFF_HEADER_LENGTH..]);

            // Compression type is at byte 104, only present if header is long enough
            let compression_type = if bytes.len() > OFF_COMPRESSION_TYPE {
                bytes[OFF_COMPRESSION_TYPE]
            } else {
                COMPRESSION_DEFLATE
            };

            (
                IncompatibleFeatures::from_bits_retain(incompat_bits),
                CompatibleFeatures::from_bits_retain(compat_bits),
                AutoclearFeatures::from_bits_retain(auto_bits),
                refcount_order,
                header_length,
                compression_type,
            )
        } else {
            // v2 defaults
            (
                IncompatibleFeatures::empty(),
                CompatibleFeatures::empty(),
                AutoclearFeatures::empty(),
                DEFAULT_REFCOUNT_ORDER_V2,
                HEADER_V2_LENGTH as u32,
                COMPRESSION_DEFLATE,
            )
        };

        let header = Self {
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            virtual_size,
            crypt_method,
            l1_table_entries,
            l1_table_offset,
            refcount_table_offset,
            refcount_table_clusters,
            snapshot_count,
            snapshots_offset,
            incompatible_features,
            compatible_features,
            autoclear_features,
            refcount_order,
            header_length,
            compression_type,
        };

        header.validate_structural()?;
        Ok(header)
    }

    /// Serialize this header into the provided buffer.
    ///
    /// The buffer must be at least [`self.serialized_length()`] bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let needed = self.serialized_length();
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                expected: needed,
                actual: buf.len(),
            });
        }

        // Zero the buffer first to ensure clean padding
        buf[..needed].fill(0);

        BigEndian::write_u32(&mut buf[OFF_MAGIC..], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[OFF_VERSION..], self.version);
        BigEndian::write_u64(&mut buf[OFF_BACKING_FILE_OFFSET..], self.backing_file_offset);
        BigEndian::write_u32(&mut buf[OFF_BACKING_FILE_SIZE..], self.backing_file_size);
        BigEndian::write_u32(&mut buf[OFF_CLUSTER_BITS..], self.cluster_bits);
        BigEndian::write_u64(&mut buf[OFF_VIRTUAL_SIZE..], self.virtual_size);
        BigEndian::write_u32(&mut buf[OFF_CRYPT_METHOD..], self.crypt_method);
        BigEndian::write_u32(&mut buf[OFF_L1_TABLE_ENTRIES..], self.l1_table_entries);
        BigEndian::write_u64(&mut buf[OFF_L1_TABLE_OFFSET..], self.l1_table_offset.0);
        BigEndian::write_u64(
            &mut buf[OFF_REFCOUNT_TABLE_OFFSET..],
            self.refcount_table_offset.0,
        );
        BigEndian::write_u32(
            &mut buf[OFF_REFCOUNT_TABLE_CLUSTERS..],
            self.refcount_table_clusters,
        );
        BigEndian::write_u32(&mut buf[OFF_SNAPSHOT_COUNT..], self.snapshot_count);
        BigEndian::write_u64(&mut buf[OFF_SNAPSHOTS_OFFSET..], self.snapshots_offset.0);

        if self.version == VERSION_3 {
            BigEndian::write_u64(
                &mut buf[OFF_INCOMPATIBLE_FEATURES..],
                self.incompatible_features.bits(),
            );
            BigEndian::write_u64(
                &mut buf[OFF_COMPATIBLE_FEATURES..],
                self.compatible_features.bits(),
            );
            BigEndian::write_u64(
                &mut buf[OFF_AUTOCLEAR_FEATURES..],
                self.autoclear_features.bits(),
            );
            BigEndian::write_u32(&mut buf[OFF_REFCOUNT_ORDER..], self.refcount_order);
            BigEndian::write_u32(&mut buf[OFF_HEADER_LENGTH..], self.header_length);

            if needed > OFF_COMPRESSION_TYPE {
                buf[OFF_COMPRESSION_TYPE] = self.compression_type;
            }
        }

        Ok(())
    }

    /// Number of bytes this header occupies on disk.
    pub fn serialized_length(&self) -> usize {
        if self.version == VERSION_3 {
            // v3 header length is stored in the header itself
            self.header_length.max(HEADER_V3_MIN_LENGTH as u32) as usize
        } else {
            HEADER_V2_LENGTH
        }
    }

    /// Cluster size in bytes: `1 << cluster_bits`.
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    /// Number of L2 entries per table: `cluster_size / 8`.
    ///
    /// Each L2 entry is 8 bytes, and one L2 table occupies exactly one cluster.
    pub fn l2_entries_per_table(&self) -> u64 {
        self.cluster_size() / L2_ENTRY_SIZE as u64
    }

    /// Refcount bit width: `1 << refcount_order`.
    pub fn refcount_bits(&self) -> u32 {
        1u32 << self.refcount_order
    }

    /// Number of refcount entries per block: `cluster_size * 8 / refcount_bits`.
    pub fn refcounts_per_block(&self) -> u64 {
        self.cluster_size() * 8 / self.refcount_bits() as u64
    }

    /// Whether this image has a backing file.
    pub fn has_backing_file(&self) -> bool {
        self.backing_file_offset != 0 && self.backing_file_size > 0
    }

    /// Validate structural header invariants that don't require file size.
    ///
    /// Called automatically by [`read_from`](Self::read_from).
    fn validate_structural(&self) -> Result<()> {
        // Cluster bits range
        if self.cluster_bits < MIN_CLUSTER_BITS || self.cluster_bits > MAX_CLUSTER_BITS {
            return Err(Error::InvalidClusterBits {
                cluster_bits: self.cluster_bits,
                min: MIN_CLUSTER_BITS,
                max: MAX_CLUSTER_BITS,
            });
        }

        // Refcount order range (v3 only; v2 is fixed at 4)
        if self.version == VERSION_3 && self.refcount_order > MAX_REFCOUNT_ORDER {
            return Err(Error::InvalidRefcountOrder {
                order: self.refcount_order,
                max: MAX_REFCOUNT_ORDER,
            });
        }

        // Unsupported incompatible features
        if self.version == VERSION_3 {
            let unknown = self.incompatible_features.bits()
                & !SUPPORTED_INCOMPATIBLE_FEATURES.bits();
            if unknown != 0 {
                return Err(Error::UnsupportedIncompatibleFeatures { features: unknown });
            }
        }

        // L1 table offset alignment (must be cluster-aligned if non-zero)
        if self.l1_table_entries > 0 && !self.l1_table_offset.is_cluster_aligned(self.cluster_bits)
        {
            return Err(Error::L2TableMisaligned {
                offset: self.l1_table_offset.0,
            });
        }

        Ok(())
    }

    /// Validate header offsets and sizes against the physical file size.
    ///
    /// Must be called after [`read_from`](Self::read_from) when the file
    /// size is known. Catches malicious or corrupted images with offsets
    /// that point beyond EOF, oversized allocations, or inconsistent fields.
    pub fn validate_against_file(&self, file_size: u64) -> Result<()> {
        let cluster_size = self.cluster_size();

        // virtual_size must be non-zero
        if self.virtual_size == 0 {
            return Err(Error::AllocationTooLarge {
                requested: 0,
                max: 0,
                context: "virtual_size is zero",
            });
        }

        // L1 table: offset + entries*8 must fit in file
        if self.l1_table_entries > 0 {
            let l1_byte_size = (self.l1_table_entries as u64)
                .checked_mul(L1_ENTRY_SIZE as u64)
                .ok_or(Error::ArithmeticOverflow {
                    context: "l1_table_entries * L1_ENTRY_SIZE",
                })?;
            let l1_end = self
                .l1_table_offset
                .0
                .checked_add(l1_byte_size)
                .ok_or(Error::ArithmeticOverflow {
                    context: "l1_table_offset + l1_byte_size",
                })?;
            if l1_end > file_size {
                return Err(Error::MetadataOffsetBeyondEof {
                    offset: self.l1_table_offset.0,
                    size: l1_byte_size,
                    file_size,
                    context: "L1 table",
                });
            }
        }

        // Refcount table: must be cluster-aligned and fit in file
        if self.refcount_table_clusters > 0 {
            if !self
                .refcount_table_offset
                .is_cluster_aligned(self.cluster_bits)
            {
                return Err(Error::RefcountBlockMisaligned {
                    offset: self.refcount_table_offset.0,
                });
            }
            let rt_byte_size = (self.refcount_table_clusters as u64)
                .checked_mul(cluster_size)
                .ok_or(Error::ArithmeticOverflow {
                    context: "refcount_table_clusters * cluster_size",
                })?;
            let rt_end = self
                .refcount_table_offset
                .0
                .checked_add(rt_byte_size)
                .ok_or(Error::ArithmeticOverflow {
                    context: "refcount_table_offset + rt_byte_size",
                })?;
            if rt_end > file_size {
                return Err(Error::MetadataOffsetBeyondEof {
                    offset: self.refcount_table_offset.0,
                    size: rt_byte_size,
                    file_size,
                    context: "refcount table",
                });
            }
        }

        // Backing file name: must respect MAX_BACKING_FILE_NAME and fit in file
        if self.has_backing_file() {
            if self.backing_file_size > MAX_BACKING_FILE_NAME {
                return Err(Error::AllocationTooLarge {
                    requested: self.backing_file_size as u64,
                    max: MAX_BACKING_FILE_NAME as u64,
                    context: "backing file name",
                });
            }
            let bf_end = self
                .backing_file_offset
                .checked_add(self.backing_file_size as u64)
                .ok_or(Error::ArithmeticOverflow {
                    context: "backing_file_offset + backing_file_size",
                })?;
            if bf_end > file_size {
                return Err(Error::MetadataOffsetBeyondEof {
                    offset: self.backing_file_offset,
                    size: self.backing_file_size as u64,
                    file_size,
                    context: "backing file name",
                });
            }
        }

        // Snapshot table: offset must be within file
        if self.snapshot_count > 0 && self.snapshots_offset.0 >= file_size {
            return Err(Error::MetadataOffsetBeyondEof {
                offset: self.snapshots_offset.0,
                size: 0,
                file_size,
                context: "snapshot table",
            });
        }

        // header_length must not exceed cluster_size (header lives in first cluster)
        if (self.header_length as u64) > cluster_size {
            return Err(Error::AllocationTooLarge {
                requested: self.header_length as u64,
                max: cluster_size,
                context: "header_length exceeds cluster size",
            });
        }

        // Only deflate compression is supported
        if self.compression_type != COMPRESSION_DEFLATE {
            return Err(Error::UnsupportedCompressionType {
                compression_type: self.compression_type as u8,
            });
        }

        Ok(())
    }
}

/// Helper to create a minimal valid v3 header for testing.
#[cfg(test)]
fn make_test_header_v3() -> Header {
    Header {
        version: VERSION_3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits: DEFAULT_CLUSTER_BITS,
        virtual_size: 1024 * 1024 * 1024, // 1 GB
        crypt_method: CRYPT_NONE,
        l1_table_entries: 16,
        l1_table_offset: ClusterOffset(0x3_0000),
        refcount_table_offset: ClusterOffset(0x1_0000),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: IncompatibleFeatures::empty(),
        compatible_features: CompatibleFeatures::empty(),
        autoclear_features: AutoclearFeatures::empty(),
        refcount_order: 4,
        header_length: HEADER_V3_MIN_LENGTH as u32,
        compression_type: COMPRESSION_DEFLATE,
    }
}

/// Helper to create a minimal valid v2 header for testing.
#[cfg(test)]
fn make_test_header_v2() -> Header {
    Header {
        version: VERSION_2,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits: DEFAULT_CLUSTER_BITS,
        virtual_size: 512 * 1024 * 1024, // 512 MB
        crypt_method: CRYPT_NONE,
        l1_table_entries: 8,
        l1_table_offset: ClusterOffset(0x1_0000),
        refcount_table_offset: ClusterOffset(0x2_0000),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: IncompatibleFeatures::empty(),
        compatible_features: CompatibleFeatures::empty(),
        autoclear_features: AutoclearFeatures::empty(),
        refcount_order: DEFAULT_REFCOUNT_ORDER_V2,
        header_length: HEADER_V2_LENGTH as u32,
        compression_type: COMPRESSION_DEFLATE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Computed property tests ----

    #[test]
    fn cluster_size_default() {
        let h = make_test_header_v3();
        assert_eq!(h.cluster_size(), 65536);
    }

    #[test]
    fn l2_entries_per_table_default() {
        let h = make_test_header_v3();
        assert_eq!(h.l2_entries_per_table(), 8192);
    }

    #[test]
    fn refcount_bits_default_v3() {
        let h = make_test_header_v3();
        assert_eq!(h.refcount_bits(), 16); // order 4 => 2^4 = 16
    }

    #[test]
    fn refcounts_per_block_default() {
        let h = make_test_header_v3();
        // 65536 bytes * 8 bits / 16 bits = 32768
        assert_eq!(h.refcounts_per_block(), 32768);
    }

    #[test]
    fn has_backing_file_detection() {
        let mut h = make_test_header_v3();
        assert!(!h.has_backing_file());

        h.backing_file_offset = 100;
        h.backing_file_size = 10;
        assert!(h.has_backing_file());
    }

    // ---- v3 round-trip ----

    #[test]
    fn round_trip_v3() {
        let original = make_test_header_v3();
        let mut buf = vec![0u8; original.serialized_length()];
        original.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    // ---- v2 round-trip ----

    #[test]
    fn round_trip_v2() {
        let original = make_test_header_v2();
        let mut buf = vec![0u8; original.serialized_length()];
        original.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    // ---- v3 with features ----

    #[test]
    fn round_trip_v3_with_features() {
        let mut h = make_test_header_v3();
        h.incompatible_features = IncompatibleFeatures::DIRTY;
        h.compatible_features = CompatibleFeatures::LAZY_REFCOUNTS;
        h.autoclear_features = AutoclearFeatures::BITMAPS;
        h.refcount_order = 6; // 64-bit refcounts

        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(h, parsed);
    }

    // ---- Rejection tests ----

    #[test]
    fn reject_wrong_magic() {
        let h = make_test_header_v3();
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();

        // Corrupt the magic
        BigEndian::write_u32(&mut buf[0..], 0xDEADBEEF);
        match Header::read_from(&buf) {
            Err(Error::InvalidMagic { found, .. }) => assert_eq!(found, 0xDEADBEEF),
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn reject_unsupported_version() {
        let h = make_test_header_v3();
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();

        BigEndian::write_u32(&mut buf[OFF_VERSION..], 4);
        match Header::read_from(&buf) {
            Err(Error::UnsupportedVersion { version }) => assert_eq!(version, 4),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn reject_too_short_for_v2() {
        let buf = vec![0u8; 50]; // Less than 72
        match Header::read_from(&buf) {
            Err(Error::HeaderTooShort { expected: 72, .. }) => {}
            other => panic!("expected HeaderTooShort, got {other:?}"),
        }
    }

    #[test]
    fn reject_too_short_for_v3() {
        // Build a valid v2 header but with version=3
        let h = make_test_header_v2();
        let mut buf = vec![0u8; HEADER_V2_LENGTH];
        h.write_to(&mut buf).unwrap();
        BigEndian::write_u32(&mut buf[OFF_VERSION..], VERSION_3);

        match Header::read_from(&buf) {
            Err(Error::HeaderTooShort { expected: 104, .. }) => {}
            other => panic!("expected HeaderTooShort, got {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_cluster_bits() {
        let good = make_test_header_v3();
        let mut buf = vec![0u8; good.serialized_length()];
        good.write_to(&mut buf).unwrap();
        BigEndian::write_u32(&mut buf[OFF_CLUSTER_BITS..], 8);

        match Header::read_from(&buf) {
            Err(Error::InvalidClusterBits {
                cluster_bits: 8, ..
            }) => {}
            other => panic!("expected InvalidClusterBits, got {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_refcount_order() {
        let good = make_test_header_v3();
        let mut buf = vec![0u8; good.serialized_length()];
        good.write_to(&mut buf).unwrap();
        BigEndian::write_u32(&mut buf[OFF_REFCOUNT_ORDER..], 7);

        match Header::read_from(&buf) {
            Err(Error::InvalidRefcountOrder { order: 7, .. }) => {}
            other => panic!("expected InvalidRefcountOrder, got {other:?}"),
        }
    }

    #[test]
    fn reject_unsupported_incompatible_features() {
        let good = make_test_header_v3();
        let mut buf = vec![0u8; good.serialized_length()];
        good.write_to(&mut buf).unwrap();
        // Set EXTERNAL_DATA_FILE bit (not supported)
        BigEndian::write_u64(
            &mut buf[OFF_INCOMPATIBLE_FEATURES..],
            IncompatibleFeatures::EXTERNAL_DATA_FILE.bits(),
        );

        match Header::read_from(&buf) {
            Err(Error::UnsupportedIncompatibleFeatures { .. }) => {}
            other => panic!("expected UnsupportedIncompatibleFeatures, got {other:?}"),
        }
    }

    // ---- Serialized length ----

    #[test]
    fn serialized_length_v2() {
        let h = make_test_header_v2();
        assert_eq!(h.serialized_length(), 72);
    }

    #[test]
    fn serialized_length_v3() {
        let h = make_test_header_v3();
        assert_eq!(h.serialized_length(), 104);
    }

    // ---- Buffer too small for write_to ----

    #[test]
    fn write_to_rejects_small_buffer() {
        let h = make_test_header_v3();
        let mut buf = vec![0u8; 50];
        match h.write_to(&mut buf) {
            Err(Error::BufferTooSmall { .. }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    // ---- Edge cases: extreme but valid configurations ----

    #[test]
    fn accept_min_cluster_bits() {
        let mut h = make_test_header_v3();
        h.cluster_bits = MIN_CLUSTER_BITS; // 9
        h.l1_table_offset = ClusterOffset(1u64 << MIN_CLUSTER_BITS); // cluster-aligned
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(parsed.cluster_bits, MIN_CLUSTER_BITS);
        assert_eq!(parsed.cluster_size(), 512);
    }

    #[test]
    fn accept_max_cluster_bits() {
        let mut h = make_test_header_v3();
        h.cluster_bits = MAX_CLUSTER_BITS; // 21
        h.l1_table_offset = ClusterOffset(1u64 << MAX_CLUSTER_BITS); // cluster-aligned
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(parsed.cluster_bits, MAX_CLUSTER_BITS);
        assert_eq!(parsed.cluster_size(), 1 << 21);
    }

    #[test]
    fn accept_refcount_order_zero() {
        // refcount_order=0 means 1-bit refcounts (valid)
        let mut h = make_test_header_v3();
        h.refcount_order = 0;
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(parsed.refcount_order, 0);
        assert_eq!(parsed.refcount_bits(), 1);
    }

    #[test]
    fn l1_table_entries_zero_is_valid() {
        let mut h = make_test_header_v3();
        h.l1_table_entries = 0;
        h.l1_table_offset = ClusterOffset(0);
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(parsed.l1_table_entries, 0);
    }

    #[test]
    fn v2_defaults_for_v3_fields() {
        let h = make_test_header_v2();
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();

        // v2 should get defaults for v3-only fields
        assert_eq!(parsed.incompatible_features, IncompatibleFeatures::empty());
        assert_eq!(parsed.compatible_features, CompatibleFeatures::empty());
        assert_eq!(parsed.autoclear_features, AutoclearFeatures::empty());
        assert_eq!(parsed.refcount_order, DEFAULT_REFCOUNT_ORDER_V2); // 4 (16-bit)
        assert_eq!(parsed.header_length, HEADER_V2_LENGTH as u32);
    }

    #[test]
    fn has_backing_file_requires_both_offset_and_size() {
        let mut h = make_test_header_v3();

        // offset but no size
        h.backing_file_offset = 100;
        h.backing_file_size = 0;
        assert!(!h.has_backing_file());

        // size but no offset
        h.backing_file_offset = 0;
        h.backing_file_size = 10;
        assert!(!h.has_backing_file());

        // both set
        h.backing_file_offset = 100;
        h.backing_file_size = 10;
        assert!(h.has_backing_file());
    }

    #[test]
    fn reject_cluster_bits_just_above_max() {
        let good = make_test_header_v3();
        let mut buf = vec![0u8; good.serialized_length()];
        good.write_to(&mut buf).unwrap();
        BigEndian::write_u32(&mut buf[OFF_CLUSTER_BITS..], MAX_CLUSTER_BITS + 1);

        assert!(matches!(
            Header::read_from(&buf),
            Err(Error::InvalidClusterBits { .. })
        ));
    }

    #[test]
    fn reject_cluster_bits_just_below_min() {
        let good = make_test_header_v3();
        let mut buf = vec![0u8; good.serialized_length()];
        good.write_to(&mut buf).unwrap();
        BigEndian::write_u32(&mut buf[OFF_CLUSTER_BITS..], MIN_CLUSTER_BITS - 1);

        assert!(matches!(
            Header::read_from(&buf),
            Err(Error::InvalidClusterBits { .. })
        ));
    }

    #[test]
    fn v3_header_with_compression_type_field() {
        let mut h = make_test_header_v3();
        h.header_length = 105; // Just enough for compression_type byte
        h.compression_type = 0; // deflate

        let mut buf = vec![0u8; 105];
        h.write_to(&mut buf).unwrap();
        let parsed = Header::read_from(&buf).unwrap();
        assert_eq!(parsed.compression_type, 0);
    }

    #[test]
    fn reject_misaligned_l1_table_offset() {
        // L1 table offset must be cluster-aligned when l1_table_entries > 0.
        let mut h = make_test_header_v3();
        h.l1_table_offset = ClusterOffset(0x3_0001); // off by 1 byte
        let mut buf = vec![0u8; h.serialized_length()];
        h.write_to(&mut buf).unwrap();

        match Header::read_from(&buf) {
            Err(Error::L2TableMisaligned { offset: 0x3_0001 }) => {}
            other => panic!("expected L2TableMisaligned, got {other:?}"),
        }
    }

    // ---- validate_against_file tests ----

    #[test]
    fn validate_valid_header_passes() {
        let h = make_test_header_v3();
        h.validate_against_file(0x100_0000).unwrap();
    }

    #[test]
    fn validate_virtual_size_zero() {
        let mut h = make_test_header_v3();
        h.virtual_size = 0;
        match h.validate_against_file(0x100_0000) {
            Err(Error::AllocationTooLarge { context, .. }) if context.contains("virtual_size") => {}
            other => panic!("expected AllocationTooLarge for zero virtual_size, got {other:?}"),
        }
    }

    #[test]
    fn validate_l1_table_beyond_eof() {
        let h = make_test_header_v3();
        // File is too small for L1 table (offset 0x3_0000 + 16*8 = 0x3_0080)
        let file_size = h.l1_table_offset.0 + 10;
        match h.validate_against_file(file_size) {
            Err(Error::MetadataOffsetBeyondEof {
                context: "L1 table",
                ..
            }) => {}
            other => panic!("expected MetadataOffsetBeyondEof for L1, got {other:?}"),
        }
    }

    #[test]
    fn validate_l1_entries_overflow() {
        let mut h = make_test_header_v3();
        h.l1_table_entries = u32::MAX;
        match h.validate_against_file(0x100_0000) {
            Err(Error::MetadataOffsetBeyondEof { .. }) | Err(Error::ArithmeticOverflow { .. }) => {}
            other => panic!("expected overflow or EOF error, got {other:?}"),
        }
    }

    #[test]
    fn validate_l1_offset_plus_size_overflow() {
        let mut h = make_test_header_v3();
        h.l1_table_offset = ClusterOffset(u64::MAX - 10);
        h.l1_table_entries = 16;
        // offset + 16*8 = u64::MAX - 10 + 128 → overflow
        match h.validate_against_file(u64::MAX) {
            Err(Error::ArithmeticOverflow { .. }) => {}
            other => panic!("expected ArithmeticOverflow, got {other:?}"),
        }
    }

    #[test]
    fn validate_refcount_table_misaligned() {
        let mut h = make_test_header_v3();
        h.refcount_table_offset = ClusterOffset(0x1_0001); // not aligned
        h.refcount_table_clusters = 1;
        match h.validate_against_file(0x100_0000) {
            Err(Error::RefcountBlockMisaligned { .. }) => {}
            other => panic!("expected RefcountBlockMisaligned, got {other:?}"),
        }
    }

    #[test]
    fn validate_refcount_table_beyond_eof() {
        let mut h = make_test_header_v3();
        h.refcount_table_offset = ClusterOffset(0x100_0000);
        h.refcount_table_clusters = 1;
        let file_size = 0x80_0000;
        match h.validate_against_file(file_size) {
            Err(Error::MetadataOffsetBeyondEof {
                context: "refcount table",
                ..
            }) => {}
            other => panic!("expected MetadataOffsetBeyondEof for refcount, got {other:?}"),
        }
    }

    #[test]
    fn validate_refcount_clusters_overflow() {
        let mut h = make_test_header_v3();
        h.refcount_table_clusters = u32::MAX;
        // Even with u32::MAX clusters, the total size overflows u64 when
        // combined with the offset, or at least exceeds any real file.
        match h.validate_against_file(0x100_0000) {
            Err(Error::MetadataOffsetBeyondEof {
                context: "refcount table",
                ..
            }) => {}
            other => panic!("expected MetadataOffsetBeyondEof, got {other:?}"),
        }
    }

    #[test]
    fn validate_backing_file_name_too_long() {
        let mut h = make_test_header_v3();
        h.backing_file_offset = 100;
        h.backing_file_size = MAX_BACKING_FILE_NAME + 1;
        match h.validate_against_file(0x100_0000) {
            Err(Error::AllocationTooLarge {
                context: "backing file name",
                ..
            }) => {}
            other => panic!("expected AllocationTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validate_backing_file_beyond_eof() {
        let mut h = make_test_header_v3();
        // Use a file_size large enough that L1 + refcount pass, but
        // the backing file name extends past EOF.
        h.backing_file_offset = 0x200_0000 - 10;
        h.backing_file_size = 100;
        let file_size = 0x200_0000;
        match h.validate_against_file(file_size) {
            Err(Error::MetadataOffsetBeyondEof {
                context: "backing file name",
                ..
            }) => {}
            other => panic!("expected MetadataOffsetBeyondEof, got {other:?}"),
        }
    }

    #[test]
    fn validate_snapshot_offset_beyond_eof() {
        let mut h = make_test_header_v3();
        h.snapshot_count = 1;
        h.snapshots_offset = ClusterOffset(0x200_0000);
        match h.validate_against_file(0x100_0000) {
            Err(Error::MetadataOffsetBeyondEof {
                context: "snapshot table",
                ..
            }) => {}
            other => panic!("expected MetadataOffsetBeyondEof, got {other:?}"),
        }
    }

    #[test]
    fn validate_header_length_exceeds_cluster() {
        let mut h = make_test_header_v3();
        h.header_length = 0x2_0000; // 128KB, larger than 64KB cluster
        match h.validate_against_file(0x100_0000) {
            Err(Error::AllocationTooLarge { .. }) => {}
            other => panic!("expected AllocationTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validate_unsupported_compression_type() {
        let mut h = make_test_header_v3();
        h.compression_type = 99;
        match h.validate_against_file(0x100_0000) {
            Err(Error::UnsupportedCompressionType { compression_type: 99 }) => {}
            other => panic!("expected UnsupportedCompressionType, got {other:?}"),
        }
    }
}
