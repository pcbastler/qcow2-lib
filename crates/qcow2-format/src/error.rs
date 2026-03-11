//! Format-level error types for QCOW2 on-disk structure parsing.
//!
//! These errors cover invalid data encountered during parsing and encoding
//! of on-disk structures. They carry context about WHERE the error occurred.
//!
//! This module is `no_std`-compatible.

extern crate alloc;

use alloc::string::String;
use core::fmt;

/// Alias for `core::result::Result` with [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors from parsing or encoding QCOW2 on-disk format structures.
#[derive(Debug)]
pub enum Error {
    // ---- Header parsing ----

    /// The file does not start with the QCOW2 magic number.
    InvalidMagic {
        /// Expected magic value (always `0x514649fb`).
        expected: u32,
        /// Actual value read from the file.
        found: u32,
    },

    /// The QCOW2 version is not supported (only v2 and v3 are valid).
    UnsupportedVersion {
        /// The version number found in the header.
        version: u32,
    },

    /// The header data is shorter than required for the detected version.
    HeaderTooShort {
        /// Minimum required header length in bytes.
        expected: usize,
        /// Actual length of available data.
        actual: usize,
    },

    /// The cluster_bits field is outside the valid range.
    InvalidClusterBits {
        /// The invalid cluster_bits value.
        cluster_bits: u32,
        /// Minimum allowed value (typically 9).
        min: u32,
        /// Maximum allowed value (typically 21).
        max: u32,
    },

    /// The image uses incompatible feature flags that this implementation
    /// does not support. The image must not be opened.
    UnsupportedIncompatibleFeatures {
        /// Bitmask of the unsupported feature bits.
        features: u64,
    },

    /// The image uses a compression type that is not supported.
    UnsupportedCompressionType {
        /// The unsupported compression type value from the header.
        compression_type: u8,
    },

    // ---- Table errors ----

    /// An L1 table index is out of bounds.
    L1IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual table size.
        table_size: u32,
    },

    /// An L2 table index is out of bounds.
    L2IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual table size.
        table_size: u32,
    },

    /// An L1 table was found at a non-cluster-aligned offset.
    L1TableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    // ---- Refcount errors ----

    /// The refcount order exceeds the maximum allowed value.
    InvalidRefcountOrder {
        /// The invalid refcount order.
        order: u32,
        /// Maximum allowed refcount order (6, for 64-bit refcounts).
        max: u32,
    },

    /// A refcount block was found at a non-cluster-aligned offset.
    RefcountBlockMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    /// A refcount block index is out of bounds.
    RefcountIndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual block size in entries.
        block_size: u32,
    },

    // ---- Snapshot ----

    /// A snapshot header is truncated (not enough data).
    SnapshotTruncated {
        /// Byte offset of the snapshot header.
        offset: u64,
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },

    /// The snapshot table is too short for the expected number of entries.
    SnapshotTableTruncated {
        /// 0-based index of the snapshot entry that couldn't be read.
        entry: u32,
        /// Byte offset where the entry was expected.
        offset: u64,
        /// Total size of the snapshot table in bytes.
        table_size: usize,
    },

    // ---- Header extension ----

    /// A header extension is truncated.
    ExtensionTruncated {
        /// Byte offset of the extension within the extension area.
        offset: usize,
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },

    // ---- Data integrity ----

    /// A buffer provided for serialization is too small.
    BufferTooSmall {
        /// Required buffer size.
        expected: usize,
        /// Actual buffer size.
        actual: usize,
    },

    // ---- Corruption / hardening ----

    /// A metadata structure references an offset beyond the physical file.
    MetadataOffsetBeyondEof {
        /// The host offset that is out of bounds.
        offset: u64,
        /// The size of the metadata structure at that offset.
        size: u64,
        /// Physical file size in bytes.
        file_size: u64,
        /// Which metadata structure is affected.
        context: &'static str,
    },

    /// A metadata field would cause an unreasonably large allocation.
    AllocationTooLarge {
        /// Requested allocation size in bytes.
        requested: u64,
        /// Maximum allowed size in bytes.
        max: u64,
        /// What was being allocated.
        context: &'static str,
    },

    /// An arithmetic overflow occurred while computing metadata sizes.
    ArithmeticOverflow {
        /// Human-readable description of the computation that overflowed.
        context: &'static str,
    },

    // ---- Bitmap errors ----

    /// Bitmap directory entry is truncated.
    BitmapDirectoryTruncated {
        /// Byte offset within the directory.
        offset: usize,
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },

    /// Bitmap extension header is invalid.
    InvalidBitmapExtension {
        /// Description of what is wrong.
        message: String,
    },

    /// A bitmap table index is out of bounds.
    BitmapIndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual table size.
        table_size: u32,
    },

    // ---- Extended L2 errors ----

    /// Extended L2 requires cluster_bits >= 14.
    ExtendedL2ClusterBitsTooSmall {
        /// The actual cluster_bits value.
        cluster_bits: u32,
        /// Minimum required value (14).
        min: u32,
    },

    // ---- BLAKE3 hash errors ----

    /// The BLAKE3 hash extension header is invalid.
    InvalidHashExtension {
        /// Description of what is wrong.
        message: String,
    },

    /// The hash size is not a valid value (must be 16 or 32).
    InvalidHashSize {
        /// The invalid hash size in bytes.
        size: u8,
    },

    /// The hash chunk bits value is out of the valid range.
    InvalidHashChunkBits {
        /// The invalid chunk bits value.
        bits: u8,
        /// Minimum allowed value.
        min: u8,
        /// Maximum allowed value.
        max: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic { expected, found } =>
                write!(f, "invalid QCOW2 magic: expected 0x{expected:08x}, found 0x{found:08x}"),
            Self::UnsupportedVersion { version } =>
                write!(f, "unsupported QCOW2 version {version} (supported: 2, 3)"),
            Self::HeaderTooShort { expected, actual } =>
                write!(f, "header too short: need {expected} bytes, got {actual}"),
            Self::InvalidClusterBits { cluster_bits, min, max } =>
                write!(f, "invalid cluster_bits {cluster_bits}: must be in [{min}..={max}]"),
            Self::UnsupportedIncompatibleFeatures { features } =>
                write!(f, "unsupported incompatible features: 0x{features:016x}"),
            Self::UnsupportedCompressionType { compression_type } =>
                write!(f, "unsupported compression type {compression_type} (supported: deflate/0, zstd/1)"),
            Self::L1IndexOutOfBounds { index, table_size } =>
                write!(f, "L1 index {index} out of bounds (table size: {table_size})"),
            Self::L2IndexOutOfBounds { index, table_size } =>
                write!(f, "L2 index {index} out of bounds (table size: {table_size})"),
            Self::L1TableMisaligned { offset } =>
                write!(f, "L1 table at offset 0x{offset:x} is not cluster-aligned"),
            Self::InvalidRefcountOrder { order, max } =>
                write!(f, "invalid refcount order {order} (max: {max})"),
            Self::RefcountBlockMisaligned { offset } =>
                write!(f, "refcount block at offset 0x{offset:x} is not cluster-aligned"),
            Self::RefcountIndexOutOfBounds { index, block_size } =>
                write!(f, "refcount index {index} out of bounds (block size: {block_size})"),
            Self::SnapshotTruncated { offset, expected, actual } =>
                write!(f, "snapshot header at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::SnapshotTableTruncated { entry, offset, table_size } =>
                write!(f, "snapshot table truncated: entry {entry} at offset 0x{offset:x} exceeds table size of {table_size} bytes"),
            Self::ExtensionTruncated { offset, expected, actual } =>
                write!(f, "header extension at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::BufferTooSmall { expected, actual } =>
                write!(f, "buffer too small: need {expected} bytes, got {actual}"),
            Self::MetadataOffsetBeyondEof { offset, size, file_size, context } =>
                write!(f, "metadata offset 0x{offset:x} with size {size} exceeds file size 0x{file_size:x} ({context})"),
            Self::AllocationTooLarge { requested, max, context } =>
                write!(f, "allocation too large: {context} requested {requested} bytes (max: {max})"),
            Self::ArithmeticOverflow { context } =>
                write!(f, "arithmetic overflow in {context}"),
            Self::BitmapDirectoryTruncated { offset, expected, actual } =>
                write!(f, "bitmap directory entry at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::InvalidBitmapExtension { message } =>
                write!(f, "invalid bitmap extension: {message}"),
            Self::BitmapIndexOutOfBounds { index, table_size } =>
                write!(f, "bitmap table index {index} out of bounds (table size: {table_size})"),
            Self::ExtendedL2ClusterBitsTooSmall { cluster_bits, min } =>
                write!(f, "extended L2 requires cluster_bits >= {min}, got {cluster_bits}"),
            Self::InvalidHashExtension { message } =>
                write!(f, "invalid hash extension: {message}"),
            Self::InvalidHashSize { size } =>
                write!(f, "invalid hash size {size} (must be 16 or 32)"),
            Self::InvalidHashChunkBits { bits, min, max } =>
                write!(f, "invalid hash chunk bits {bits} (must be 0 or {min}..={max})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    // ---- InvalidMagic ----

    #[test]
    fn display_invalid_magic_typical() {
        let e = Error::InvalidMagic { expected: 0x514649fb, found: 0x00000000 };
        assert_eq!(e.to_string(), "invalid QCOW2 magic: expected 0x514649fb, found 0x00000000");
    }

    #[test]
    fn display_invalid_magic_max() {
        let e = Error::InvalidMagic { expected: u32::MAX, found: u32::MAX };
        assert_eq!(e.to_string(), "invalid QCOW2 magic: expected 0xffffffff, found 0xffffffff");
    }

    #[test]
    fn display_invalid_magic_zero() {
        let e = Error::InvalidMagic { expected: 0, found: 0 };
        assert_eq!(e.to_string(), "invalid QCOW2 magic: expected 0x00000000, found 0x00000000");
    }

    #[test]
    fn debug_invalid_magic() {
        let e = Error::InvalidMagic { expected: 0x514649fb, found: 0 };
        let _ = format!("{e:?}");
    }

    // ---- UnsupportedVersion ----

    #[test]
    fn display_unsupported_version() {
        let e = Error::UnsupportedVersion { version: 1 };
        assert_eq!(e.to_string(), "unsupported QCOW2 version 1 (supported: 2, 3)");
    }

    #[test]
    fn display_unsupported_version_zero() {
        let e = Error::UnsupportedVersion { version: 0 };
        assert_eq!(e.to_string(), "unsupported QCOW2 version 0 (supported: 2, 3)");
    }

    #[test]
    fn display_unsupported_version_max() {
        let e = Error::UnsupportedVersion { version: u32::MAX };
        assert_eq!(
            e.to_string(),
            format!("unsupported QCOW2 version {} (supported: 2, 3)", u32::MAX)
        );
    }

    // ---- HeaderTooShort ----

    #[test]
    fn display_header_too_short() {
        let e = Error::HeaderTooShort { expected: 104, actual: 72 };
        assert_eq!(e.to_string(), "header too short: need 104 bytes, got 72");
    }

    #[test]
    fn display_header_too_short_zero() {
        let e = Error::HeaderTooShort { expected: 0, actual: 0 };
        assert_eq!(e.to_string(), "header too short: need 0 bytes, got 0");
    }

    // ---- InvalidClusterBits ----

    #[test]
    fn display_invalid_cluster_bits() {
        let e = Error::InvalidClusterBits { cluster_bits: 8, min: 9, max: 21 };
        assert_eq!(e.to_string(), "invalid cluster_bits 8: must be in [9..=21]");
    }

    #[test]
    fn display_invalid_cluster_bits_zero() {
        let e = Error::InvalidClusterBits { cluster_bits: 0, min: 0, max: 0 };
        assert_eq!(e.to_string(), "invalid cluster_bits 0: must be in [0..=0]");
    }

    // ---- UnsupportedIncompatibleFeatures ----

    #[test]
    fn display_unsupported_incompatible_features() {
        let e = Error::UnsupportedIncompatibleFeatures { features: 0x0000000000000080 };
        assert_eq!(e.to_string(), "unsupported incompatible features: 0x0000000000000080");
    }

    #[test]
    fn display_unsupported_incompatible_features_max() {
        let e = Error::UnsupportedIncompatibleFeatures { features: u64::MAX };
        assert_eq!(e.to_string(), "unsupported incompatible features: 0xffffffffffffffff");
    }

    #[test]
    fn display_unsupported_incompatible_features_zero() {
        let e = Error::UnsupportedIncompatibleFeatures { features: 0 };
        assert_eq!(e.to_string(), "unsupported incompatible features: 0x0000000000000000");
    }

    // ---- UnsupportedCompressionType ----

    #[test]
    fn display_unsupported_compression_type() {
        let e = Error::UnsupportedCompressionType { compression_type: 5 };
        assert_eq!(e.to_string(), "unsupported compression type 5 (supported: deflate/0, zstd/1)");
    }

    #[test]
    fn display_unsupported_compression_type_max() {
        let e = Error::UnsupportedCompressionType { compression_type: u8::MAX };
        assert_eq!(e.to_string(), "unsupported compression type 255 (supported: deflate/0, zstd/1)");
    }

    // ---- L1IndexOutOfBounds ----

    #[test]
    fn display_l1_index_out_of_bounds() {
        let e = Error::L1IndexOutOfBounds { index: 100, table_size: 50 };
        assert_eq!(e.to_string(), "L1 index 100 out of bounds (table size: 50)");
    }

    #[test]
    fn display_l1_index_out_of_bounds_zero() {
        let e = Error::L1IndexOutOfBounds { index: 0, table_size: 0 };
        assert_eq!(e.to_string(), "L1 index 0 out of bounds (table size: 0)");
    }

    // ---- L2IndexOutOfBounds ----

    #[test]
    fn display_l2_index_out_of_bounds() {
        let e = Error::L2IndexOutOfBounds { index: 512, table_size: 256 };
        assert_eq!(e.to_string(), "L2 index 512 out of bounds (table size: 256)");
    }

    #[test]
    fn display_l2_index_out_of_bounds_max() {
        let e = Error::L2IndexOutOfBounds { index: u32::MAX, table_size: u32::MAX };
        assert_eq!(
            e.to_string(),
            format!("L2 index {} out of bounds (table size: {})", u32::MAX, u32::MAX)
        );
    }

    // ---- L1TableMisaligned ----

    #[test]
    fn display_l1_table_misaligned() {
        let e = Error::L1TableMisaligned { offset: 0x10001 };
        assert_eq!(e.to_string(), "L1 table at offset 0x10001 is not cluster-aligned");
    }

    #[test]
    fn display_l1_table_misaligned_zero() {
        let e = Error::L1TableMisaligned { offset: 0 };
        assert_eq!(e.to_string(), "L1 table at offset 0x0 is not cluster-aligned");
    }

    // ---- InvalidRefcountOrder ----

    #[test]
    fn display_invalid_refcount_order() {
        let e = Error::InvalidRefcountOrder { order: 7, max: 6 };
        assert_eq!(e.to_string(), "invalid refcount order 7 (max: 6)");
    }

    #[test]
    fn display_invalid_refcount_order_zero() {
        let e = Error::InvalidRefcountOrder { order: 0, max: 0 };
        assert_eq!(e.to_string(), "invalid refcount order 0 (max: 0)");
    }

    // ---- RefcountBlockMisaligned ----

    #[test]
    fn display_refcount_block_misaligned() {
        let e = Error::RefcountBlockMisaligned { offset: 0xdeadbeef };
        assert_eq!(e.to_string(), "refcount block at offset 0xdeadbeef is not cluster-aligned");
    }

    #[test]
    fn display_refcount_block_misaligned_zero() {
        let e = Error::RefcountBlockMisaligned { offset: 0 };
        assert_eq!(e.to_string(), "refcount block at offset 0x0 is not cluster-aligned");
    }

    // ---- RefcountIndexOutOfBounds ----

    #[test]
    fn display_refcount_index_out_of_bounds() {
        let e = Error::RefcountIndexOutOfBounds { index: 1024, block_size: 512 };
        assert_eq!(e.to_string(), "refcount index 1024 out of bounds (block size: 512)");
    }

    #[test]
    fn display_refcount_index_out_of_bounds_zero() {
        let e = Error::RefcountIndexOutOfBounds { index: 0, block_size: 0 };
        assert_eq!(e.to_string(), "refcount index 0 out of bounds (block size: 0)");
    }

    // ---- SnapshotTruncated ----

    #[test]
    fn display_snapshot_truncated() {
        let e = Error::SnapshotTruncated { offset: 0x30000, expected: 40, actual: 20 };
        assert_eq!(
            e.to_string(),
            "snapshot header at offset 0x30000 is truncated: need 40 bytes, got 20"
        );
    }

    #[test]
    fn display_snapshot_truncated_zero() {
        let e = Error::SnapshotTruncated { offset: 0, expected: 0, actual: 0 };
        assert_eq!(
            e.to_string(),
            "snapshot header at offset 0x0 is truncated: need 0 bytes, got 0"
        );
    }

    // ---- SnapshotTableTruncated ----

    #[test]
    fn display_snapshot_table_truncated() {
        let e = Error::SnapshotTableTruncated { entry: 3, offset: 0x1000, table_size: 512 };
        assert_eq!(
            e.to_string(),
            "snapshot table truncated: entry 3 at offset 0x1000 exceeds table size of 512 bytes"
        );
    }

    #[test]
    fn display_snapshot_table_truncated_zero() {
        let e = Error::SnapshotTableTruncated { entry: 0, offset: 0, table_size: 0 };
        assert_eq!(
            e.to_string(),
            "snapshot table truncated: entry 0 at offset 0x0 exceeds table size of 0 bytes"
        );
    }

    // ---- ExtensionTruncated ----

    #[test]
    fn display_extension_truncated() {
        let e = Error::ExtensionTruncated { offset: 0x200, expected: 16, actual: 8 };
        assert_eq!(
            e.to_string(),
            "header extension at offset 0x200 is truncated: need 16 bytes, got 8"
        );
    }

    #[test]
    fn display_extension_truncated_zero() {
        let e = Error::ExtensionTruncated { offset: 0, expected: 0, actual: 0 };
        assert_eq!(
            e.to_string(),
            "header extension at offset 0x0 is truncated: need 0 bytes, got 0"
        );
    }

    // ---- BufferTooSmall ----

    #[test]
    fn display_buffer_too_small() {
        let e = Error::BufferTooSmall { expected: 4096, actual: 512 };
        assert_eq!(e.to_string(), "buffer too small: need 4096 bytes, got 512");
    }

    #[test]
    fn display_buffer_too_small_zero() {
        let e = Error::BufferTooSmall { expected: 0, actual: 0 };
        assert_eq!(e.to_string(), "buffer too small: need 0 bytes, got 0");
    }

    // ---- MetadataOffsetBeyondEof ----

    #[test]
    fn display_metadata_offset_beyond_eof() {
        let e = Error::MetadataOffsetBeyondEof {
            offset: 0x100000,
            size: 65536,
            file_size: 0x80000,
            context: "L2 table",
        };
        assert_eq!(
            e.to_string(),
            "metadata offset 0x100000 with size 65536 exceeds file size 0x80000 (L2 table)"
        );
    }

    #[test]
    fn display_metadata_offset_beyond_eof_zero() {
        let e = Error::MetadataOffsetBeyondEof {
            offset: 0,
            size: 0,
            file_size: 0,
            context: "",
        };
        assert_eq!(
            e.to_string(),
            "metadata offset 0x0 with size 0 exceeds file size 0x0 ()"
        );
    }

    #[test]
    fn display_metadata_offset_beyond_eof_max() {
        let e = Error::MetadataOffsetBeyondEof {
            offset: u64::MAX,
            size: u64::MAX,
            file_size: u64::MAX,
            context: "refcount block",
        };
        assert_eq!(
            e.to_string(),
            format!(
                "metadata offset 0x{:x} with size {} exceeds file size 0x{:x} (refcount block)",
                u64::MAX, u64::MAX, u64::MAX
            )
        );
    }

    // ---- AllocationTooLarge ----

    #[test]
    fn display_allocation_too_large() {
        let e = Error::AllocationTooLarge {
            requested: 1_000_000_000,
            max: 67_108_864,
            context: "snapshot extra data",
        };
        assert_eq!(
            e.to_string(),
            "allocation too large: snapshot extra data requested 1000000000 bytes (max: 67108864)"
        );
    }

    #[test]
    fn display_allocation_too_large_zero() {
        let e = Error::AllocationTooLarge { requested: 0, max: 0, context: "" };
        assert_eq!(e.to_string(), "allocation too large:  requested 0 bytes (max: 0)");
    }

    // ---- ArithmeticOverflow ----

    #[test]
    fn display_arithmetic_overflow() {
        let e = Error::ArithmeticOverflow { context: "virtual_size * cluster_size" };
        assert_eq!(e.to_string(), "arithmetic overflow in virtual_size * cluster_size");
    }

    #[test]
    fn display_arithmetic_overflow_empty() {
        let e = Error::ArithmeticOverflow { context: "" };
        assert_eq!(e.to_string(), "arithmetic overflow in ");
    }

    // ---- BitmapDirectoryTruncated ----

    #[test]
    fn display_bitmap_directory_truncated() {
        let e = Error::BitmapDirectoryTruncated { offset: 0x400, expected: 24, actual: 10 };
        assert_eq!(
            e.to_string(),
            "bitmap directory entry at offset 0x400 is truncated: need 24 bytes, got 10"
        );
    }

    #[test]
    fn display_bitmap_directory_truncated_zero() {
        let e = Error::BitmapDirectoryTruncated { offset: 0, expected: 0, actual: 0 };
        assert_eq!(
            e.to_string(),
            "bitmap directory entry at offset 0x0 is truncated: need 0 bytes, got 0"
        );
    }

    // ---- InvalidBitmapExtension ----

    #[test]
    fn display_invalid_bitmap_extension() {
        let e = Error::InvalidBitmapExtension { message: String::from("nb_bitmaps is zero") };
        assert_eq!(e.to_string(), "invalid bitmap extension: nb_bitmaps is zero");
    }

    #[test]
    fn display_invalid_bitmap_extension_empty() {
        let e = Error::InvalidBitmapExtension { message: String::new() };
        assert_eq!(e.to_string(), "invalid bitmap extension: ");
    }

    // ---- BitmapIndexOutOfBounds ----

    #[test]
    fn display_bitmap_index_out_of_bounds() {
        let e = Error::BitmapIndexOutOfBounds { index: 64, table_size: 32 };
        assert_eq!(e.to_string(), "bitmap table index 64 out of bounds (table size: 32)");
    }

    #[test]
    fn display_bitmap_index_out_of_bounds_zero() {
        let e = Error::BitmapIndexOutOfBounds { index: 0, table_size: 0 };
        assert_eq!(e.to_string(), "bitmap table index 0 out of bounds (table size: 0)");
    }

    // ---- ExtendedL2ClusterBitsTooSmall ----

    #[test]
    fn display_extended_l2_cluster_bits_too_small() {
        let e = Error::ExtendedL2ClusterBitsTooSmall { cluster_bits: 12, min: 14 };
        assert_eq!(e.to_string(), "extended L2 requires cluster_bits >= 14, got 12");
    }

    #[test]
    fn display_extended_l2_cluster_bits_too_small_zero() {
        let e = Error::ExtendedL2ClusterBitsTooSmall { cluster_bits: 0, min: 0 };
        assert_eq!(e.to_string(), "extended L2 requires cluster_bits >= 0, got 0");
    }

    // ---- InvalidHashExtension ----

    #[test]
    fn display_invalid_hash_extension() {
        let e = Error::InvalidHashExtension { message: String::from("chunk_bits out of range") };
        assert_eq!(e.to_string(), "invalid hash extension: chunk_bits out of range");
    }

    #[test]
    fn display_invalid_hash_extension_empty() {
        let e = Error::InvalidHashExtension { message: String::new() };
        assert_eq!(e.to_string(), "invalid hash extension: ");
    }

    // ---- InvalidHashSize ----

    #[test]
    fn display_invalid_hash_size() {
        let e = Error::InvalidHashSize { size: 24 };
        assert_eq!(e.to_string(), "invalid hash size 24 (must be 16 or 32)");
    }

    #[test]
    fn display_invalid_hash_size_zero() {
        let e = Error::InvalidHashSize { size: 0 };
        assert_eq!(e.to_string(), "invalid hash size 0 (must be 16 or 32)");
    }

    #[test]
    fn display_invalid_hash_size_max() {
        let e = Error::InvalidHashSize { size: u8::MAX };
        assert_eq!(e.to_string(), "invalid hash size 255 (must be 16 or 32)");
    }

    // ---- InvalidHashChunkBits ----

    #[test]
    fn display_invalid_hash_chunk_bits() {
        let e = Error::InvalidHashChunkBits { bits: 8, min: 9, max: 21 };
        assert_eq!(e.to_string(), "invalid hash chunk bits 8 (must be 0 or 9..=21)");
    }

    #[test]
    fn display_invalid_hash_chunk_bits_zero() {
        let e = Error::InvalidHashChunkBits { bits: 0, min: 0, max: 0 };
        assert_eq!(e.to_string(), "invalid hash chunk bits 0 (must be 0 or 0..=0)");
    }

    #[test]
    fn display_invalid_hash_chunk_bits_max() {
        let e = Error::InvalidHashChunkBits { bits: u8::MAX, min: u8::MAX, max: u8::MAX };
        assert_eq!(e.to_string(), "invalid hash chunk bits 255 (must be 0 or 255..=255)");
    }

    // ---- Debug trait coverage for all variants ----

    #[test]
    fn debug_all_variants() {
        let variants: Vec<Error> = vec![
            Error::InvalidMagic { expected: 0x514649fb, found: 0 },
            Error::UnsupportedVersion { version: 1 },
            Error::HeaderTooShort { expected: 104, actual: 0 },
            Error::InvalidClusterBits { cluster_bits: 8, min: 9, max: 21 },
            Error::UnsupportedIncompatibleFeatures { features: 0xff },
            Error::UnsupportedCompressionType { compression_type: 99 },
            Error::L1IndexOutOfBounds { index: 1, table_size: 0 },
            Error::L2IndexOutOfBounds { index: 1, table_size: 0 },
            Error::L1TableMisaligned { offset: 1 },
            Error::InvalidRefcountOrder { order: 7, max: 6 },
            Error::RefcountBlockMisaligned { offset: 1 },
            Error::RefcountIndexOutOfBounds { index: 1, block_size: 0 },
            Error::SnapshotTruncated { offset: 0, expected: 1, actual: 0 },
            Error::SnapshotTableTruncated { entry: 0, offset: 0, table_size: 0 },
            Error::ExtensionTruncated { offset: 0, expected: 1, actual: 0 },
            Error::BufferTooSmall { expected: 1, actual: 0 },
            Error::MetadataOffsetBeyondEof { offset: 0, size: 0, file_size: 0, context: "test" },
            Error::AllocationTooLarge { requested: 0, max: 0, context: "test" },
            Error::ArithmeticOverflow { context: "test" },
            Error::BitmapDirectoryTruncated { offset: 0, expected: 1, actual: 0 },
            Error::InvalidBitmapExtension { message: String::from("test") },
            Error::BitmapIndexOutOfBounds { index: 1, table_size: 0 },
            Error::ExtendedL2ClusterBitsTooSmall { cluster_bits: 9, min: 14 },
            Error::InvalidHashExtension { message: String::from("test") },
            Error::InvalidHashSize { size: 0 },
            Error::InvalidHashChunkBits { bits: 0, min: 9, max: 21 },
        ];
        for e in &variants {
            let dbg = format!("{e:?}");
            assert!(!dbg.is_empty());
        }
    }
}
