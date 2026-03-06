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
