//! Unified error types for the qcow2-lib crate.
//!
//! Every error variant carries context about WHERE the error occurred
//! (byte offset, table index, cluster number) to enable meaningful diagnostics.

use thiserror::Error;

/// Alias for `std::result::Result` with [`Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that can occur during QCOW2 image operations.
#[derive(Debug, Error)]
pub enum Error {
    // ---- I/O errors with context ----
    /// An I/O operation failed at a specific file offset.
    #[error("I/O error at offset 0x{offset:x} ({context}): {source}")]
    Io {
        /// The underlying I/O error.
        source: std::io::Error,
        /// Byte offset in the image file where the error occurred.
        offset: u64,
        /// Human-readable description of what was being done.
        context: &'static str,
    },

    // ---- Header parsing ----
    /// The file does not start with the QCOW2 magic number.
    #[error("invalid QCOW2 magic: expected 0x{expected:08x}, found 0x{found:08x}")]
    InvalidMagic {
        /// Expected magic value (always `0x514649fb`).
        expected: u32,
        /// Actual value read from the file.
        found: u32,
    },

    /// The QCOW2 version is not supported (only v2 and v3 are valid).
    #[error("unsupported QCOW2 version {version} (supported: 2, 3)")]
    UnsupportedVersion {
        /// The version number found in the header.
        version: u32,
    },

    /// The header data is shorter than required for the detected version.
    #[error("header too short: need {expected} bytes, got {actual}")]
    HeaderTooShort {
        /// Minimum required header length in bytes.
        expected: usize,
        /// Actual length of available data.
        actual: usize,
    },

    /// The cluster_bits field is outside the valid range.
    #[error("invalid cluster_bits {cluster_bits}: must be in [{min}..={max}]")]
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
    #[error("unsupported incompatible features: 0x{features:016x}")]
    UnsupportedIncompatibleFeatures {
        /// Bitmask of the unsupported feature bits.
        features: u64,
    },

    // ---- Table errors ----
    /// An L1 table index is out of bounds.
    #[error("L1 index {index} out of bounds (table size: {table_size})")]
    L1IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual table size.
        table_size: u32,
    },

    /// An L2 table index is out of bounds.
    #[error("L2 index {index} out of bounds (table size: {table_size})")]
    L2IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual table size.
        table_size: u32,
    },

    /// An L2 table was found at a non-cluster-aligned offset.
    #[error("L2 table at offset 0x{offset:x} is not cluster-aligned")]
    L2TableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    // ---- Refcount errors ----
    /// The refcount order exceeds the maximum allowed value.
    #[error("invalid refcount order {order} (max: {max})")]
    InvalidRefcountOrder {
        /// The invalid refcount order.
        order: u32,
        /// Maximum allowed refcount order (6, for 64-bit refcounts).
        max: u32,
    },

    /// A refcount block was found at a non-cluster-aligned offset.
    #[error("refcount block at offset 0x{offset:x} is not cluster-aligned")]
    RefcountBlockMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    /// A refcount block index is out of bounds.
    #[error("refcount index {index} out of bounds (block size: {block_size})")]
    RefcountIndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// The actual block size in entries.
        block_size: u32,
    },

    // ---- Compression ----
    /// Decompression of a compressed cluster failed.
    #[error("decompression failed for cluster at guest offset 0x{guest_offset:x}: {source}")]
    DecompressionFailed {
        /// The underlying decompression error.
        source: std::io::Error,
        /// Guest offset of the cluster being decompressed.
        guest_offset: u64,
    },

    // ---- Backing file ----
    /// The backing file chain exceeds the maximum allowed depth.
    #[error("backing file chain exceeds maximum depth of {max_depth}")]
    BackingChainTooDeep {
        /// The configured maximum depth.
        max_depth: u32,
    },

    /// A backing file referenced by the image could not be found.
    #[error("backing file not found: {path}")]
    BackingFileNotFound {
        /// Path of the missing backing file.
        path: String,
    },

    // ---- Snapshot ----
    /// A snapshot header is truncated (not enough data).
    #[error("snapshot header at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}")]
    SnapshotTruncated {
        /// Byte offset of the snapshot header.
        offset: u64,
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },

    // ---- Header extension ----
    /// A header extension is truncated.
    #[error("header extension at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}")]
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
    #[error("buffer too small: need {expected} bytes, got {actual}")]
    BufferTooSmall {
        /// Required buffer size.
        expected: usize,
        /// Actual buffer size.
        actual: usize,
    },

    /// A guest offset exceeds the virtual disk size.
    #[error("offset 0x{offset:x} exceeds virtual disk size 0x{disk_size:x}")]
    OffsetBeyondDiskSize {
        /// The out-of-bounds offset.
        offset: u64,
        /// The virtual disk size.
        disk_size: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_displays_offset_and_context() {
        let err = Error::Io {
            source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short read"),
            offset: 0x1000,
            context: "reading L2 table",
        };
        let msg = err.to_string();
        assert!(msg.contains("0x1000"), "should contain hex offset: {msg}");
        assert!(msg.contains("reading L2 table"), "should contain context: {msg}");
        assert!(msg.contains("short read"), "should contain source: {msg}");
    }

    #[test]
    fn invalid_magic_displays_both_values() {
        let err = Error::InvalidMagic {
            expected: 0x514649fb,
            found: 0x00000000,
        };
        let msg = err.to_string();
        assert!(msg.contains("514649fb"), "should contain expected: {msg}");
        assert!(msg.contains("00000000"), "should contain found: {msg}");
    }

    #[test]
    fn unsupported_version_displays_version() {
        let err = Error::UnsupportedVersion { version: 4 };
        assert!(err.to_string().contains('4'));
        assert!(err.to_string().contains("2, 3"));
    }

    #[test]
    fn header_too_short_displays_sizes() {
        let err = Error::HeaderTooShort {
            expected: 104,
            actual: 72,
        };
        let msg = err.to_string();
        assert!(msg.contains("104"), "should contain expected: {msg}");
        assert!(msg.contains("72"), "should contain actual: {msg}");
    }

    #[test]
    fn invalid_cluster_bits_displays_range() {
        let err = Error::InvalidClusterBits {
            cluster_bits: 8,
            min: 9,
            max: 21,
        };
        let msg = err.to_string();
        assert!(msg.contains('8'), "should contain value: {msg}");
        assert!(msg.contains('9'), "should contain min: {msg}");
        assert!(msg.contains("21"), "should contain max: {msg}");
    }

    #[test]
    fn l1_index_out_of_bounds_displays_context() {
        let err = Error::L1IndexOutOfBounds {
            index: 100,
            table_size: 50,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"), "should contain index: {msg}");
        assert!(msg.contains("50"), "should contain table_size: {msg}");
    }

    #[test]
    fn offset_beyond_disk_size_displays_hex() {
        let err = Error::OffsetBeyondDiskSize {
            offset: 0x1_0000_0000,
            disk_size: 0x8000_0000,
        };
        let msg = err.to_string();
        assert!(msg.contains("100000000"), "should contain offset: {msg}");
        assert!(msg.contains("80000000"), "should contain disk_size: {msg}");
    }

    #[test]
    fn decompression_failed_displays_guest_offset() {
        let err = Error::DecompressionFailed {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data"),
            guest_offset: 0x2_0000,
        };
        let msg = err.to_string();
        assert!(msg.contains("20000"), "should contain guest offset: {msg}");
        assert!(msg.contains("bad data"), "should contain source: {msg}");
    }
}
