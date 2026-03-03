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

    /// The image uses a compression type that is not supported.
    #[error("unsupported compression type {compression_type} (only deflate/0 is supported)")]
    UnsupportedCompressionType {
        /// The unsupported compression type value from the header.
        compression_type: u8,
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

    /// An L1 table was found at a non-cluster-aligned offset.
    #[error("L1 table at offset 0x{offset:x} is not cluster-aligned")]
    L1TableMisaligned {
        /// The misaligned host offset.
        offset: u64,
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

    /// The backing file chain contains a loop (a file references itself or an ancestor).
    #[error("backing chain loop detected: {path} was already visited")]
    BackingChainLoop {
        /// Path of the file that was visited twice.
        path: String,
    },

    /// Commit was attempted on an image without a backing file.
    #[error("cannot commit: image has no backing file")]
    CommitNoBacking,

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

    // ---- Corruption / hardening ----
    /// A metadata structure in the header references an offset beyond the physical file.
    #[error("metadata offset 0x{offset:x} with size {size} exceeds file size 0x{file_size:x} ({context})")]
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
    #[error("allocation too large: {context} requested {requested} bytes (max: {max})")]
    AllocationTooLarge {
        /// Requested allocation size in bytes.
        requested: u64,
        /// Maximum allowed size in bytes.
        max: u64,
        /// What was being allocated.
        context: &'static str,
    },

    /// An arithmetic overflow occurred while computing metadata sizes or offsets.
    #[error("arithmetic overflow in {context}")]
    ArithmeticOverflow {
        /// Human-readable description of the computation that overflowed.
        context: &'static str,
    },

    // ---- Write errors ----
    /// A write operation was attempted on a read-only image.
    #[error("image is opened read-only")]
    ReadOnly,

    /// The refcount table is full and cannot track additional clusters.
    #[error("refcount table is full (no space for new clusters)")]
    RefcountTableFull,

    /// Incrementing a refcount would exceed the maximum representable value.
    #[error("refcount overflow at cluster offset 0x{cluster_offset:x}: current {current}, max {max}")]
    RefcountOverflow {
        /// Host offset of the cluster.
        cluster_offset: u64,
        /// Current refcount value before the increment.
        current: u64,
        /// Maximum representable refcount value for the configured width.
        max: u64,
    },

    /// Snapshot not found by name or ID.
    #[error("snapshot not found: {identifier}")]
    SnapshotNotFound {
        /// The name or ID that was searched for.
        identifier: String,
    },

    /// Snapshot name must not be empty.
    #[error("snapshot name must not be empty")]
    SnapshotNameEmpty,

    /// A snapshot with this name already exists.
    #[error("snapshot with name {name:?} already exists")]
    SnapshotNameDuplicate {
        /// The duplicate name.
        name: String,
    },

    /// Image creation failed due to an I/O error.
    #[error("failed to create image at {path}: {source}")]
    CreateFailed {
        /// The underlying I/O error.
        source: std::io::Error,
        /// Path where the image was being created.
        path: String,
    },

    /// A write operation failed.
    #[error("write failed at guest offset 0x{guest_offset:x}: {message}")]
    WriteFailed {
        /// Guest offset where the write was attempted.
        guest_offset: u64,
        /// Description of what went wrong.
        message: String,
    },

    // ---- Resize errors ----
    /// Resize target is smaller than the current virtual size.
    #[error("cannot shrink image from {current} to {requested} bytes (shrink not yet supported)")]
    ShrinkNotSupported {
        /// Current virtual size in bytes.
        current: u64,
        /// Requested virtual size in bytes.
        requested: u64,
    },

    /// Resize target is not aligned to the cluster size.
    #[error("resize target {size} is not aligned to cluster size {cluster_size}")]
    ResizeNotAligned {
        /// The unaligned requested size.
        size: u64,
        /// The cluster size that alignment is required to.
        cluster_size: u64,
    },

    // ---- Conversion errors ----
    /// A format conversion operation failed.
    #[error("conversion failed: {message}")]
    ConversionFailed {
        /// Description of what went wrong.
        message: String,
    },

    /// Compression of a cluster produced output that is not smaller than the original.
    #[error("compression ineffective: compressed size {compressed_size} >= cluster size {cluster_size} at guest offset 0x{guest_offset:x}")]
    CompressionTooLarge {
        /// Size of the compressed data in bytes.
        compressed_size: usize,
        /// Cluster size in bytes.
        cluster_size: usize,
        /// Guest offset of the cluster.
        guest_offset: u64,
    },

    // ---- Repair / shrink errors ----
    /// Shrinking would cause data loss because allocated clusters exist beyond the new boundary.
    #[error("shrink would lose data: cluster at offset 0x{cluster_offset:x} is still allocated ({context})")]
    ShrinkDataLoss {
        /// Host offset of the allocated cluster beyond the boundary.
        cluster_offset: u64,
        /// Which structure references this cluster.
        context: &'static str,
    },

    /// A repair operation failed.
    #[error("repair failed: {message}")]
    RepairFailed {
        /// Description of what went wrong.
        message: String,
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
            cluster_bits: 42,
            min: 100,
            max: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("42"), "should contain value: {msg}");
        assert!(msg.contains("100"), "should contain min: {msg}");
        assert!(msg.contains("200"), "should contain max: {msg}");
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

    #[test]
    fn refcount_block_misaligned_displays_offset() {
        let err = Error::RefcountBlockMisaligned { offset: 0x1_0001 };
        let msg = err.to_string();
        assert!(msg.contains("10001"), "should contain hex offset: {msg}");
        assert!(
            msg.contains("not cluster-aligned"),
            "should mention alignment: {msg}"
        );
    }

    #[test]
    fn backing_chain_too_deep_displays_depth() {
        let err = Error::BackingChainTooDeep { max_depth: 16 };
        let msg = err.to_string();
        assert!(msg.contains("16"), "should contain max_depth: {msg}");
        assert!(
            msg.contains("exceeds maximum depth"),
            "should mention depth limit: {msg}"
        );
    }

    #[test]
    fn l2_table_misaligned_displays_offset() {
        let err = Error::L2TableMisaligned { offset: 0x3_0001 };
        let msg = err.to_string();
        assert!(msg.contains("30001"), "should contain hex offset: {msg}");
        assert!(
            msg.contains("not cluster-aligned"),
            "should mention alignment: {msg}"
        );
    }

    #[test]
    fn l2_index_out_of_bounds_displays_context() {
        let err = Error::L2IndexOutOfBounds {
            index: 512,
            table_size: 256,
        };
        let msg = err.to_string();
        assert!(msg.contains("512"), "should contain index: {msg}");
        assert!(msg.contains("256"), "should contain table_size: {msg}");
    }

    #[test]
    fn unsupported_incompatible_features_displays_hex() {
        let err = Error::UnsupportedIncompatibleFeatures { features: 0xFF };
        let msg = err.to_string();
        assert!(
            msg.contains("00000000000000ff"),
            "should contain hex features: {msg}"
        );
    }

    #[test]
    fn unsupported_compression_type_displays_value() {
        let err = Error::UnsupportedCompressionType {
            compression_type: 99,
        };
        let msg = err.to_string();
        assert!(msg.contains("99"), "should contain type value: {msg}");
        assert!(msg.contains("deflate"), "should mention deflate: {msg}");
    }

    #[test]
    fn invalid_refcount_order_displays_values() {
        let err = Error::InvalidRefcountOrder { order: 42, max: 33 };
        let msg = err.to_string();
        assert!(msg.contains("42"), "should contain order: {msg}");
        assert!(msg.contains("33"), "should contain max: {msg}");
    }

    #[test]
    fn refcount_index_out_of_bounds_displays_context() {
        let err = Error::RefcountIndexOutOfBounds {
            index: 1000,
            block_size: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("1000"), "should contain index: {msg}");
        assert!(msg.contains("512"), "should contain block_size: {msg}");
    }

    #[test]
    fn backing_chain_loop_displays_path() {
        let err = Error::BackingChainLoop {
            path: "/images/a.qcow2".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/images/a.qcow2"),
            "should contain path: {msg}"
        );
        assert!(msg.contains("loop"), "should mention loop: {msg}");
    }

    #[test]
    fn commit_no_backing_displays_message() {
        let err = Error::CommitNoBacking;
        let msg = err.to_string();
        assert!(msg.contains("no backing"), "should mention no backing: {msg}");
    }

    #[test]
    fn backing_file_not_found_displays_path() {
        let err = Error::BackingFileNotFound {
            path: "/var/lib/images/base.qcow2".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/var/lib/images/base.qcow2"),
            "should contain path: {msg}"
        );
    }

    #[test]
    fn snapshot_truncated_displays_context() {
        let err = Error::SnapshotTruncated {
            offset: 0x5000,
            expected: 64,
            actual: 32,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000"), "should contain hex offset: {msg}");
        assert!(msg.contains("64"), "should contain expected: {msg}");
        assert!(msg.contains("32"), "should contain actual: {msg}");
    }

    #[test]
    fn extension_truncated_displays_context() {
        let err = Error::ExtensionTruncated {
            offset: 0x1234,
            expected: 256,
            actual: 37,
        };
        let msg = err.to_string();
        assert!(msg.contains("1234"), "should contain hex offset: {msg}");
        assert!(msg.contains("256"), "should contain expected: {msg}");
        assert!(msg.contains("37"), "should contain actual: {msg}");
    }

    #[test]
    fn buffer_too_small_displays_sizes() {
        let err = Error::BufferTooSmall {
            expected: 1024,
            actual: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("1024"), "should contain expected: {msg}");
        assert!(msg.contains("512"), "should contain actual: {msg}");
    }

    #[test]
    fn metadata_offset_beyond_eof_displays_context() {
        let err = Error::MetadataOffsetBeyondEof {
            offset: 0x10_0000,
            size: 0x1_0000,
            file_size: 0x8_0000,
            context: "L1 table",
        };
        let msg = err.to_string();
        assert!(msg.contains("100000"), "should contain offset: {msg}");
        assert!(msg.contains("65536"), "should contain size: {msg}");
        assert!(msg.contains("80000"), "should contain file_size: {msg}");
        assert!(msg.contains("L1 table"), "should contain context: {msg}");
    }

    #[test]
    fn allocation_too_large_displays_context() {
        let err = Error::AllocationTooLarge {
            requested: 0x1_0000_0000,
            max: 0x1000_0000,
            context: "L1 table buffer",
        };
        let msg = err.to_string();
        assert!(
            msg.contains("L1 table buffer"),
            "should contain context: {msg}"
        );
        assert!(
            msg.contains("4294967296"),
            "should contain requested: {msg}"
        );
    }

    #[test]
    fn arithmetic_overflow_displays_context() {
        let err = Error::ArithmeticOverflow {
            context: "l1_table_entries * L1_ENTRY_SIZE",
        };
        let msg = err.to_string();
        assert!(
            msg.contains("l1_table_entries * L1_ENTRY_SIZE"),
            "should contain context: {msg}"
        );
    }

    #[test]
    fn read_only_displays_message() {
        let err = Error::ReadOnly;
        let msg = err.to_string();
        assert!(msg.contains("read-only"), "should mention read-only: {msg}");
    }

    #[test]
    fn refcount_table_full_displays_message() {
        let err = Error::RefcountTableFull;
        let msg = err.to_string();
        assert!(
            msg.contains("refcount table is full"),
            "should mention full table: {msg}"
        );
    }

    #[test]
    fn refcount_overflow_displays_context() {
        let err = Error::RefcountOverflow {
            cluster_offset: 0x5_0000,
            current: 65535,
            max: 65535,
        };
        let msg = err.to_string();
        assert!(msg.contains("50000"), "should contain hex offset: {msg}");
        assert!(msg.contains("65535"), "should contain current value: {msg}");
    }

    #[test]
    fn snapshot_not_found_displays_identifier() {
        let err = Error::SnapshotNotFound {
            identifier: "my-snap".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-snap"), "should contain identifier: {msg}");
    }

    #[test]
    fn snapshot_name_empty_displays_message() {
        let err = Error::SnapshotNameEmpty;
        let msg = err.to_string();
        assert!(msg.contains("empty"), "should mention empty: {msg}");
    }

    #[test]
    fn snapshot_name_duplicate_displays_name() {
        let err = Error::SnapshotNameDuplicate {
            name: "backup-1".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("backup-1"), "should contain name: {msg}");
        assert!(msg.contains("already exists"), "should mention duplicate: {msg}");
    }

    #[test]
    fn create_failed_displays_path_and_source() {
        let err = Error::CreateFailed {
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"),
            path: "/tmp/test.qcow2".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/test.qcow2"),
            "should contain path: {msg}"
        );
        assert!(
            msg.contains("access denied"),
            "should contain source: {msg}"
        );
    }

    #[test]
    fn write_failed_displays_offset_and_message() {
        let err = Error::WriteFailed {
            guest_offset: 0x10_0000,
            message: "L2 table allocation failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("100000"), "should contain hex offset: {msg}");
        assert!(
            msg.contains("L2 table allocation failed"),
            "should contain message: {msg}"
        );
    }

    #[test]
    fn shrink_not_supported_displays_sizes() {
        let err = Error::ShrinkNotSupported {
            current: 1073741824,
            requested: 536870912,
        };
        let msg = err.to_string();
        assert!(msg.contains("1073741824"), "should contain current: {msg}");
        assert!(msg.contains("536870912"), "should contain requested: {msg}");
        assert!(msg.contains("shrink"), "should mention shrink: {msg}");
    }

    #[test]
    fn resize_not_aligned_displays_sizes() {
        let err = Error::ResizeNotAligned {
            size: 1000,
            cluster_size: 65536,
        };
        let msg = err.to_string();
        assert!(msg.contains("1000"), "should contain size: {msg}");
        assert!(msg.contains("65536"), "should contain cluster_size: {msg}");
        assert!(msg.contains("not aligned"), "should mention alignment: {msg}");
    }

    #[test]
    fn conversion_failed_displays_message() {
        let err = Error::ConversionFailed {
            message: "unsupported source format".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported source format"),
            "should contain message: {msg}"
        );
    }

    #[test]
    fn compression_too_large_displays_context() {
        let err = Error::CompressionTooLarge {
            compressed_size: 70000,
            cluster_size: 65536,
            guest_offset: 0x10_0000,
        };
        let msg = err.to_string();
        assert!(msg.contains("70000"), "should contain compressed_size: {msg}");
        assert!(msg.contains("65536"), "should contain cluster_size: {msg}");
        assert!(msg.contains("100000"), "should contain hex offset: {msg}");
    }

    #[test]
    fn shrink_data_loss_displays_context() {
        let err = Error::ShrinkDataLoss {
            cluster_offset: 0x5_0000,
            context: "active L2 entry",
        };
        let msg = err.to_string();
        assert!(msg.contains("50000"), "should contain hex offset: {msg}");
        assert!(
            msg.contains("active L2 entry"),
            "should contain context: {msg}"
        );
        assert!(msg.contains("shrink"), "should mention shrink: {msg}");
    }

    #[test]
    fn repair_failed_displays_message() {
        let err = Error::RepairFailed {
            message: "refcount table corrupted beyond repair".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("refcount table corrupted beyond repair"),
            "should contain message: {msg}"
        );
        assert!(msg.contains("repair failed"), "should mention repair: {msg}");
    }
}
