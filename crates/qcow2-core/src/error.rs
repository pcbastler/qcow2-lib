//! Unified error types for the qcow2-core crate.
//!
//! Every error variant carries context about WHERE the error occurred
//! (byte offset, table index, cluster number) to enable meaningful diagnostics.
//!
//! Format-level errors (parsing/encoding on-disk structures) are defined in
//! [`qcow2_format::Error`] and wrapped here as [`Error::Format`].
//!
//! This module is `no_std`-compatible. Instead of wrapping `std::io::Error`,
//! I/O failures are represented by [`IoErrorKind`], a lightweight enum that
//! can be converted to/from `std::io::ErrorKind` by the `qcow2` userspace crate.

extern crate alloc;

use alloc::string::String;
use core::fmt;

/// Re-export the format-level error type.
pub use qcow2_format::Error as FormatError;

/// Alias for `core::result::Result` with [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Lightweight I/O error classification for `no_std` environments.
///
/// Maps 1:1 to the commonly used `std::io::ErrorKind` variants, enabling
/// lossless round-tripping in userspace while remaining available in
/// contexts without the standard library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoErrorKind {
    /// An operation could not be completed because an "end of file" was
    /// reached prematurely.
    UnexpectedEof,
    /// The operation lacked the necessary privileges.
    PermissionDenied,
    /// A parameter was incorrect.
    InvalidInput,
    /// The data was not valid for the intended purpose.
    InvalidData,
    /// A write operation returned `Ok(0)`.
    WriteZero,
    /// An entity was not found.
    NotFound,
    /// An I/O error not covered by the other variants.
    Other,
}

impl fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of file"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::WriteZero => write!(f, "write zero"),
            Self::NotFound => write!(f, "not found"),
            Self::Other => write!(f, "I/O error"),
        }
    }
}

/// All errors that can occur during QCOW2 image operations.
#[derive(Debug)]
pub enum Error {
    // ---- Format errors (parsing/encoding) ----

    /// An error from parsing or encoding on-disk format structures.
    Format(qcow2_format::Error),

    // ---- I/O errors with context ----

    /// An I/O operation failed at a specific file offset.
    Io {
        /// The kind of I/O error that occurred.
        kind: IoErrorKind,
        /// Optional message with additional detail.
        message: String,
        /// Byte offset in the image file where the error occurred.
        offset: u64,
        /// Human-readable description of what was being done.
        context: &'static str,
    },

    // ---- Table errors (engine-level) ----

    /// An L2 table was found at a non-cluster-aligned offset.
    L2TableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    // ---- Compression ----

    /// Decompression of a compressed cluster failed.
    DecompressionFailed {
        /// The kind of error that occurred.
        kind: IoErrorKind,
        /// Description of the failure.
        message: String,
        /// Guest offset of the cluster being decompressed.
        guest_offset: u64,
    },

    // ---- Backing file ----

    /// The backing file chain exceeds the maximum allowed depth.
    BackingChainTooDeep {
        /// The configured maximum depth.
        max_depth: u32,
    },

    /// A backing file referenced by the image could not be found.
    BackingFileNotFound {
        /// Path of the missing backing file.
        path: String,
    },

    /// The backing file chain contains a loop.
    BackingChainLoop {
        /// Path of the file that was visited twice.
        path: String,
    },

    /// Commit was attempted on an image without a backing file.
    CommitNoBacking,

    // ---- Data integrity ----

    /// The virtual_size is invalid (e.g. zero).
    InvalidVirtualSize {
        /// The invalid virtual size.
        size: u64,
    },

    /// A guest offset exceeds the virtual disk size.
    OffsetBeyondDiskSize {
        /// The out-of-bounds offset.
        offset: u64,
        /// The virtual disk size.
        disk_size: u64,
    },

    // ---- Write errors ----

    /// A write operation was attempted on a read-only image.
    ReadOnly,

    /// A write operation requires a refcount manager, but none was loaded.
    NoRefcountManager,

    /// A metadata cache entry was not found immediately after insertion.
    CacheInconsistency {
        /// The offset of the missing cache entry.
        offset: u64,
    },

    /// The refcount table is full and cannot track additional clusters.
    RefcountTableFull,

    /// Incrementing a refcount would exceed the maximum representable value.
    RefcountOverflow {
        /// Host offset of the cluster.
        cluster_offset: u64,
        /// Current refcount value before the increment.
        current: u64,
        /// Maximum representable refcount value for the configured width.
        max: u64,
    },

    /// Snapshot not found by name or ID.
    SnapshotNotFound {
        /// The name or ID that was searched for.
        identifier: String,
    },

    /// Snapshot name must not be empty.
    SnapshotNameEmpty,

    /// A snapshot with this name already exists.
    SnapshotNameDuplicate {
        /// The duplicate name.
        name: String,
    },

    /// Image creation failed.
    CreateFailed {
        /// Description of the failure.
        message: String,
        /// Path where the image was being created.
        path: String,
    },

    /// A write operation failed.
    WriteFailed {
        /// Guest offset where the write was attempted.
        guest_offset: u64,
        /// Description of what went wrong.
        message: String,
    },

    // ---- Resize errors ----

    /// Resize target is smaller than the current virtual size.
    ShrinkNotSupported {
        /// Current virtual size in bytes.
        current: u64,
        /// Requested virtual size in bytes.
        requested: u64,
    },

    /// Resize target is not aligned to the cluster size.
    ResizeNotAligned {
        /// The unaligned requested size.
        size: u64,
        /// The cluster size that alignment is required to.
        cluster_size: u64,
    },

    // ---- Conversion errors ----

    /// A format conversion operation failed.
    ConversionFailed {
        /// Description of what went wrong.
        message: String,
    },

    /// Compression produced output not smaller than the original.
    CompressionTooLarge {
        /// Size of the compressed data in bytes.
        compressed_size: usize,
        /// Cluster size in bytes.
        cluster_size: usize,
        /// Guest offset of the cluster.
        guest_offset: u64,
    },

    // ---- Repair / shrink errors ----

    /// Shrinking would cause data loss.
    ShrinkDataLoss {
        /// Host offset of the allocated cluster beyond the boundary.
        cluster_offset: u64,
        /// Which structure references this cluster.
        context: &'static str,
    },

    /// A repair operation failed.
    RepairFailed {
        /// Description of what went wrong.
        message: String,
    },

    // ---- Bitmap errors (engine-level) ----

    /// A bitmap with this name was not found.
    BitmapNotFound {
        /// The bitmap name that was searched for.
        name: String,
    },

    /// A bitmap with this name already exists.
    BitmapNameDuplicate {
        /// The duplicate name.
        name: String,
    },

    /// Bitmap name must not be empty.
    BitmapNameEmpty,

    /// A bitmap table was found at a non-cluster-aligned offset.
    BitmapTableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    // ---- Extended L2 errors (engine-level) ----

    /// A subcluster bitmap has an invalid state.
    InvalidSubclusterBitmap {
        /// L2 table index of the entry.
        l2_index: u32,
        /// Subcluster index with the invalid state.
        subcluster_index: u32,
    },

    // ---- External data file errors ----

    /// The external data file could not be opened.
    ExternalDataFileOpen {
        /// Description of the failure.
        message: String,
        /// Path of the external data file.
        path: String,
    },

    /// Compressed clusters are not supported with external data files.
    CompressedWithExternalData,

    /// Image has EXTERNAL_DATA_FILE flag but no data file path.
    MissingExternalDataFilePath,

    /// Only raw external data files are supported.
    RawExternalRequired,

    // ---- Encryption errors ----

    /// Decryption of a cluster failed.
    DecryptionFailed {
        /// Guest offset of the cluster being decrypted.
        guest_offset: u64,
        /// Description of the error.
        message: String,
    },

    /// Encryption of a cluster failed.
    EncryptionFailed {
        /// Guest offset of the cluster being encrypted.
        guest_offset: u64,
        /// Description of the error.
        message: String,
    },

    /// The LUKS header in the image is invalid or corrupted.
    InvalidLuksHeader {
        /// Description of what is wrong.
        message: String,
    },

    /// The cipher or cipher mode is not supported.
    UnsupportedCipher {
        /// Cipher algorithm name (e.g., "aes").
        cipher_name: String,
        /// Cipher mode (e.g., "xts-plain64").
        cipher_mode: String,
    },

    /// Key derivation failed (PBKDF2 or Argon2).
    KeyDerivationFailed {
        /// Description of the error.
        message: String,
    },

    /// The provided password did not unlock any key slot.
    WrongPassword,

    /// An encrypted image was opened without providing a password.
    NoPasswordProvided,

    /// An encryption operation was attempted on a non-encrypted image.
    NotEncrypted,

    /// Encryption and compression are mutually exclusive in QCOW2.
    EncryptionWithCompression,

    /// All LUKS key slots are full.
    LuksKeySlotsFull,

    // ---- BLAKE3 hash errors (engine-level) ----

    /// A hash table was found at a non-cluster-aligned offset.
    HashTableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    /// Header extensions exceed the available space in cluster 0.
    HeaderExtensionOverflow {
        /// Total bytes needed (header length + serialized extensions).
        needed: usize,
        /// Cluster size (maximum available space).
        cluster_size: u64,
    },

    /// Hash operations require an initialized hash extension.
    HashNotInitialized,

    /// Hash verification detected a mismatch.
    HashVerifyFailed {
        /// Hash chunk index where the mismatch was found.
        hash_chunk_index: u64,
        /// Guest byte offset of the hash chunk.
        guest_offset: u64,
        /// Expected hash (hex string).
        expected: String,
        /// Actual computed hash (hex string).
        actual: String,
    },

    // ---- Block writer errors ----

    /// A write was attempted to a guest cluster that was already flushed to disk.
    ClusterAlreadyFlushed {
        /// Guest offset of the cluster.
        guest_offset: u64,
        /// Host offset where the cluster was written.
        host_offset: u64,
    },

    /// A read was attempted for a cluster that was already flushed from the buffer.
    ClusterNotInBuffer {
        /// Guest offset of the cluster.
        guest_offset: u64,
    },

    /// The block writer memory limit was exceeded and no blocks could be evicted.
    BlockWriterMemoryExceeded {
        /// Current memory usage in bytes.
        current: u64,
        /// Configured limit in bytes.
        limit: u64,
    },

    /// The block writer has already been finalized; no further writes are allowed.
    BlockWriterFinalized,
}

impl From<qcow2_format::Error> for Error {
    fn from(e: qcow2_format::Error) -> Self {
        Error::Format(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(e) => write!(f, "{e}"),
            Self::Io { kind, message, offset, context } => {
                write!(f, "I/O error at offset 0x{offset:x} ({context}): {kind}")?;
                if !message.is_empty() {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            _ => self.fmt_engine_error(f),
        }
    }
}

impl Error {
    fn fmt_engine_error(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(_) | Self::Io { .. } => unreachable!(),
            Self::L2TableMisaligned { offset } =>
                write!(f, "L2 table at offset 0x{offset:x} is not cluster-aligned"),
            Self::DecompressionFailed { kind, message, guest_offset } =>
                write!(f, "decompression failed for cluster at guest offset 0x{guest_offset:x}: {kind}: {message}"),
            Self::BackingChainTooDeep { max_depth } =>
                write!(f, "backing file chain exceeds maximum depth of {max_depth}"),
            Self::BackingFileNotFound { path } =>
                write!(f, "backing file not found: {path}"),
            Self::BackingChainLoop { path } =>
                write!(f, "backing chain loop detected: {path} was already visited"),
            Self::CommitNoBacking =>
                write!(f, "cannot commit: image has no backing file"),
            Self::InvalidVirtualSize { size } =>
                write!(f, "invalid virtual_size {size}: must be greater than 0"),
            Self::OffsetBeyondDiskSize { offset, disk_size } =>
                write!(f, "offset 0x{offset:x} exceeds virtual disk size 0x{disk_size:x}"),
            Self::ReadOnly => write!(f, "image is opened read-only"),
            Self::NoRefcountManager => write!(f, "no refcount manager loaded — image was not opened with write support"),
            Self::CacheInconsistency { offset } => write!(f, "metadata cache inconsistency: entry missing after insertion at offset 0x{offset:x}"),
            Self::RefcountTableFull =>
                write!(f, "refcount table is full (no space for new clusters)"),
            Self::RefcountOverflow { cluster_offset, current, max } =>
                write!(f, "refcount overflow at cluster offset 0x{cluster_offset:x}: current {current}, max {max}"),
            Self::SnapshotNotFound { identifier } =>
                write!(f, "snapshot not found: {identifier}"),
            Self::SnapshotNameEmpty => write!(f, "snapshot name must not be empty"),
            Self::SnapshotNameDuplicate { name } =>
                write!(f, "snapshot with name {name:?} already exists"),
            Self::CreateFailed { message, path } =>
                write!(f, "failed to create image at {path}: {message}"),
            Self::WriteFailed { guest_offset, message } =>
                write!(f, "write failed at guest offset 0x{guest_offset:x}: {message}"),
            Self::ShrinkNotSupported { current, requested } =>
                write!(f, "cannot shrink image from {current} to {requested} bytes (shrink not yet supported)"),
            Self::ResizeNotAligned { size, cluster_size } =>
                write!(f, "resize target {size} is not aligned to cluster size {cluster_size}"),
            Self::ConversionFailed { message } => write!(f, "conversion failed: {message}"),
            _ => self.fmt_extended_error(f),
        }
    }

    fn fmt_extended_error(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompressionTooLarge { compressed_size, cluster_size, guest_offset } =>
                write!(f, "compression ineffective: compressed size {compressed_size} >= cluster size {cluster_size} at guest offset 0x{guest_offset:x}"),
            Self::ShrinkDataLoss { cluster_offset, context } =>
                write!(f, "shrink would lose data: cluster at offset 0x{cluster_offset:x} is still allocated ({context})"),
            Self::RepairFailed { message } => write!(f, "repair failed: {message}"),
            Self::BitmapNotFound { name } => write!(f, "bitmap not found: {name}"),
            Self::BitmapNameDuplicate { name } =>
                write!(f, "bitmap with name {name:?} already exists"),
            Self::BitmapNameEmpty => write!(f, "bitmap name must not be empty"),
            Self::BitmapTableMisaligned { offset } =>
                write!(f, "bitmap table at offset 0x{offset:x} is not cluster-aligned"),
            Self::InvalidSubclusterBitmap { l2_index, subcluster_index } =>
                write!(f, "invalid subcluster bitmap at L2 index {l2_index}: subcluster {subcluster_index} has both alloc and zero bits set"),
            Self::ExternalDataFileOpen { message, path } =>
                write!(f, "failed to open external data file '{path}': {message}"),
            Self::CompressedWithExternalData =>
                write!(f, "compressed clusters are not supported with external data files"),
            Self::MissingExternalDataFilePath =>
                write!(f, "image has EXTERNAL_DATA_FILE flag but no data file path in header extensions"),
            Self::RawExternalRequired =>
                write!(f, "only raw external data files are supported (RAW_EXTERNAL autoclear bit required)"),
            Self::DecryptionFailed { guest_offset, message } =>
                write!(f, "decryption failed for cluster at guest offset 0x{guest_offset:x}: {message}"),
            Self::EncryptionFailed { guest_offset, message } =>
                write!(f, "encryption failed for cluster at guest offset 0x{guest_offset:x}: {message}"),
            Self::InvalidLuksHeader { message } => write!(f, "invalid LUKS header: {message}"),
            Self::UnsupportedCipher { cipher_name, cipher_mode } =>
                write!(f, "unsupported cipher: {cipher_name}-{cipher_mode}"),
            Self::KeyDerivationFailed { message } =>
                write!(f, "key derivation failed: {message}"),
            Self::WrongPassword => write!(f, "wrong password: no key slot could be unlocked"),
            Self::NoPasswordProvided =>
                write!(f, "image is encrypted but no password was provided"),
            Self::NotEncrypted =>
                write!(f, "encryption operation attempted on non-encrypted image"),
            Self::EncryptionWithCompression =>
                write!(f, "encryption and compression are mutually exclusive"),
            Self::LuksKeySlotsFull => write!(f, "all LUKS key slots are full"),
            Self::HashTableMisaligned { offset } =>
                write!(f, "hash table at offset 0x{offset:x} is not cluster-aligned"),
            Self::HeaderExtensionOverflow { needed, cluster_size } =>
                write!(f, "header extensions ({needed} bytes) exceed cluster 0 ({cluster_size} bytes)"),
            Self::HashNotInitialized => write!(f, "hash extension not initialized"),
            Self::HashVerifyFailed { hash_chunk_index, guest_offset, expected, actual } =>
                write!(f, "hash mismatch at hash chunk {hash_chunk_index} (0x{guest_offset:x}): expected {expected}, actual {actual}"),
            Self::ClusterAlreadyFlushed { guest_offset, host_offset } =>
                write!(f, "guest cluster at offset 0x{guest_offset:x} was already flushed to host offset 0x{host_offset:x}"),
            Self::ClusterNotInBuffer { guest_offset } =>
                write!(f, "guest cluster at offset 0x{guest_offset:x} is not in the write buffer (already flushed)"),
            Self::BlockWriterMemoryExceeded { current, limit } =>
                write!(f, "block writer memory limit exceeded: {current} bytes used, limit is {limit} bytes"),
            Self::BlockWriterFinalized =>
                write!(f, "block writer has already been finalized; no further writes are allowed"),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // ---- IoErrorKind Display ----

    #[test]
    fn io_error_kind_display() {
        assert_eq!(IoErrorKind::UnexpectedEof.to_string(), "unexpected end of file");
        assert_eq!(IoErrorKind::PermissionDenied.to_string(), "permission denied");
        assert_eq!(IoErrorKind::InvalidInput.to_string(), "invalid input");
        assert_eq!(IoErrorKind::InvalidData.to_string(), "invalid data");
        assert_eq!(IoErrorKind::WriteZero.to_string(), "write zero");
        assert_eq!(IoErrorKind::NotFound.to_string(), "not found");
        assert_eq!(IoErrorKind::Other.to_string(), "I/O error");
    }

    // ---- Error::Format ----

    #[test]
    fn display_format_delegates_to_inner() {
        let inner = FormatError::InvalidMagic {
            found: 0xDEADBEEF,
            expected: 0x514649fb,
        };
        let expected = inner.to_string();
        let err = Error::Format(inner);
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn from_format_error() {
        let inner = FormatError::InvalidMagic {
            found: 0xDEADBEEF,
            expected: 0x514649fb,
        };
        let expected_msg = inner.to_string();
        let err: Error = inner.into();
        assert!(matches!(err, Error::Format(_)));
        assert_eq!(err.to_string(), expected_msg);
    }

    // ---- Error::Io ----

    #[test]
    fn display_io_with_message() {
        let err = Error::Io {
            kind: IoErrorKind::NotFound,
            message: String::from("file missing"),
            offset: 0x1000,
            context: "reading L1 table",
        };
        assert_eq!(
            err.to_string(),
            "I/O error at offset 0x1000 (reading L1 table): not found: file missing"
        );
    }

    #[test]
    fn display_io_empty_message() {
        let err = Error::Io {
            kind: IoErrorKind::UnexpectedEof,
            message: String::new(),
            offset: 0x0,
            context: "reading header",
        };
        assert_eq!(
            err.to_string(),
            "I/O error at offset 0x0 (reading header): unexpected end of file"
        );
        // Must NOT end with a trailing ": "
        assert!(!err.to_string().ends_with(": "));
    }

    #[test]
    fn display_io_max_offset() {
        let err = Error::Io {
            kind: IoErrorKind::Other,
            message: String::from("disk full"),
            offset: u64::MAX,
            context: "write",
        };
        assert_eq!(
            err.to_string(),
            "I/O error at offset 0xffffffffffffffff (write): I/O error: disk full"
        );
    }

    // ---- Table errors ----

    #[test]
    fn display_l2_table_misaligned() {
        let err = Error::L2TableMisaligned { offset: 0x1234 };
        assert_eq!(
            err.to_string(),
            "L2 table at offset 0x1234 is not cluster-aligned"
        );
    }

    #[test]
    fn display_l2_table_misaligned_zero() {
        let err = Error::L2TableMisaligned { offset: 0 };
        assert_eq!(
            err.to_string(),
            "L2 table at offset 0x0 is not cluster-aligned"
        );
    }

    // ---- Compression ----

    #[test]
    fn display_decompression_failed() {
        let err = Error::DecompressionFailed {
            kind: IoErrorKind::InvalidData,
            message: String::from("zlib stream corrupt"),
            guest_offset: 0x20000,
        };
        assert_eq!(
            err.to_string(),
            "decompression failed for cluster at guest offset 0x20000: invalid data: zlib stream corrupt"
        );
    }

    // ---- Backing file ----

    #[test]
    fn display_backing_chain_too_deep() {
        let err = Error::BackingChainTooDeep { max_depth: 16 };
        assert_eq!(
            err.to_string(),
            "backing file chain exceeds maximum depth of 16"
        );
    }

    #[test]
    fn display_backing_file_not_found() {
        let err = Error::BackingFileNotFound {
            path: String::from("/tmp/base.qcow2"),
        };
        assert_eq!(
            err.to_string(),
            "backing file not found: /tmp/base.qcow2"
        );
    }

    #[test]
    fn display_backing_chain_loop() {
        let err = Error::BackingChainLoop {
            path: String::from("loop.qcow2"),
        };
        assert_eq!(
            err.to_string(),
            "backing chain loop detected: loop.qcow2 was already visited"
        );
    }

    #[test]
    fn display_commit_no_backing() {
        assert_eq!(
            Error::CommitNoBacking.to_string(),
            "cannot commit: image has no backing file"
        );
    }

    // ---- Data integrity ----

    #[test]
    fn display_invalid_virtual_size() {
        let err = Error::InvalidVirtualSize { size: 0 };
        assert_eq!(
            err.to_string(),
            "invalid virtual_size 0: must be greater than 0"
        );
    }

    #[test]
    fn display_offset_beyond_disk_size() {
        let err = Error::OffsetBeyondDiskSize {
            offset: 0x100000,
            disk_size: 0x80000,
        };
        assert_eq!(
            err.to_string(),
            "offset 0x100000 exceeds virtual disk size 0x80000"
        );
    }

    // ---- Write errors ----

    #[test]
    fn display_read_only() {
        assert_eq!(Error::ReadOnly.to_string(), "image is opened read-only");
    }

    #[test]
    fn display_refcount_table_full() {
        assert_eq!(
            Error::RefcountTableFull.to_string(),
            "refcount table is full (no space for new clusters)"
        );
    }

    #[test]
    fn display_refcount_overflow() {
        let err = Error::RefcountOverflow {
            cluster_offset: 0x30000,
            current: 65535,
            max: 65535,
        };
        assert_eq!(
            err.to_string(),
            "refcount overflow at cluster offset 0x30000: current 65535, max 65535"
        );
    }

    #[test]
    fn display_snapshot_not_found() {
        let err = Error::SnapshotNotFound {
            identifier: String::from("snap1"),
        };
        assert_eq!(err.to_string(), "snapshot not found: snap1");
    }

    #[test]
    fn display_snapshot_name_empty() {
        assert_eq!(
            Error::SnapshotNameEmpty.to_string(),
            "snapshot name must not be empty"
        );
    }

    #[test]
    fn display_snapshot_name_duplicate() {
        let err = Error::SnapshotNameDuplicate {
            name: String::from("backup"),
        };
        assert_eq!(
            err.to_string(),
            "snapshot with name \"backup\" already exists"
        );
    }

    #[test]
    fn display_create_failed() {
        let err = Error::CreateFailed {
            message: String::from("permission denied"),
            path: String::from("/root/disk.qcow2"),
        };
        assert_eq!(
            err.to_string(),
            "failed to create image at /root/disk.qcow2: permission denied"
        );
    }

    #[test]
    fn display_write_failed() {
        let err = Error::WriteFailed {
            guest_offset: 0x40000,
            message: String::from("backend error"),
        };
        assert_eq!(
            err.to_string(),
            "write failed at guest offset 0x40000: backend error"
        );
    }

    // ---- Resize ----

    #[test]
    fn display_shrink_not_supported() {
        let err = Error::ShrinkNotSupported {
            current: 1048576,
            requested: 524288,
        };
        assert_eq!(
            err.to_string(),
            "cannot shrink image from 1048576 to 524288 bytes (shrink not yet supported)"
        );
    }

    #[test]
    fn display_resize_not_aligned() {
        let err = Error::ResizeNotAligned {
            size: 100000,
            cluster_size: 65536,
        };
        assert_eq!(
            err.to_string(),
            "resize target 100000 is not aligned to cluster size 65536"
        );
    }

    // ---- Conversion ----

    #[test]
    fn display_conversion_failed() {
        let err = Error::ConversionFailed {
            message: String::from("unsupported format"),
        };
        assert_eq!(err.to_string(), "conversion failed: unsupported format");
    }

    #[test]
    fn display_compression_too_large() {
        let err = Error::CompressionTooLarge {
            compressed_size: 70000,
            cluster_size: 65536,
            guest_offset: 0x10000,
        };
        assert_eq!(
            err.to_string(),
            "compression ineffective: compressed size 70000 >= cluster size 65536 at guest offset 0x10000"
        );
    }

    // ---- Repair / shrink ----

    #[test]
    fn display_shrink_data_loss() {
        let err = Error::ShrinkDataLoss {
            cluster_offset: 0x500000,
            context: "L2 table",
        };
        assert_eq!(
            err.to_string(),
            "shrink would lose data: cluster at offset 0x500000 is still allocated (L2 table)"
        );
    }

    #[test]
    fn display_repair_failed() {
        let err = Error::RepairFailed {
            message: String::from("corrupted refcount"),
        };
        assert_eq!(err.to_string(), "repair failed: corrupted refcount");
    }

    // ---- Bitmap ----

    #[test]
    fn display_bitmap_not_found() {
        let err = Error::BitmapNotFound {
            name: String::from("dirty"),
        };
        assert_eq!(err.to_string(), "bitmap not found: dirty");
    }

    #[test]
    fn display_bitmap_name_duplicate() {
        let err = Error::BitmapNameDuplicate {
            name: String::from("dirty"),
        };
        assert_eq!(
            err.to_string(),
            "bitmap with name \"dirty\" already exists"
        );
    }

    #[test]
    fn display_bitmap_name_empty() {
        assert_eq!(
            Error::BitmapNameEmpty.to_string(),
            "bitmap name must not be empty"
        );
    }

    #[test]
    fn display_bitmap_table_misaligned() {
        let err = Error::BitmapTableMisaligned { offset: 0xABC };
        assert_eq!(
            err.to_string(),
            "bitmap table at offset 0xabc is not cluster-aligned"
        );
    }

    // ---- Extended L2 ----

    #[test]
    fn display_invalid_subcluster_bitmap() {
        let err = Error::InvalidSubclusterBitmap {
            l2_index: 42,
            subcluster_index: 7,
        };
        assert_eq!(
            err.to_string(),
            "invalid subcluster bitmap at L2 index 42: subcluster 7 has both alloc and zero bits set"
        );
    }

    // ---- External data file ----

    #[test]
    fn display_external_data_file_open() {
        let err = Error::ExternalDataFileOpen {
            message: String::from("no such file"),
            path: String::from("/data/ext.raw"),
        };
        assert_eq!(
            err.to_string(),
            "failed to open external data file '/data/ext.raw': no such file"
        );
    }

    #[test]
    fn display_compressed_with_external_data() {
        assert_eq!(
            Error::CompressedWithExternalData.to_string(),
            "compressed clusters are not supported with external data files"
        );
    }

    #[test]
    fn display_missing_external_data_file_path() {
        assert_eq!(
            Error::MissingExternalDataFilePath.to_string(),
            "image has EXTERNAL_DATA_FILE flag but no data file path in header extensions"
        );
    }

    #[test]
    fn display_raw_external_required() {
        assert_eq!(
            Error::RawExternalRequired.to_string(),
            "only raw external data files are supported (RAW_EXTERNAL autoclear bit required)"
        );
    }

    // ---- Encryption ----

    #[test]
    fn display_decryption_failed() {
        let err = Error::DecryptionFailed {
            guest_offset: 0x80000,
            message: String::from("bad padding"),
        };
        assert_eq!(
            err.to_string(),
            "decryption failed for cluster at guest offset 0x80000: bad padding"
        );
    }

    #[test]
    fn display_encryption_failed() {
        let err = Error::EncryptionFailed {
            guest_offset: 0x90000,
            message: String::from("key not set"),
        };
        assert_eq!(
            err.to_string(),
            "encryption failed for cluster at guest offset 0x90000: key not set"
        );
    }

    #[test]
    fn display_invalid_luks_header() {
        let err = Error::InvalidLuksHeader {
            message: String::from("bad magic"),
        };
        assert_eq!(err.to_string(), "invalid LUKS header: bad magic");
    }

    #[test]
    fn display_unsupported_cipher() {
        let err = Error::UnsupportedCipher {
            cipher_name: String::from("serpent"),
            cipher_mode: String::from("cbc-essiv"),
        };
        assert_eq!(
            err.to_string(),
            "unsupported cipher: serpent-cbc-essiv"
        );
    }

    #[test]
    fn display_key_derivation_failed() {
        let err = Error::KeyDerivationFailed {
            message: String::from("iteration count too high"),
        };
        assert_eq!(
            err.to_string(),
            "key derivation failed: iteration count too high"
        );
    }

    #[test]
    fn display_wrong_password() {
        assert_eq!(
            Error::WrongPassword.to_string(),
            "wrong password: no key slot could be unlocked"
        );
    }

    #[test]
    fn display_no_password_provided() {
        assert_eq!(
            Error::NoPasswordProvided.to_string(),
            "image is encrypted but no password was provided"
        );
    }

    #[test]
    fn display_encryption_with_compression() {
        assert_eq!(
            Error::EncryptionWithCompression.to_string(),
            "encryption and compression are mutually exclusive"
        );
    }

    #[test]
    fn display_luks_key_slots_full() {
        assert_eq!(
            Error::LuksKeySlotsFull.to_string(),
            "all LUKS key slots are full"
        );
    }

    // ---- Hash ----

    #[test]
    fn display_hash_table_misaligned() {
        let err = Error::HashTableMisaligned { offset: 0xFF00 };
        assert_eq!(
            err.to_string(),
            "hash table at offset 0xff00 is not cluster-aligned"
        );
    }

    #[test]
    fn display_header_extension_overflow() {
        let err = Error::HeaderExtensionOverflow {
            needed: 70000,
            cluster_size: 65536,
        };
        assert_eq!(
            err.to_string(),
            "header extensions (70000 bytes) exceed cluster 0 (65536 bytes)"
        );
    }

    #[test]
    fn display_hash_not_initialized() {
        assert_eq!(
            Error::HashNotInitialized.to_string(),
            "hash extension not initialized"
        );
    }

    #[test]
    fn display_hash_verify_failed() {
        let err = Error::HashVerifyFailed {
            hash_chunk_index: 3,
            guest_offset: 0x30000,
            expected: String::from("aabbccdd"),
            actual: String::from("11223344"),
        };
        assert_eq!(
            err.to_string(),
            "hash mismatch at hash chunk 3 (0x30000): expected aabbccdd, actual 11223344"
        );
    }

    // ---- Edge cases ----

    #[test]
    fn display_io_all_kinds() {
        for (kind, expected_kind_str) in [
            (IoErrorKind::UnexpectedEof, "unexpected end of file"),
            (IoErrorKind::PermissionDenied, "permission denied"),
            (IoErrorKind::InvalidInput, "invalid input"),
            (IoErrorKind::InvalidData, "invalid data"),
            (IoErrorKind::WriteZero, "write zero"),
            (IoErrorKind::NotFound, "not found"),
            (IoErrorKind::Other, "I/O error"),
        ] {
            let err = Error::Io {
                kind,
                message: String::new(),
                offset: 0,
                context: "test",
            };
            let display = err.to_string();
            assert!(
                display.contains(expected_kind_str),
                "Io with kind {kind:?} should contain '{expected_kind_str}', got: {display}"
            );
        }
    }

    #[test]
    fn display_refcount_overflow_max_values() {
        let err = Error::RefcountOverflow {
            cluster_offset: u64::MAX,
            current: u64::MAX,
            max: u64::MAX,
        };
        assert_eq!(
            err.to_string(),
            "refcount overflow at cluster offset 0xffffffffffffffff: current 18446744073709551615, max 18446744073709551615"
        );
    }

    #[test]
    fn display_offset_beyond_disk_size_zero() {
        let err = Error::OffsetBeyondDiskSize {
            offset: 0,
            disk_size: 0,
        };
        assert_eq!(
            err.to_string(),
            "offset 0x0 exceeds virtual disk size 0x0"
        );
    }

    // ---- Block writer errors ----

    #[test]
    fn display_cluster_already_flushed() {
        let err = Error::ClusterAlreadyFlushed {
            guest_offset: 0x10000,
            host_offset: 0x30000,
        };
        assert_eq!(
            err.to_string(),
            "guest cluster at offset 0x10000 was already flushed to host offset 0x30000"
        );
    }

    #[test]
    fn display_cluster_not_in_buffer() {
        let err = Error::ClusterNotInBuffer {
            guest_offset: 0x20000,
        };
        assert_eq!(
            err.to_string(),
            "guest cluster at offset 0x20000 is not in the write buffer (already flushed)"
        );
    }

    #[test]
    fn display_block_writer_memory_exceeded() {
        let err = Error::BlockWriterMemoryExceeded {
            current: 4_294_967_296,
            limit: 4_294_967_296,
        };
        assert_eq!(
            err.to_string(),
            "block writer memory limit exceeded: 4294967296 bytes used, limit is 4294967296 bytes"
        );
    }

    #[test]
    fn display_block_writer_finalized() {
        assert_eq!(
            Error::BlockWriterFinalized.to_string(),
            "block writer has already been finalized; no further writes are allowed"
        );
    }
}
