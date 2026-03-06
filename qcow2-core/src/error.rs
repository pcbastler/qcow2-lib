//! Unified error types for the qcow2-core crate.
//!
//! Every error variant carries context about WHERE the error occurred
//! (byte offset, table index, cluster number) to enable meaningful diagnostics.
//!
//! This module is `no_std`-compatible. Instead of wrapping `std::io::Error`,
//! I/O failures are represented by [`IoErrorKind`], a lightweight enum that
//! can be converted to/from `std::io::ErrorKind` by the `qcow2` userspace crate.

extern crate alloc;

use alloc::string::String;
use core::fmt;

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

    /// The virtual_size is invalid (e.g. zero).
    InvalidVirtualSize {
        /// The invalid virtual size.
        size: u64,
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

    /// An L2 table was found at a non-cluster-aligned offset.
    L2TableMisaligned {
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

    /// A guest offset exceeds the virtual disk size.
    OffsetBeyondDiskSize {
        /// The out-of-bounds offset.
        offset: u64,
        /// The virtual disk size.
        disk_size: u64,
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

    // ---- Write errors ----

    /// A write operation was attempted on a read-only image.
    ReadOnly,

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

    // ---- Bitmap errors ----

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

    /// A bitmap table was found at a non-cluster-aligned offset.
    BitmapTableMisaligned {
        /// The misaligned host offset.
        offset: u64,
    },

    // ---- Extended L2 errors ----

    /// Extended L2 requires cluster_bits >= 14.
    ExtendedL2ClusterBitsTooSmall {
        /// The actual cluster_bits value.
        cluster_bits: u32,
        /// Minimum required value (14).
        min: u32,
    },

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

    /// Encryption and compression are mutually exclusive in QCOW2.
    EncryptionWithCompression,

    /// All LUKS key slots are full.
    LuksKeySlotsFull,

    // ---- BLAKE3 hash errors ----

    /// The BLAKE3 hash extension header is invalid.
    InvalidHashExtension {
        /// Description of what is wrong.
        message: String,
    },

    /// A hash table was found at a non-cluster-aligned offset.
    HashTableMisaligned {
        /// The misaligned host offset.
        offset: u64,
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
            Self::Io { kind, message, offset, context } => {
                write!(f, "I/O error at offset 0x{offset:x} ({context}): {kind}")?;
                if !message.is_empty() {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            Self::InvalidMagic { expected, found } =>
                write!(f, "invalid QCOW2 magic: expected 0x{expected:08x}, found 0x{found:08x}"),
            Self::UnsupportedVersion { version } =>
                write!(f, "unsupported QCOW2 version {version} (supported: 2, 3)"),
            Self::HeaderTooShort { expected, actual } =>
                write!(f, "header too short: need {expected} bytes, got {actual}"),
            Self::InvalidVirtualSize { size } =>
                write!(f, "invalid virtual_size {size}: must be greater than 0"),
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
            Self::L2TableMisaligned { offset } =>
                write!(f, "L2 table at offset 0x{offset:x} is not cluster-aligned"),
            Self::InvalidRefcountOrder { order, max } =>
                write!(f, "invalid refcount order {order} (max: {max})"),
            Self::RefcountBlockMisaligned { offset } =>
                write!(f, "refcount block at offset 0x{offset:x} is not cluster-aligned"),
            Self::RefcountIndexOutOfBounds { index, block_size } =>
                write!(f, "refcount index {index} out of bounds (block size: {block_size})"),
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
            Self::SnapshotTruncated { offset, expected, actual } =>
                write!(f, "snapshot header at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::SnapshotTableTruncated { entry, offset, table_size } =>
                write!(f, "snapshot table truncated: entry {entry} at offset 0x{offset:x} exceeds table size of {table_size} bytes"),
            Self::ExtensionTruncated { offset, expected, actual } =>
                write!(f, "header extension at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::BufferTooSmall { expected, actual } =>
                write!(f, "buffer too small: need {expected} bytes, got {actual}"),
            Self::OffsetBeyondDiskSize { offset, disk_size } =>
                write!(f, "offset 0x{offset:x} exceeds virtual disk size 0x{disk_size:x}"),
            Self::MetadataOffsetBeyondEof { offset, size, file_size, context } =>
                write!(f, "metadata offset 0x{offset:x} with size {size} exceeds file size 0x{file_size:x} ({context})"),
            Self::AllocationTooLarge { requested, max, context } =>
                write!(f, "allocation too large: {context} requested {requested} bytes (max: {max})"),
            Self::ArithmeticOverflow { context } =>
                write!(f, "arithmetic overflow in {context}"),
            Self::ReadOnly =>
                write!(f, "image is opened read-only"),
            Self::RefcountTableFull =>
                write!(f, "refcount table is full (no space for new clusters)"),
            Self::RefcountOverflow { cluster_offset, current, max } =>
                write!(f, "refcount overflow at cluster offset 0x{cluster_offset:x}: current {current}, max {max}"),
            Self::SnapshotNotFound { identifier } =>
                write!(f, "snapshot not found: {identifier}"),
            Self::SnapshotNameEmpty =>
                write!(f, "snapshot name must not be empty"),
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
            Self::ConversionFailed { message } =>
                write!(f, "conversion failed: {message}"),
            Self::CompressionTooLarge { compressed_size, cluster_size, guest_offset } =>
                write!(f, "compression ineffective: compressed size {compressed_size} >= cluster size {cluster_size} at guest offset 0x{guest_offset:x}"),
            Self::ShrinkDataLoss { cluster_offset, context } =>
                write!(f, "shrink would lose data: cluster at offset 0x{cluster_offset:x} is still allocated ({context})"),
            Self::RepairFailed { message } =>
                write!(f, "repair failed: {message}"),
            Self::BitmapNotFound { name } =>
                write!(f, "bitmap not found: {name}"),
            Self::BitmapNameDuplicate { name } =>
                write!(f, "bitmap with name {name:?} already exists"),
            Self::BitmapNameEmpty =>
                write!(f, "bitmap name must not be empty"),
            Self::BitmapDirectoryTruncated { offset, expected, actual } =>
                write!(f, "bitmap directory entry at offset 0x{offset:x} is truncated: need {expected} bytes, got {actual}"),
            Self::InvalidBitmapExtension { message } =>
                write!(f, "invalid bitmap extension: {message}"),
            Self::BitmapIndexOutOfBounds { index, table_size } =>
                write!(f, "bitmap table index {index} out of bounds (table size: {table_size})"),
            Self::BitmapTableMisaligned { offset } =>
                write!(f, "bitmap table at offset 0x{offset:x} is not cluster-aligned"),
            Self::ExtendedL2ClusterBitsTooSmall { cluster_bits, min } =>
                write!(f, "extended L2 requires cluster_bits >= {min}, got {cluster_bits}"),
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
            Self::InvalidLuksHeader { message } =>
                write!(f, "invalid LUKS header: {message}"),
            Self::UnsupportedCipher { cipher_name, cipher_mode } =>
                write!(f, "unsupported cipher: {cipher_name}-{cipher_mode}"),
            Self::KeyDerivationFailed { message } =>
                write!(f, "key derivation failed: {message}"),
            Self::WrongPassword =>
                write!(f, "wrong password: no key slot could be unlocked"),
            Self::NoPasswordProvided =>
                write!(f, "image is encrypted but no password was provided"),
            Self::EncryptionWithCompression =>
                write!(f, "encryption and compression are mutually exclusive"),
            Self::LuksKeySlotsFull =>
                write!(f, "all LUKS key slots are full"),
            Self::InvalidHashExtension { message } =>
                write!(f, "invalid hash extension: {message}"),
            Self::HashTableMisaligned { offset } =>
                write!(f, "hash table at offset 0x{offset:x} is not cluster-aligned"),
            Self::HashNotInitialized =>
                write!(f, "hash extension not initialized"),
            Self::HashVerifyFailed { hash_chunk_index, guest_offset, expected, actual } =>
                write!(f, "hash mismatch at hash chunk {hash_chunk_index} (0x{guest_offset:x}): expected {expected}, actual {actual}"),
            Self::InvalidHashSize { size } =>
                write!(f, "invalid hash size {size} (must be 16 or 32)"),
            Self::InvalidHashChunkBits { bits, min, max } =>
                write!(f, "invalid hash chunk bits {bits} (must be 0 or {min}..={max})"),
        }
    }
}
