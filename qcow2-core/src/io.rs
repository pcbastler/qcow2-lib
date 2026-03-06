//! I/O backend and compression abstractions for positioned reads and writes.
//!
//! The [`IoBackend`] trait decouples the engine from any specific I/O
//! implementation. The [`Compressor`] trait decouples compression algorithms
//! from the engine. The [`BackingImage`] trait abstracts over backing file
//! access for the read path.
//!
//! All traits are `no_std`-compatible. Concrete implementations live in the
//! `qcow2` userspace crate (file-backed, flate2/zstd) or in kernel modules
//! (VFS-backed, kernel zlib/zstd).

use crate::error::Result;

/// Abstraction over positioned I/O operations.
///
/// Implementations must be `Send + Sync` to support concurrent and async
/// engine designs. All operations are offset-based (positioned) and do not
/// maintain a file cursor.
pub trait IoBackend: Send + Sync {
    /// Read exactly `buf.len()` bytes starting at the given offset.
    ///
    /// Returns an error if the full read cannot be satisfied (e.g., EOF).
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// Write exactly `buf.len()` bytes starting at the given offset.
    ///
    /// Returns an error if the full write cannot be completed.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()>;

    /// Flush any buffered writes to the underlying storage.
    fn flush(&self) -> Result<()>;

    /// Total size of the backing storage in bytes.
    fn file_size(&self) -> Result<u64>;

    /// Resize the backing storage to exactly `size` bytes.
    ///
    /// Extends with zeros or truncates as appropriate.
    fn set_len(&self, size: u64) -> Result<()>;
}

/// Abstraction over compression and decompression algorithms.
///
/// Decouples the QCOW2 engine from specific compression libraries (flate2,
/// zstd in userspace; kernel zlib/zstd in kernel modules).
///
/// Implementations must be `Send + Sync` to match [`IoBackend`] requirements.
pub trait Compressor: Send + Sync {
    /// Decompress a QCOW2 compressed cluster.
    ///
    /// # Arguments
    /// * `input` — Compressed bytes read from the host file.
    /// * `output` — Buffer for the decompressed data (exactly one cluster).
    /// * `compression_type` — 0 = deflate, 1 = zstandard.
    ///
    /// # Returns
    /// The number of bytes written to `output`.
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
        compression_type: u8,
    ) -> Result<usize>;

    /// Compress a cluster of data.
    ///
    /// # Arguments
    /// * `input` — Uncompressed cluster data.
    /// * `output` — Buffer for compressed output (must be at least `input.len()`).
    /// * `compression_type` — 0 = deflate, 1 = zstandard.
    ///
    /// # Returns
    /// The number of bytes written to `output`, or an error if compression
    /// produces output larger than the input (ineffective compression).
    fn compress(
        &self,
        input: &[u8],
        output: &mut [u8],
        compression_type: u8,
    ) -> Result<usize>;
}

/// Abstraction over a backing image for the read path.
///
/// When a cluster is unallocated in the current image, the reader falls
/// back to reading from the backing image. This trait allows the core
/// engine to work without knowing the concrete image type.
pub trait BackingImage {
    /// Virtual size of the backing image in bytes.
    fn virtual_size(&self) -> u64;

    /// Read `buf.len()` bytes from the backing image at the given guest offset.
    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()>;
}
