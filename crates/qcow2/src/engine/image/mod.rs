//! Main entry point for opening and reading QCOW2 images.
//!
//! [`Qcow2Image`] is the public facade that ties together header parsing,
//! cluster mapping, caching, and the read engine. Users of this crate
//! typically interact only with this type.
//!
//! The implementation is split across sub-modules by functional area:
//! - [`open`]: opening images from files and backends
//! - [`create`]: image creation and overlay setup
//! - [`read_write`]: read, write, flush, and compressed writes
//! - [`accessors`]: public getters and setters
//! - [`backing_ops`]: commit and rebase operations
//! - [`snapshot`]: snapshot management
//! - [`bitmap`]: persistent dirty bitmap API
//! - [`hash`]: BLAKE3 per-chunk hash API
//! - [`integrity`]: integrity checks and repair
//! - [`resize`]: virtual size changes and file truncation

mod accessors;
mod backing_ops;
mod bitmap;
mod create;
mod hash;
mod integrity;
mod open;
mod read_write;
mod resize;
mod snapshot;

use crate::engine::backing::BackingChain;
use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::compression;
use crate::engine::image_meta::ImageMeta;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::refcount_manager::RefcountManager;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::io::IoBackend;

/// A QCOW2 disk image.
///
/// Owns the I/O backend, header, L1 table, and metadata cache. Provides
/// `read_at` for reads and `write_at` + `flush` when opened in read-write mode.
///
/// # Example
///
/// ```no_run
/// use qcow2::engine::image::Qcow2Image;
///
/// let mut image = Qcow2Image::open("disk.qcow2").unwrap();
/// let mut buf = vec![0u8; 512];
/// image.read_at(&mut buf, 0).unwrap();
/// ```
pub struct Qcow2Image {
    /// All mutable metadata state (shared with Qcow2ImageAsync via Mutex).
    pub(crate) meta: ImageMeta,
    pub(crate) backend: Box<dyn IoBackend>,
    /// Separate I/O backend for guest data when using an external data file.
    pub(crate) data_backend: Option<Box<dyn IoBackend>>,
    pub(crate) backing_chain: Option<BackingChain>,
    pub(crate) backing_image: Option<Box<Qcow2Image>>,
    /// Encryption context (set when image has crypt_method=2 and password provided).
    pub(crate) crypt_context: Option<crate::engine::encryption::CryptContext>,
    /// Compression backend for deflate/zstd.
    pub(crate) compressor: compression::StdCompressor,
}

impl crate::io::BackingImage for Qcow2Image {
    fn virtual_size(&self) -> u64 {
        self.meta.header.virtual_size
    }

    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> crate::error::Result<()> {
        Qcow2Image::read_at(self, buf, guest_offset)
    }
}

/// Options for creating a new QCOW2 image.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Log2 of cluster size (default: 16 = 64 KB).
    pub cluster_bits: Option<u32>,
    /// Enable extended L2 entries (subclusters). Default: false.
    /// Requires cluster_bits >= 14.
    pub extended_l2: bool,
    /// Compression type: `None` = deflate (default), `Some(COMPRESSION_ZSTD)` = zstandard.
    pub compression_type: Option<u8>,
    /// External data file name. When set, guest data is stored in a separate raw file.
    pub data_file: Option<String>,
    /// Encryption options. When set, the image will be LUKS-encrypted.
    pub encryption: Option<EncryptionOptions>,
}

/// Options for creating an encrypted QCOW2 image.
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    /// Password for the key slot.
    pub password: Vec<u8>,
    /// Cipher mode (default: AES-XTS-plain64).
    pub cipher: crate::engine::encryption::CipherMode,
    /// LUKS version: 1 or 2 (default: 1).
    pub luks_version: u8,
    /// PBKDF2/Argon2 iteration time target in milliseconds.
    pub iter_time_ms: Option<u32>,
}

impl Qcow2Image {
    /// Private constructor for shared struct initialization.
    ///
    /// Fields not passed as arguments use sensible defaults:
    /// `dirty = false`, `compressed_cursor = 0`, `compressor = StdCompressor`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_inner(
        header: Header,
        extensions: Vec<HeaderExtension>,
        backend: Box<dyn IoBackend>,
        data_backend: Option<Box<dyn IoBackend>>,
        mapper: ClusterMapper,
        backing_chain: Option<BackingChain>,
        backing_image: Option<Box<Qcow2Image>>,
        read_mode: ReadMode,
        warnings: Vec<ReadWarning>,
        refcount_manager: Option<RefcountManager>,
        writable: bool,
        has_auto_bitmaps: bool,
        has_hashes: bool,
        crypt_context: Option<crate::engine::encryption::CryptContext>,
    ) -> Self {
        Self {
            meta: ImageMeta {
                header,
                extensions,
                mapper,
                cache: MetadataCache::new(CacheConfig::default()),
                refcount_manager,
                writable,
                dirty: false,
                compressed_cursor: 0,
                has_auto_bitmaps,
                has_hashes,
                read_mode,
                warnings,
            },
            backend,
            data_backend,
            backing_chain,
            backing_image,
            crypt_context,
            compressor: compression::StdCompressor,
        }
    }

    /// Decompose into constituent parts for `Qcow2ImageAsync` conversion.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        ImageMeta,
        Box<dyn IoBackend>,
        Option<Box<dyn IoBackend>>,
        Option<BackingChain>,
        Option<Box<Qcow2Image>>,
        Option<crate::engine::encryption::CryptContext>,
        compression::StdCompressor,
    ) {
        // Prevent Drop from running (which would flush)
        let me = std::mem::ManuallyDrop::new(self);

        // Safety: we take ownership of each field exactly once and never use `me` again.
        unsafe {
            let meta = std::ptr::read(&me.meta);
            let backend = std::ptr::read(&me.backend);
            let data_backend = std::ptr::read(&me.data_backend);
            let backing_chain = std::ptr::read(&me.backing_chain);
            let backing_image = std::ptr::read(&me.backing_image);
            let crypt_context = std::ptr::read(&me.crypt_context);
            let compressor = std::ptr::read(&me.compressor);
            (meta, backend, data_backend, backing_chain, backing_image, crypt_context, compressor)
        }
    }

    /// Reconstruct from constituent parts (inverse of `into_parts`).
    pub fn from_parts(
        meta: ImageMeta,
        backend: Box<dyn IoBackend>,
        data_backend: Option<Box<dyn IoBackend>>,
        backing_chain: Option<BackingChain>,
        backing_image: Option<Box<Qcow2Image>>,
        crypt_context: Option<crate::engine::encryption::CryptContext>,
        compressor: compression::StdCompressor,
    ) -> Self {
        Self {
            meta,
            backend,
            data_backend,
            backing_chain,
            backing_image,
            crypt_context,
            compressor,
        }
    }
}

impl Drop for Qcow2Image {
    fn drop(&mut self) {
        if self.meta.writable {
            // Best-effort flush of dirty metadata on drop.
            // Errors are silently ignored since Drop cannot return errors.
            let _ = self.flush_dirty_metadata();
            let _ = self.backend.flush();
        }
    }
}

#[cfg(test)]
mod tests;
