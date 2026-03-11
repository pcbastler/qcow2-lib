//! Main entry point for opening and reading QCOW2 images.
//!
//! [`Qcow2Image`] is the public facade that ties together header parsing,
//! cluster mapping, caching, and the read engine. Users of this crate
//! typically interact only with this type.
//!
//! The implementation is split across sub-modules by functional area:
//! - [`create`]: image creation and overlay setup
//! - [`backing`]: commit and rebase operations
//! - [`snapshot`]: snapshot management
//! - [`bitmap`]: persistent dirty bitmap API
//! - [`hash`]: BLAKE3 per-chunk hash API
//! - [`resize`]: virtual size changes and file truncation

mod backing_ops;
mod bitmap;
mod create;
mod hash;
mod resize;
mod snapshot;

use std::path::Path;


use crate::engine::backing::{self as backing_mod, BackingChain};
use crate::engine::cache::{CacheConfig, CacheMode, CacheStats, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::compression;
use crate::engine::hash_manager;
use crate::engine::image_meta::ImageMeta;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::reader::Qcow2Reader;
use crate::engine::refcount_manager::RefcountManager;
use crate::engine::writer::Qcow2Writer;
use crate::error::{Error, FormatError, Result};
use crate::format::bitmap::BitmapDirectoryEntry;
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::L1Table;
use crate::format::types::ClusterOffset;
use crate::io::sync_backend::SyncFileBackend;
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
    meta: ImageMeta,
    backend: Box<dyn IoBackend>,
    /// Separate I/O backend for guest data when using an external data file.
    data_backend: Option<Box<dyn IoBackend>>,
    backing_chain: Option<BackingChain>,
    backing_image: Option<Box<Qcow2Image>>,
    /// Encryption context (set when image has crypt_method=2 and password provided).
    crypt_context: Option<crate::engine::encryption::CryptContext>,
    /// Compression backend for deflate/zstd.
    compressor: compression::StdCompressor,
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

// ---- Core: open, read, accessors ----

impl Qcow2Image {
    /// Private constructor for shared struct initialization.
    ///
    /// Fields not passed as arguments use sensible defaults:
    /// `dirty = false`, `compressed_cursor = 0`, `compressor = StdCompressor`.
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
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

    /// Open a QCOW2 image file at the given path.
    ///
    /// Parses the header, loads the L1 table, and optionally resolves
    /// the backing file chain. Uses [`ReadMode::Strict`] by default.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_mode(path, ReadMode::Strict)
    }

    /// Open a QCOW2 image file with the specified read mode.
    ///
    /// In [`ReadMode::Lenient`], recoverable errors during reads will
    /// produce zeros and warnings instead of aborting.
    pub fn open_with_mode<P: AsRef<Path>>(path: P, read_mode: ReadMode) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_backend_with_options(Box::new(backend), Some(image_dir), read_mode, None, None)
    }

    /// Create a `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Useful for testing with [`MemoryBackend`](crate::io::MemoryBackend)
    /// or for custom I/O implementations. Uses [`ReadMode::Strict`].
    pub fn from_backend(backend: Box<dyn IoBackend>) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, None, None)
    }

    /// Create a `Qcow2Image` from a backend with an explicit read mode.
    pub fn from_backend_with_mode(
        backend: Box<dyn IoBackend>,
        read_mode: ReadMode,
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, read_mode, None, None)
    }

    /// Create a `Qcow2Image` from separate metadata and data backends.
    ///
    /// Use this when the image has an external data file and you want to
    /// provide the data backend yourself instead of having the library open it.
    pub fn from_backend_with_data(
        backend: Box<dyn IoBackend>,
        data_backend: Option<Box<dyn IoBackend>>,
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, data_backend, None)
    }

    /// Open a QCOW2 image file with a password for encrypted images.
    pub fn open_with_password<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_backend_with_options(
            Box::new(backend), Some(image_dir), ReadMode::Strict, None, Some(password),
        )
    }

    /// Open a QCOW2 image read-write with a password for encrypted images.
    pub fn open_rw_with_password<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open_rw(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut image = Self::from_backend_with_options(
            Box::new(backend), Some(image_dir), ReadMode::Strict, None, Some(password),
        )?;

        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;
        Ok(image)
    }

    /// Create a `Qcow2Image` from a backend with a password for encrypted images.
    pub fn from_backend_with_password(
        backend: Box<dyn IoBackend>,
        password: &[u8],
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, None, Some(password))
    }

    /// Internal constructor that handles both file and backend paths.
    fn from_backend_with_options(
        backend: Box<dyn IoBackend>,
        image_dir: Option<&Path>,
        read_mode: ReadMode,
        data_backend: Option<Box<dyn IoBackend>>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, extensions, file_size) =
            Self::read_header_and_extensions(backend.as_ref())?;

        let mapper = Self::build_mapper(backend.as_ref(), &header, file_size)?;

        let mut warnings = Vec::new();
        let (backing_chain, backing_image) =
            Self::resolve_backing(&header, backend.as_ref(), image_dir, read_mode, &mut warnings)?;

        let data_backend = Self::resolve_data_backend(
            &header, &extensions, data_backend, image_dir,
        )?;

        let has_auto_bitmaps = Self::detect_auto_bitmaps(backend.as_ref(), &extensions);
        let has_hashes = hash_manager::detect_hashes(&extensions);

        let crypt_context = Self::recover_crypt_context(
            &header, &extensions, backend.as_ref(), password,
        )?;

        Ok(Self::new_inner(
            header, extensions, backend, data_backend,
            mapper, backing_chain, backing_image,
            read_mode, warnings,
            None, false, has_auto_bitmaps, has_hashes, crypt_context,
        ))
    }

    /// Read and validate the header, extensions, and file size.
    fn read_header_and_extensions(
        backend: &dyn IoBackend,
    ) -> Result<(Header, Vec<HeaderExtension>, u64)> {
        let mut header_buf = vec![0u8; 512];
        let file_size = backend.file_size()?;
        let read_size = header_buf.len().min(file_size as usize);
        backend.read_exact_at(&mut header_buf[..read_size], 0)?;
        let header = Header::read_from(&header_buf[..read_size])?;
        header.validate_against_file(file_size)?;

        let ext_start = header.header_length as u64;
        let ext_end = header.cluster_size().min(file_size);
        let extensions = if ext_start < ext_end {
            let mut ext_buf = vec![0u8; (ext_end - ext_start) as usize];
            backend.read_exact_at(&mut ext_buf, ext_start)?;
            HeaderExtension::read_all(&ext_buf).unwrap_or_default()
        } else {
            Vec::new()
        };

        for ext in &extensions {
            if let HeaderExtension::Blake3Hashes(blake3) = ext {
                if blake3.hash_table_offset != 0
                    && !ClusterOffset(blake3.hash_table_offset)
                        .is_cluster_aligned(header.cluster_bits)
                {
                    return Err(Error::HashTableMisaligned {
                        offset: blake3.hash_table_offset,
                    });
                }
            }
        }

        Ok((header, extensions, file_size))
    }

    /// Read L1 table and build the cluster mapper.
    fn build_mapper(
        backend: &dyn IoBackend,
        header: &Header,
        file_size: u64,
    ) -> Result<ClusterMapper> {
        let l1_size = (header.l1_table_entries as usize)
            .checked_mul(crate::format::constants::L1_ENTRY_SIZE)
            .ok_or(FormatError::ArithmeticOverflow {
                context: "l1_table_entries * L1_ENTRY_SIZE",
            })?;
        let mut l1_buf = vec![0u8; l1_size];
        backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
        let l1_table = L1Table::read_from(&l1_buf, header.l1_table_entries)?;
        Ok(ClusterMapper::new(l1_table, header.geometry(), file_size))
    }

    /// Resolve the backing chain and open the backing image.
    fn resolve_backing(
        header: &Header,
        backend: &dyn IoBackend,
        image_dir: Option<&Path>,
        read_mode: ReadMode,
        warnings: &mut Vec<ReadWarning>,
    ) -> Result<(Option<BackingChain>, Option<Box<Qcow2Image>>)> {
        if !header.has_backing_file() {
            return Ok((None, None));
        }
        let dir = match image_dir {
            Some(d) => d,
            None => return Ok((None, None)),
        };
        let name = backing_mod::read_backing_file_name(
            backend, header.backing_file_offset, header.backing_file_size,
        )?;
        match BackingChain::resolve(&name, dir) {
            Ok(chain) => {
                let backing_path = &chain.entries()[0].path;
                match Qcow2Image::open_with_mode(backing_path, read_mode) {
                    Ok(img) => Ok((Some(chain), Some(Box::new(img)))),
                    Err(e) if read_mode == ReadMode::Lenient => {
                        warnings.push(ReadWarning {
                            guest_offset: 0,
                            message: format!("failed to open backing file: {e}"),
                        });
                        Ok((Some(chain), None))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) if read_mode == ReadMode::Lenient => {
                warnings.push(ReadWarning {
                    guest_offset: 0,
                    message: format!("backing file resolution failed: {e}"),
                });
                Ok((None, None))
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve the external data file backend.
    fn resolve_data_backend(
        header: &Header,
        extensions: &[HeaderExtension],
        data_backend: Option<Box<dyn IoBackend>>,
        image_dir: Option<&Path>,
    ) -> Result<Option<Box<dyn IoBackend>>> {
        if !header.incompatible_features.contains(IncompatibleFeatures::EXTERNAL_DATA_FILE) {
            return Ok(None);
        }
        if !header.autoclear_features.contains(AutoclearFeatures::RAW_EXTERNAL) {
            return Err(Error::RawExternalRequired);
        }
        if let Some(db) = data_backend {
            return Ok(Some(db));
        }
        let dir = image_dir.ok_or(Error::MissingExternalDataFilePath)?;
        let data_file_name = extensions
            .iter()
            .find_map(|e| match e {
                HeaderExtension::ExternalDataFile(name) => Some(name.clone()),
                _ => None,
            })
            .ok_or(Error::MissingExternalDataFilePath)?;
        let data_path = dir.join(&data_file_name);
        let db = SyncFileBackend::open(&data_path).map_err(|e| {
            if let Error::Io { message, .. } = &e {
                Error::ExternalDataFileOpen {
                    message: message.clone(),
                    path: data_path.display().to_string(),
                }
            } else {
                e
            }
        })?;
        Ok(Some(Box::new(db) as Box<dyn IoBackend>))
    }

    /// Recover the encryption context from the LUKS header if encrypted.
    fn recover_crypt_context(
        header: &Header,
        extensions: &[HeaderExtension],
        backend: &dyn IoBackend,
        password: Option<&[u8]>,
    ) -> Result<Option<crate::engine::encryption::CryptContext>> {
        if header.crypt_method != crate::format::constants::CRYPT_LUKS {
            return Ok(None);
        }
        let pw = password.ok_or(Error::NoPasswordProvided)?;
        let (luks_offset, luks_length) = extensions
            .iter()
            .find_map(|e| match e {
                HeaderExtension::FullDiskEncryption { offset, length } => {
                    Some((*offset, *length))
                }
                _ => None,
            })
            .ok_or(Error::InvalidLuksHeader {
                message: "missing FullDiskEncryption header extension".to_string(),
            })?;
        let mut luks_data = vec![0u8; luks_length as usize];
        backend.read_exact_at(&mut luks_data, luks_offset)?;
        let ctx = crate::engine::encryption::recover_master_key(&luks_data, pw)?;
        Ok(Some(ctx))
    }

    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Handles reads that span multiple clusters, zero clusters,
    /// compressed clusters, and unallocated regions.
    ///
    /// In [`ReadMode::Lenient`], unreadable regions are filled with zeros
    /// and warnings are collected (see [`warnings`](Self::warnings)).
    pub fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        // RAW_EXTERNAL: data is always at guest offset in the raw file.
        // No L2 lookup needed — identity mapping is guaranteed.
        if let Some(ref data_be) = self.data_backend {
            return data_be.read_exact_at(buf, guest_offset);
        }

        let mut reader = Qcow2Reader::new(
            &self.meta.mapper,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.meta.cache,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            self.meta.read_mode,
            &mut self.meta.warnings,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        reader.read_at(buf, guest_offset)
    }

    /// The parsed image header.
    pub fn header(&self) -> &Header {
        &self.meta.header
    }

    /// The header extensions found in the image.
    pub fn extensions(&self) -> &[HeaderExtension] {
        &self.meta.extensions
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> u64 {
        self.meta.header.virtual_size
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.meta.header.cluster_size()
    }

    /// The cluster_bits value from the header.
    pub fn cluster_bits(&self) -> u32 {
        self.meta.header.cluster_bits
    }

    /// Whether the image is encrypted (crypt_method != 0).
    pub fn is_encrypted(&self) -> bool {
        self.crypt_context.is_some()
    }

    /// The resolved backing file chain, if any.
    pub fn backing_chain(&self) -> Option<&BackingChain> {
        self.backing_chain.as_ref()
    }

    /// Current cache statistics for diagnostics.
    pub fn cache_stats(&self) -> &CacheStats {
        self.meta.cache.stats()
    }

    /// Current cache write mode.
    pub fn cache_mode(&self) -> CacheMode {
        self.meta.cache.mode()
    }

    /// Set the cache write mode.
    ///
    /// When switching from WriteBack to WriteThrough, all dirty entries are
    /// flushed to disk first. Switching from WriteThrough to WriteBack is
    /// always safe (no flush needed).
    pub fn set_cache_mode(&mut self, mode: CacheMode) -> Result<()> {
        if self.meta.cache.mode() == mode {
            return Ok(());
        }
        // Flush dirty entries before switching to WriteThrough
        if mode == CacheMode::WriteThrough {
            self.flush_dirty_metadata()?;
        }
        self.meta.cache.set_mode(mode);
        Ok(())
    }

    /// Access the underlying I/O backend.
    ///
    /// Useful for CLI tools that need to read raw metadata directly.
    pub fn backend(&self) -> &dyn IoBackend {
        self.backend.as_ref()
    }

    /// The I/O backend for guest data clusters.
    ///
    /// Returns the external data file backend if present, otherwise the main backend.
    pub fn data_backend(&self) -> &dyn IoBackend {
        self.data_backend
            .as_deref()
            .unwrap_or(self.backend.as_ref())
    }

    /// Whether this image uses an external data file.
    pub fn has_external_data_file(&self) -> bool {
        self.data_backend.is_some()
    }

    /// Set the external data backend (for testing or caller-provided backends).
    pub fn set_data_backend(&mut self, backend: Box<dyn IoBackend>) {
        self.data_backend = Some(backend);
    }

    /// The current read mode.
    pub fn read_mode(&self) -> ReadMode {
        self.meta.read_mode
    }

    /// Change the read mode for subsequent reads.
    pub fn set_read_mode(&mut self, mode: ReadMode) {
        self.meta.read_mode = mode;
    }

    /// Warnings collected during lenient-mode reads.
    ///
    /// Empty in strict mode since errors are returned immediately.
    pub fn warnings(&self) -> &[ReadWarning] {
        &self.meta.warnings
    }

    /// Clear all collected warnings.
    pub fn clear_warnings(&mut self) {
        self.meta.warnings.clear();
    }

    // ---- Write API ----

    /// Open a QCOW2 image file for read-write access.
    ///
    /// Loads the refcount table and enables `write_at` / `flush`.
    /// Sets the DIRTY incompatible feature flag on the first write.
    pub fn open_rw<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open_rw(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut image = Self::from_backend_with_options(
            Box::new(backend),
            Some(image_dir),
            ReadMode::Strict,
            None,
            None,
        )?;

        // If external data file, reopen in rw mode
        if image.has_external_data_file() {
            let data_file_name = image
                .meta.extensions
                .iter()
                .find_map(|e| match e {
                    HeaderExtension::ExternalDataFile(name) => Some(name.clone()),
                    _ => None,
                })
                .ok_or(Error::MissingExternalDataFilePath)?;
            let data_path = image_dir.join(&data_file_name);
            let db = SyncFileBackend::open_rw(&data_path).map_err(|e| {
                if let Error::Io { message, .. } = &e {
                    Error::ExternalDataFileOpen {
                        message: message.clone(),
                        path: data_path.display().to_string(),
                    }
                } else {
                    e
                }
            })?;
            image.data_backend = Some(Box::new(db));
        }

        // Load refcount manager for write support
        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;

        Ok(image)
    }

    /// Create a writable `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Loads the refcount table for cluster allocation. Useful for testing.
    pub fn from_backend_rw(backend: Box<dyn IoBackend>) -> Result<Self> {
        let mut image = Self::from_backend_with_options(backend, None, ReadMode::Strict, None, None)?;

        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;

        Ok(image)
    }

    /// Write `buf` starting at the given guest offset.
    ///
    /// Requires the image to be opened with `open_rw` or `from_backend_rw`.
    /// Sets the DIRTY flag on the first write. All metadata updates are
    /// written through to disk immediately.
    pub fn write_at(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        // Set dirty flag on first write
        if !self.meta.dirty {
            self.mark_dirty()?;
        }

        let raw_external = self.data_backend.is_some();
        let data_be: &dyn IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.meta.mapper,
            self.meta.header.l1_table_offset,
            self.backend.as_ref(),
            data_be,
            &mut self.meta.cache,
            refcount_manager,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            raw_external,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.write_at(buf, guest_offset)?;

        // Auto-track dirty bitmaps
        if self.meta.has_auto_bitmaps {
            self.track_bitmap_write(guest_offset, buf.len() as u64)?;
        }

        // Update per-cluster hashes
        if self.meta.has_hashes {
            self.update_hashes_for_write(guest_offset, buf.len() as u64)?;
        }

        Ok(())
    }

    /// Flush all dirty cached metadata to disk and clear the DIRTY flag.
    ///
    /// In WriteBack mode, flushes refcount blocks first (crash consistency:
    /// leaked space is recoverable, dangling L2 refs are not), then L2 tables,
    /// then issues an fsync, and finally clears the DIRTY header bit.
    pub fn flush(&mut self) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        self.flush_dirty_metadata()?;

        self.backend.flush()?;

        if self.meta.dirty {
            self.clear_dirty()?;
        }

        Ok(())
    }

    /// Write all dirty refcount blocks and L2 tables from cache to disk.
    fn flush_dirty_metadata(&mut self) -> Result<()> {
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut self.meta.cache,
            self.meta.header.cluster_bits,
        )
    }

    /// Whether the image is opened for writing.
    pub fn is_writable(&self) -> bool {
        self.meta.writable
    }

    /// Whether the DIRTY flag is currently set.
    pub fn is_dirty(&self) -> bool {
        self.meta.dirty
    }

    /// Set the DIRTY incompatible feature flag in the on-disk header.
    ///
    /// Also clears the BITMAPS autoclear bit if bitmaps exist, since
    /// bitmaps may be inconsistent while the image is dirty.
    fn mark_dirty(&mut self) -> Result<()> {
        self.meta.header.incompatible_features |= IncompatibleFeatures::DIRTY;

        // Clear autoclear bits while image is dirty
        if self.meta.has_auto_bitmaps
            && self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.meta.header.autoclear_features -= AutoclearFeatures::BITMAPS;
        }
        if self.meta.has_hashes
            && self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.meta.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
        }

        // Single batched I/O for both feature fields
        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            self.backend.as_ref(),
            self.meta.header.incompatible_features,
            self.meta.header.autoclear_features,
        )?;

        self.backend.flush()?;
        self.meta.dirty = true;
        Ok(())
    }

    /// Clear the DIRTY incompatible feature flag from the on-disk header.
    ///
    /// Restores the BITMAPS autoclear bit if bitmaps exist.
    fn clear_dirty(&mut self) -> Result<()> {
        self.meta.header.incompatible_features -= IncompatibleFeatures::DIRTY;

        // Restore autoclear bits on clean close
        if self.meta.has_auto_bitmaps
            && !self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.meta.header.autoclear_features |= AutoclearFeatures::BITMAPS;
        }
        if self.meta.has_hashes
            && !self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.meta.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
        }

        // Single batched I/O for both feature fields
        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            self.backend.as_ref(),
            self.meta.header.incompatible_features,
            self.meta.header.autoclear_features,
        )?;

        self.backend.flush()?;
        self.meta.dirty = false;
        Ok(())
    }



    // ---- Compressed write API ----

    /// Write a cluster, attempting compression first.
    ///
    /// If deflate compression reduces the data size below the cluster size,
    /// writes a compressed cluster. Otherwise falls back to a normal
    /// uncompressed write.
    ///
    /// The `guest_offset` must be cluster-aligned and `data.len()` must
    /// equal the cluster size.
    pub fn write_cluster_maybe_compressed(
        &mut self,
        data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size() as usize;
        match compression::compress_cluster(data, cluster_size, self.meta.header.compression_type)? {
            Some(compressed) => self.write_compressed_at(&compressed, guest_offset),
            None => self.write_at(data, guest_offset),
        }
    }

    /// Write pre-compressed data as a compressed cluster.
    fn write_compressed_at(
        &mut self,
        compressed_data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        if !self.meta.dirty {
            self.mark_dirty()?;
        }

        if self.data_backend.is_some() {
            return Err(Error::CompressedWithExternalData);
        }
        if self.crypt_context.is_some() {
            return Err(Error::EncryptionWithCompression);
        }

        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.meta.mapper,
            self.meta.header.l1_table_offset,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            false,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.set_compressed_cursor(self.meta.compressed_cursor);
        let result = writer.write_compressed_at(compressed_data, guest_offset);
        self.meta.compressed_cursor = writer.compressed_cursor();
        result
    }

    // ---- Integrity & repair API ----

    /// Check image integrity by verifying all refcounts against the actual
    /// cluster references.
    ///
    /// This walks all L1/L2 tables (active **and** snapshots) to build an
    /// expected reference count map, then compares with stored refcounts.
    pub fn check_integrity(
        &mut self,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        // Flush dirty metadata so the check sees current on-disk state
        if self.meta.writable {
            self.flush_dirty_metadata()?;
        }
        crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &self.meta.header,
        )
    }

    /// Check integrity and optionally repair mismatches.
    ///
    /// Returns the integrity report from *before* repair. If `mode` is `Some`,
    /// any issues found are repaired in-place and the backend is flushed.
    pub fn check_and_repair(
        &mut self,
        mode: Option<crate::engine::integrity::RepairMode>,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        // Flush dirty metadata so the check sees current on-disk state
        self.flush_dirty_metadata()?;
        let report = crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &self.meta.header,
        )?;

        if let Some(repair_mode) = mode {
            if !report.is_clean() {
                let refcount_manager = self
                    .meta.refcount_manager
                    .as_mut()
                    .ok_or(Error::ReadOnly)?;
                crate::engine::integrity::repair_refcounts(
                    self.backend.as_ref(),
                    &self.meta.header,
                    refcount_manager,
                    &mut self.meta.cache,
                    repair_mode,
                )?;
                self.backend.flush()?;
            }
        }

        Ok(report)
    }

    // ---- Internal helpers ----

    /// Detect whether any bitmap has the AUTO flag set.
    fn detect_auto_bitmaps(
        backend: &dyn IoBackend,
        extensions: &[HeaderExtension],
    ) -> bool {
        let ext = match extensions.iter().find_map(|e| match e {
            HeaderExtension::Bitmaps(b) => Some(b),
            _ => None,
        }) {
            Some(ext) if ext.nb_bitmaps > 0 => ext,
            _ => return false,
        };

        // Guard against malicious bitmap_directory_size exceeding the file.
        let file_size = match backend.file_size() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if ext.bitmap_directory_size > file_size {
            return false;
        }

        let mut buf = vec![0u8; ext.bitmap_directory_size as usize];
        if backend
            .read_exact_at(&mut buf, ext.bitmap_directory_offset)
            .is_err()
        {
            return false;
        }

        match BitmapDirectoryEntry::read_directory(&buf, ext.nb_bitmaps) {
            Ok(entries) => entries.iter().any(|e| e.is_auto()),
            Err(_) => false,
        }
    }
}

impl Qcow2Image {
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
