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
    header: Header,
    extensions: Vec<HeaderExtension>,
    backend: Box<dyn IoBackend>,
    /// Separate I/O backend for guest data when using an external data file.
    data_backend: Option<Box<dyn IoBackend>>,
    mapper: ClusterMapper,
    cache: MetadataCache,
    backing_chain: Option<BackingChain>,
    backing_image: Option<Box<Qcow2Image>>,
    read_mode: ReadMode,
    warnings: Vec<ReadWarning>,
    refcount_manager: Option<RefcountManager>,
    writable: bool,
    dirty: bool,
    /// Byte offset for packing compressed clusters into shared host clusters.
    compressed_cursor: u64,
    /// Cached flag: true if any bitmap has the AUTO flag set.
    has_auto_bitmaps: bool,
    /// Cached flag: true if a BLAKE3 hash extension exists.
    has_hashes: bool,
    /// Encryption context (set when image has crypt_method=2 and password provided).
    crypt_context: Option<crate::engine::encryption::CryptContext>,
    /// Compression backend for deflate/zstd.
    compressor: compression::StdCompressor,
}

impl crate::io::BackingImage for Qcow2Image {
    fn virtual_size(&self) -> u64 {
        self.header.virtual_size
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
            header,
            extensions,
            backend,
            data_backend,
            mapper,
            cache: MetadataCache::new(CacheConfig::default()),
            backing_chain,
            backing_image,
            read_mode,
            warnings,
            refcount_manager,
            writable,
            dirty: false,
            compressed_cursor: 0,
            has_auto_bitmaps,
            has_hashes,
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
            &image.header,
        )?;
        image.refcount_manager = Some(refcount_manager);
        image.writable = true;
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
        // Read header (read enough for the largest possible v3 header)
        let mut header_buf = vec![0u8; 512];
        let file_size = backend.file_size()?;
        let read_size = header_buf.len().min(file_size as usize);
        backend.read_exact_at(&mut header_buf[..read_size], 0)?;
        let header = Header::read_from(&header_buf[..read_size])?;

        // Validate header offsets against physical file size
        header.validate_against_file(file_size)?;

        // Read header extensions (between header end and first cluster boundary)
        let ext_start = header.header_length as u64;
        let cluster_size = header.cluster_size();
        let ext_end = cluster_size.min(file_size);
        let extensions = if ext_start < ext_end {
            let mut ext_buf = vec![0u8; (ext_end - ext_start) as usize];
            backend.read_exact_at(&mut ext_buf, ext_start)?;
            HeaderExtension::read_all(&ext_buf).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Validate BLAKE3 hash table offset is cluster-aligned
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

        // Read L1 table (with checked arithmetic for allocation size)
        let l1_size = (header.l1_table_entries as usize)
            .checked_mul(crate::format::constants::L1_ENTRY_SIZE)
            .ok_or(FormatError::ArithmeticOverflow {
                context: "l1_table_entries * L1_ENTRY_SIZE",
            })?;
        let mut l1_buf = vec![0u8; l1_size];
        backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
        let l1_table = L1Table::read_from(&l1_buf, header.l1_table_entries)?;

        // Build cluster mapper
        let mapper = ClusterMapper::new(l1_table, header.geometry(), file_size);

        // Resolve backing chain and open backing image
        let mut warnings = Vec::new();
        let mut backing_chain = None;
        let mut backing_image = None;

        if header.has_backing_file() {
            if let Some(dir) = image_dir {
                let name = backing_mod::read_backing_file_name(
                    backend.as_ref(),
                    header.backing_file_offset,
                    header.backing_file_size,
                )?;
                match BackingChain::resolve(&name, dir) {
                    Ok(chain) => {
                        // Open the immediate backing file for read-through
                        let backing_path = &chain.entries()[0].path;
                        match Qcow2Image::open_with_mode(backing_path, read_mode) {
                            Ok(img) => {
                                backing_image = Some(Box::new(img));
                            }
                            Err(e) if read_mode == ReadMode::Lenient => {
                                warnings.push(ReadWarning {
                                    guest_offset: 0,
                                    message: format!("failed to open backing file: {e}"),
                                });
                            }
                            Err(e) => return Err(e),
                        }
                        backing_chain = Some(chain);
                    }
                    Err(e) if read_mode == ReadMode::Lenient => {
                        warnings.push(ReadWarning {
                            guest_offset: 0,
                            message: format!("backing file resolution failed: {e}"),
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Open external data file if EXTERNAL_DATA_FILE feature is set
        let data_backend = if header
            .incompatible_features
            .contains(IncompatibleFeatures::EXTERNAL_DATA_FILE)
        {
            // Require RAW_EXTERNAL — non-raw external data files are not supported
            if !header
                .autoclear_features
                .contains(AutoclearFeatures::RAW_EXTERNAL)
            {
                return Err(Error::RawExternalRequired);
            }
            if let Some(db) = data_backend {
                // Caller provided the data backend directly
                Some(db)
            } else if let Some(dir) = image_dir {
                // Path-based open: find the filename in header extensions
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
                Some(Box::new(db) as Box<dyn IoBackend>)
            } else {
                return Err(Error::MissingExternalDataFilePath);
            }
        } else {
            None
        };

        // Check if any bitmap has auto-tracking enabled
        let has_auto_bitmaps = Self::detect_auto_bitmaps(backend.as_ref(), &extensions);

        // Check if BLAKE3 hash extension exists
        let has_hashes = hash_manager::detect_hashes(&extensions);

        // Recover encryption context if image is LUKS-encrypted
        let crypt_context = if header.crypt_method == crate::format::constants::CRYPT_LUKS {
            let pw = password.ok_or(Error::NoPasswordProvided)?;

            // Find LUKS header location from FullDiskEncryption extension
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

            // Read LUKS header data
            let mut luks_data = vec![0u8; luks_length as usize];
            backend.read_exact_at(&mut luks_data, luks_offset)?;

            let ctx = crate::engine::encryption::recover_master_key(&luks_data, pw)?;
            Some(ctx)
        } else {
            None
        };

        Ok(Self::new_inner(
            header,
            extensions,
            backend,
            data_backend,
            mapper,
            backing_chain,
            backing_image,
            read_mode,
            warnings,
            None,  // refcount_manager (read-only)
            false, // writable
            has_auto_bitmaps,
            has_hashes,
            crypt_context,
        ))
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
            &self.mapper,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.cache,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.header.compression_type,
            self.read_mode,
            &mut self.warnings,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        reader.read_at(buf, guest_offset)
    }

    /// The parsed image header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The header extensions found in the image.
    pub fn extensions(&self) -> &[HeaderExtension] {
        &self.extensions
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> u64 {
        self.header.virtual_size
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.header.cluster_size()
    }

    /// The cluster_bits value from the header.
    pub fn cluster_bits(&self) -> u32 {
        self.header.cluster_bits
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
        self.cache.stats()
    }

    /// Current cache write mode.
    pub fn cache_mode(&self) -> CacheMode {
        self.cache.mode()
    }

    /// Set the cache write mode.
    ///
    /// When switching from WriteBack to WriteThrough, all dirty entries are
    /// flushed to disk first. Switching from WriteThrough to WriteBack is
    /// always safe (no flush needed).
    pub fn set_cache_mode(&mut self, mode: CacheMode) -> Result<()> {
        if self.cache.mode() == mode {
            return Ok(());
        }
        // Flush dirty entries before switching to WriteThrough
        if mode == CacheMode::WriteThrough {
            self.flush_dirty_metadata()?;
        }
        self.cache.set_mode(mode);
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
        self.read_mode
    }

    /// Change the read mode for subsequent reads.
    pub fn set_read_mode(&mut self, mode: ReadMode) {
        self.read_mode = mode;
    }

    /// Warnings collected during lenient-mode reads.
    ///
    /// Empty in strict mode since errors are returned immediately.
    pub fn warnings(&self) -> &[ReadWarning] {
        &self.warnings
    }

    /// Clear all collected warnings.
    pub fn clear_warnings(&mut self) {
        self.warnings.clear();
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
                .extensions
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
            &image.header,
        )?;
        image.refcount_manager = Some(refcount_manager);
        image.writable = true;

        Ok(image)
    }

    /// Create a writable `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Loads the refcount table for cluster allocation. Useful for testing.
    pub fn from_backend_rw(backend: Box<dyn IoBackend>) -> Result<Self> {
        let mut image = Self::from_backend_with_options(backend, None, ReadMode::Strict, None, None)?;

        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.header,
        )?;
        image.refcount_manager = Some(refcount_manager);
        image.writable = true;

        Ok(image)
    }

    /// Write `buf` starting at the given guest offset.
    ///
    /// Requires the image to be opened with `open_rw` or `from_backend_rw`.
    /// Sets the DIRTY flag on the first write. All metadata updates are
    /// written through to disk immediately.
    pub fn write_at(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        // Set dirty flag on first write
        if !self.dirty {
            self.mark_dirty()?;
        }

        let raw_external = self.data_backend.is_some();
        let data_be: &dyn IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.mapper,
            self.header.l1_table_offset,
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.header.compression_type,
            raw_external,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.write_at(buf, guest_offset)?;

        // Auto-track dirty bitmaps
        if self.has_auto_bitmaps {
            self.track_bitmap_write(guest_offset, buf.len() as u64)?;
        }

        // Update per-cluster hashes
        if self.has_hashes {
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
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        self.flush_dirty_metadata()?;

        self.backend.flush()?;

        if self.dirty {
            self.clear_dirty()?;
        }

        Ok(())
    }

    /// Write all dirty refcount blocks and L2 tables from cache to disk.
    fn flush_dirty_metadata(&mut self) -> Result<()> {
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut self.cache,
            self.header.cluster_bits,
        )
    }

    /// Whether the image is opened for writing.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Whether the DIRTY flag is currently set.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Set the DIRTY incompatible feature flag in the on-disk header.
    ///
    /// Also clears the BITMAPS autoclear bit if bitmaps exist, since
    /// bitmaps may be inconsistent while the image is dirty.
    fn mark_dirty(&mut self) -> Result<()> {
        self.header.incompatible_features |= IncompatibleFeatures::DIRTY;
        self.write_incompatible_features()?;

        // Clear BITMAPS autoclear bit while image is dirty
        if self.has_auto_bitmaps
            && self
                .header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.header.autoclear_features -= AutoclearFeatures::BITMAPS;
            self.write_autoclear_features()?;
        }

        // Clear BLAKE3_HASHES autoclear bit while image is dirty
        if self.has_hashes
            && self
                .header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
            self.write_autoclear_features()?;
        }

        self.backend.flush()?;
        self.dirty = true;
        Ok(())
    }

    /// Clear the DIRTY incompatible feature flag from the on-disk header.
    ///
    /// Restores the BITMAPS autoclear bit if bitmaps exist.
    fn clear_dirty(&mut self) -> Result<()> {
        self.header.incompatible_features -= IncompatibleFeatures::DIRTY;
        self.write_incompatible_features()?;

        // Restore BITMAPS autoclear bit on clean close
        if self.has_auto_bitmaps
            && !self
                .header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.header.autoclear_features |= AutoclearFeatures::BITMAPS;
            self.write_autoclear_features()?;
        }

        // Restore BLAKE3_HASHES autoclear bit on clean close
        if self.has_hashes
            && !self
                .header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
            self.write_autoclear_features()?;
        }

        self.backend.flush()?;
        self.dirty = false;
        Ok(())
    }

    /// Write the autoclear_features field to the on-disk header (offset 88).
    fn write_autoclear_features(&self) -> Result<()> {
        qcow2_core::engine::metadata_io::write_autoclear_features(
            self.backend.as_ref(),
            self.header.autoclear_features,
        )
    }

    /// Write the incompatible_features field to the on-disk header (offset 72).
    fn write_incompatible_features(&self) -> Result<()> {
        qcow2_core::engine::metadata_io::write_incompatible_features(
            self.backend.as_ref(),
            self.header.incompatible_features,
        )
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
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size() as usize;
        match compression::compress_cluster(data, cluster_size, self.header.compression_type)? {
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
        if !self.dirty {
            self.mark_dirty()?;
        }

        if self.data_backend.is_some() {
            return Err(Error::CompressedWithExternalData);
        }
        if self.crypt_context.is_some() {
            return Err(Error::EncryptionWithCompression);
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.mapper,
            self.header.l1_table_offset,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.header.compression_type,
            false,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.set_compressed_cursor(self.compressed_cursor);
        let result = writer.write_compressed_at(compressed_data, guest_offset);
        self.compressed_cursor = writer.compressed_cursor();
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
        if self.writable {
            self.flush_dirty_metadata()?;
        }
        crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &self.header,
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
            &self.header,
        )?;

        if let Some(repair_mode) = mode {
            if !report.is_clean() {
                let refcount_manager = self
                    .refcount_manager
                    .as_mut()
                    .ok_or(Error::ReadOnly)?;
                crate::engine::integrity::repair_refcounts(
                    self.backend.as_ref(),
                    &self.header,
                    refcount_manager,
                    &mut self.cache,
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

impl Drop for Qcow2Image {
    fn drop(&mut self) {
        if self.writable {
            // Best-effort flush of dirty metadata on drop.
            // Errors are silently ignored since Drop cannot return errors.
            let _ = self.flush_dirty_metadata();
            let _ = self.backend.flush();
        }
    }
}

#[cfg(test)]
mod tests;
