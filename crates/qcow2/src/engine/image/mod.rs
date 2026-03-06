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

use byteorder::{BigEndian, ByteOrder};

use crate::engine::backing::{self as backing_mod, BackingChain};
use crate::engine::bitmap_manager::BitmapManager;
use crate::engine::cache::{CacheConfig, CacheStats, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::compression;
use crate::engine::hash_manager::{self, HashManager};
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

        Ok(Self {
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
            refcount_manager: None,
            writable: false,
            dirty: false,
            compressed_cursor: 0,
            has_auto_bitmaps,
            has_hashes,
            crypt_context,
            compressor: compression::StdCompressor,
        })
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
            let cluster_bits = self.header.cluster_bits;
            let virtual_size = self.header.virtual_size;
            let refcount_manager = self
                .refcount_manager
                .as_mut()
                .expect("writable image must have refcount_manager");

            let mut mgr = BitmapManager::new(
                self.backend.as_ref(),
                &mut self.cache,
                refcount_manager,
                &mut self.header,
                &mut self.extensions,
                cluster_bits,
                virtual_size,
            );
            mgr.track_write(guest_offset, buf.len() as u64)?;
        }

        // Update per-cluster hashes
        if self.has_hashes {
            let cluster_bits = self.header.cluster_bits;
            let virtual_size = self.header.virtual_size;
            let refcount_manager = self
                .refcount_manager
                .as_mut()
                .expect("writable image must have refcount_manager");

            let compression_type = self.header.compression_type;
            let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
                Some(db) => db.as_ref(),
                None => self.backend.as_ref(),
            };
            let mut mgr = HashManager::new(
                self.backend.as_ref(),
                data_be,
                &mut self.cache,
                refcount_manager,
                &mut self.header,
                &mut self.extensions,
                &self.mapper,
                cluster_bits,
                virtual_size,
                compression_type,
                self.crypt_context.as_ref(),
                &self.compressor,
            );
            mgr.update_hashes_for_range(guest_offset, buf.len() as u64)?;
        }

        Ok(())
    }

    /// Flush all pending writes and clear the DIRTY flag.
    ///
    /// Since we use write-through, this only needs to flush the backend
    /// and clear the dirty bit in the header.
    pub fn flush(&mut self) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        self.backend.flush()?;

        if self.dirty {
            self.clear_dirty()?;
        }

        Ok(())
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
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, self.header.autoclear_features.bits());
        self.backend.write_all_at(&buf, 88)?;
        Ok(())
    }

    /// Write the incompatible_features field to the on-disk header (offset 72).
    fn write_incompatible_features(&self) -> Result<()> {
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, self.header.incompatible_features.bits());
        self.backend.write_all_at(&buf, 72)?;
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
        &self,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
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

// ---- Test helpers shared across sub-module tests ----

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::format::constants::*;
    use crate::format::header::Header;
    use crate::format::l1::L1Entry;
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    pub const CLUSTER_BITS: u32 = 16;
    pub const CLUSTER_SIZE: usize = 1 << 16;

    /// Build a minimal but valid QCOW2 v3 image in memory.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry)
    ///   Cluster 2: L2 table
    ///   Cluster 3+: data clusters
    pub fn build_test_image(
        l2_entries: &[(u32, u64)],
        data_clusters: &[(usize, &[u8])],
    ) -> MemoryBackend {
        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];

        let l1_offset = CLUSTER_SIZE;
        let l2_offset = 2 * CLUSTER_SIZE;

        // Write header
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30, // 1 GB
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(l1_offset as u64),
            refcount_table_offset: ClusterOffset(0), // not used in read tests
            refcount_table_clusters: 0,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header.write_to(&mut image_data[..HEADER_V3_MIN_LENGTH]).unwrap();

        // Write L1 table: one entry pointing to L2 at cluster 2
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        BigEndian::write_u64(&mut image_data[l1_offset..], l1_entry.raw());

        // Write L2 entries
        for &(index, raw_entry) in l2_entries {
            let offset = l2_offset + index as usize * L2_ENTRY_SIZE;
            BigEndian::write_u64(&mut image_data[offset..], raw_entry);
        }

        // Write data clusters
        for &(cluster_idx, data) in data_clusters {
            let offset = cluster_idx * CLUSTER_SIZE;
            let len = data.len().min(CLUSTER_SIZE);
            image_data[offset..offset + len].copy_from_slice(&data[..len]);
        }

        MemoryBackend::new(image_data)
    }

    /// Build a writable QCOW2 v3 image with a proper refcount table.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry, unallocated)
    ///   Cluster 2: refcount table (1 cluster)
    ///   Cluster 3: refcount block 0
    ///   Cluster 4+: free
    pub fn build_writable_test_image() -> MemoryBackend {
        let l1_offset = CLUSTER_SIZE;
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;
        let total_size = 4 * CLUSTER_SIZE;

        let mut data = vec![0u8; total_size];

        // Write header
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(l1_offset as u64),
            refcount_table_offset: ClusterOffset(rt_offset as u64),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header.write_to(&mut data[..HEADER_V3_MIN_LENGTH]).unwrap();

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-3 have refcount 1
        for i in 0..4 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }

        MemoryBackend::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::read_mode::ReadMode;
    use crate::format::constants::*;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};
    use test_helpers::*;

    #[test]
    fn open_from_backend_reads_header() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        assert_eq!(image.header().version, 3);
        assert_eq!(image.header().cluster_bits, CLUSTER_BITS);
        assert_eq!(image.virtual_size(), 1 << 30);
        assert_eq!(image.cluster_size(), CLUSTER_SIZE as u64);
    }

    #[test]
    fn read_allocated_data() {
        let data_cluster = 3;
        let host_offset = data_cluster as u64 * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;
        let test_data = b"Hello from Qcow2Image!";

        let backend = build_test_image(
            &[(0, l2_raw)],
            &[(data_cluster, test_data)],
        );
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0u8; test_data.len()];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, test_data);
    }

    #[test]
    fn read_unallocated_returns_zeros() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_zero_cluster() {
        let l2_raw = L2_ZERO_FLAG;
        let backend = build_test_image(&[(0, l2_raw)], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0xFFu8; 256];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_beyond_virtual_size_fails() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let vs = image.virtual_size();
        let mut buf = vec![0u8; 512];
        let result = image.read_at(&mut buf, vs);
        assert!(result.is_err());
    }

    #[test]
    fn cache_stats_are_accessible() {
        let data_cluster = 3;
        let host_offset = data_cluster as u64 * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;

        let backend = build_test_image(
            &[(0, l2_raw)],
            &[(data_cluster, &[0xAA; 64])],
        );
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0u8; 64];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(image.cache_stats().l2_misses, 1);

        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(image.cache_stats().l2_hits, 1);
    }

    // ---- Edge cases: opening invalid files ----

    #[test]
    fn reject_non_qcow2_data() {
        let backend = MemoryBackend::zeroed(4096);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_short_for_header() {
        let backend = MemoryBackend::new(vec![0u8; 40]);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_file() {
        let backend = MemoryBackend::new(vec![]);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_garbage_data() {
        let backend = MemoryBackend::new(b"hello world, this is not a qcow2 image!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!".to_vec());
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn extensions_accessor_works() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let _exts = image.extensions();
    }

    #[test]
    fn backend_accessor_works() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let b = image.backend();
        assert!(b.file_size().unwrap() > 0);
    }

    // ---- ReadMode + validation tests ----

    #[test]
    fn default_read_mode_is_strict() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Strict);
    }

    #[test]
    fn set_read_mode_changes_behavior() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Strict);

        image.set_read_mode(ReadMode::Lenient);
        assert_eq!(image.read_mode(), ReadMode::Lenient);
    }

    #[test]
    fn warnings_initially_empty() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert!(image.warnings().is_empty());
    }

    #[test]
    fn clear_warnings_works() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        image.clear_warnings();
        assert!(image.warnings().is_empty());
    }

    #[test]
    fn from_backend_with_mode_sets_mode() {
        let backend = build_test_image(&[], &[]);
        let image =
            Qcow2Image::from_backend_with_mode(Box::new(backend), ReadMode::Lenient).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Lenient);
    }

    #[test]
    fn strict_mode_rejects_l1_beyond_eof() {
        let mut image_data = vec![0u8; 2 * CLUSTER_SIZE];
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: 100,
            l1_table_offset: ClusterOffset(0x100_0000),
            refcount_table_offset: ClusterOffset(0),
            refcount_table_clusters: 0,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header
            .write_to(&mut image_data[..HEADER_V3_MIN_LENGTH])
            .unwrap();

        let backend = MemoryBackend::new(image_data);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn strict_mode_rejects_huge_l1_entries() {
        let mut image_data = vec![0u8; 2 * CLUSTER_SIZE];
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: u32::MAX,
            l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
            refcount_table_offset: ClusterOffset(0),
            refcount_table_clusters: 0,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header
            .write_to(&mut image_data[..HEADER_V3_MIN_LENGTH])
            .unwrap();

        let backend = MemoryBackend::new(image_data);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn lenient_mode_reads_zeros_for_unallocated() {
        let backend = build_test_image(&[], &[]);
        let mut image =
            Qcow2Image::from_backend_with_mode(Box::new(backend), ReadMode::Lenient).unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
        assert!(image.warnings().is_empty());
    }

    // ---- Write API tests ----

    #[test]
    fn from_backend_rw_enables_writing() {
        let backend = build_writable_test_image();
        let image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert!(image.is_writable());
        assert!(!image.is_dirty());
    }

    #[test]
    fn read_only_image_rejects_write() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let result = image.write_at(&[0x42; 64], 0);
        assert!(matches!(result, Err(Error::ReadOnly)));
    }

    #[test]
    fn read_only_image_rejects_flush() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let result = image.flush();
        assert!(matches!(result, Err(Error::ReadOnly)));
    }

    #[test]
    fn write_sets_dirty_flag() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert!(!image.is_dirty());

        image.write_at(&[0xAA; 64], 0).unwrap();
        assert!(image.is_dirty());
    }

    #[test]
    fn dirty_flag_persisted_to_disk_header() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0xBB; 64], 0).unwrap();

        let mut buf = [0u8; 8];
        image.backend().read_exact_at(&mut buf, 72).unwrap();
        let features = BigEndian::read_u64(&buf);
        assert_ne!(features & 1, 0, "DIRTY bit should be set on disk");
    }

    #[test]
    fn flush_clears_dirty_flag() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0xCC; 64], 0).unwrap();
        assert!(image.is_dirty());

        image.flush().unwrap();
        assert!(!image.is_dirty());

        let mut buf = [0u8; 8];
        image.backend().read_exact_at(&mut buf, 72).unwrap();
        let features = BigEndian::read_u64(&buf);
        assert_eq!(features & 1, 0, "DIRTY bit should be cleared on disk");
    }

    #[test]
    fn write_then_read_back() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let write_data = vec![0xDD; 1024];
        image.write_at(&write_data, 0).unwrap();

        let mut read_buf = vec![0u8; 1024];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn write_partial_then_read_full_cluster() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let write_data = vec![0xEE; 100];
        image.write_at(&write_data, 200).unwrap();

        let mut cluster_buf = vec![0u8; CLUSTER_SIZE];
        image.read_at(&mut cluster_buf, 0).unwrap();

        assert!(cluster_buf[..200].iter().all(|&b| b == 0));
        assert_eq!(&cluster_buf[200..300], &write_data[..]);
        assert!(cluster_buf[300..].iter().all(|&b| b == 0));
    }

    #[test]
    fn multiple_writes_then_read() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0x11; 50], 0).unwrap();
        image.write_at(&[0x22; 50], 50).unwrap();
        image.write_at(&[0x33; 50], 100).unwrap();

        let mut buf = vec![0u8; 150];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf[..50].iter().all(|&b| b == 0x11));
        assert!(buf[50..100].iter().all(|&b| b == 0x22));
        assert!(buf[100..150].iter().all(|&b| b == 0x33));
    }

    #[test]
    fn flush_without_writes_is_noop() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.flush().unwrap();
        assert!(!image.is_dirty());
    }
}
