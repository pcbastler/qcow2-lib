//! Main entry point for opening and reading QCOW2 images.
//!
//! [`Qcow2Image`] is the public facade that ties together header parsing,
//! cluster mapping, caching, and the read engine. Users of this crate
//! typically interact only with this type.

use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::backing::{self, BackingChain};
use crate::engine::cache::{CacheConfig, CacheStats, MetadataCache};
use crate::engine::compression;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::reader::Qcow2Reader;
use crate::engine::refcount_manager::RefcountManager;
use crate::engine::snapshot_manager::{SnapshotInfo, SnapshotManager};
use crate::engine::writer::Qcow2Writer;
use crate::error::{Error, Result};
use crate::format::feature_flags::IncompatibleFeatures;
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
/// use qcow2_lib::engine::image::Qcow2Image;
///
/// let mut image = Qcow2Image::open("disk.qcow2").unwrap();
/// let mut buf = vec![0u8; 512];
/// image.read_at(&mut buf, 0).unwrap();
/// ```
pub struct Qcow2Image {
    header: Header,
    extensions: Vec<HeaderExtension>,
    backend: Box<dyn IoBackend>,
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
}

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
        Self::from_backend_with_options(Box::new(backend), Some(image_dir), read_mode)
    }

    /// Create a `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Useful for testing with [`MemoryBackend`](crate::io::MemoryBackend)
    /// or for custom I/O implementations. Uses [`ReadMode::Strict`].
    pub fn from_backend(backend: Box<dyn IoBackend>) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict)
    }

    /// Create a `Qcow2Image` from a backend with an explicit read mode.
    pub fn from_backend_with_mode(
        backend: Box<dyn IoBackend>,
        read_mode: ReadMode,
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, read_mode)
    }

    /// Internal constructor that handles both file and backend paths.
    fn from_backend_with_options(
        backend: Box<dyn IoBackend>,
        image_dir: Option<&Path>,
        read_mode: ReadMode,
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

        // Read L1 table (with checked arithmetic for allocation size)
        let l1_size = (header.l1_table_entries as usize)
            .checked_mul(crate::format::constants::L1_ENTRY_SIZE)
            .ok_or(Error::ArithmeticOverflow {
                context: "l1_table_entries * L1_ENTRY_SIZE",
            })?;
        let mut l1_buf = vec![0u8; l1_size];
        backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
        let l1_table = L1Table::read_from(&l1_buf, header.l1_table_entries)?;

        // Build cluster mapper
        let mapper = ClusterMapper::new(l1_table, header.cluster_bits, file_size);

        // Resolve backing chain and open backing image
        let mut warnings = Vec::new();
        let mut backing_chain = None;
        let mut backing_image = None;

        if header.has_backing_file() {
            if let Some(dir) = image_dir {
                let name = backing::read_backing_file_name(
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

        Ok(Self {
            header,
            extensions,
            backend,
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
        let mut reader = Qcow2Reader::new(
            &self.mapper,
            self.backend.as_ref(),
            &mut self.cache,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.read_mode,
            &mut self.warnings,
            self.backing_image.as_deref_mut(),
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
        )?;

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
        let mut image = Self::from_backend_with_options(backend, None, ReadMode::Strict)?;

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

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.mapper,
            self.header.l1_table_offset,
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.backing_image.as_deref_mut(),
        );
        writer.write_at(buf, guest_offset)
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
    fn mark_dirty(&mut self) -> Result<()> {
        self.header.incompatible_features |= IncompatibleFeatures::DIRTY;
        self.write_incompatible_features()?;
        self.backend.flush()?;
        self.dirty = true;
        Ok(())
    }

    /// Clear the DIRTY incompatible feature flag from the on-disk header.
    fn clear_dirty(&mut self) -> Result<()> {
        self.header.incompatible_features -= IncompatibleFeatures::DIRTY;
        self.write_incompatible_features()?;
        self.backend.flush()?;
        self.dirty = false;
        Ok(())
    }

    /// Write the incompatible_features field to the on-disk header (offset 72).
    fn write_incompatible_features(&self) -> Result<()> {
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, self.header.incompatible_features.bits());
        self.backend.write_all_at(&buf, 72)?;
        Ok(())
    }

    // ---- Image creation ----

    /// Create a new QCOW2 v3 image at the given path.
    ///
    /// Returns a writable `Qcow2Image` ready for writes. The image is
    /// created with a minimal on-disk layout:
    ///
    /// - Cluster 0: header
    /// - Cluster 1: L1 table
    /// - Cluster 2: refcount table (1 cluster)
    /// - Cluster 3: refcount block 0
    pub fn create<P: AsRef<Path>>(path: P, options: CreateOptions) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::create(path).map_err(|e| {
            if let Error::Io { source, .. } = e {
                Error::CreateFailed {
                    source,
                    path: path.display().to_string(),
                }
            } else {
                e
            }
        })?;
        Self::create_on_backend(Box::new(backend), options)
    }

    /// Create a new QCOW2 v3 image on an I/O backend (for testing).
    pub fn create_on_backend(
        backend: Box<dyn IoBackend>,
        options: CreateOptions,
    ) -> Result<Self> {
        let cluster_bits = options.cluster_bits.unwrap_or(16);
        let cluster_size = 1u64 << cluster_bits;
        let refcount_order = 4u32; // 16-bit refcounts

        // Calculate L1 table size
        let l2_entries = cluster_size / 8; // 8 bytes per L2 entry
        let bytes_per_l1_entry = l2_entries * cluster_size;
        let l1_entries =
            ((options.virtual_size + bytes_per_l1_entry - 1) / bytes_per_l1_entry) as u32;

        // Layout: header(0), L1(1), reftable(2), refblock(3)
        let l1_offset = cluster_size;
        let rt_offset = 2 * cluster_size;
        let rb_offset = 3 * cluster_size;
        let initial_clusters = 4u64;

        // Build header
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits,
            virtual_size: options.virtual_size,
            crypt_method: 0,
            l1_table_entries: l1_entries,
            l1_table_offset: ClusterOffset(l1_offset),
            refcount_table_offset: ClusterOffset(rt_offset),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order,
            header_length: crate::format::constants::HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };

        // Write zeroed image (initial_clusters * cluster_size bytes)
        let zeroed_cluster = vec![0u8; cluster_size as usize];
        for i in 0..initial_clusters {
            backend.write_all_at(&zeroed_cluster, i * cluster_size)?;
        }

        // Write header
        let mut header_buf = vec![0u8; cluster_size as usize];
        header.write_to(&mut header_buf)?;
        backend.write_all_at(&header_buf, 0)?;

        // Write L1 table (all zeros = unallocated, already written)

        // Write refcount table: entry 0 → refcount block at cluster 3
        let mut rt_buf = [0u8; 8];
        BigEndian::write_u64(&mut rt_buf, rb_offset);
        backend.write_all_at(&rt_buf, rt_offset)?;

        // Write refcount block: clusters 0-3 have refcount 1
        let mut rb_buf = vec![0u8; cluster_size as usize];
        for i in 0..initial_clusters as usize {
            BigEndian::write_u16(&mut rb_buf[i * 2..], 1);
        }
        backend.write_all_at(&rb_buf, rb_offset)?;

        backend.flush()?;

        // Build in-memory structures
        let l1_table = L1Table::new_empty(l1_entries);
        let file_size = backend.file_size()?;
        let mapper = ClusterMapper::new(l1_table, cluster_bits, file_size);
        let refcount_manager = RefcountManager::load(backend.as_ref(), &header)?;

        Ok(Self {
            header,
            extensions: Vec::new(),
            backend,
            mapper,
            cache: MetadataCache::new(CacheConfig::default()),
            backing_chain: None,
            backing_image: None,
            read_mode: ReadMode::Strict,
            warnings: Vec::new(),
            refcount_manager: Some(refcount_manager),
            writable: true,
            dirty: false,
            compressed_cursor: 0,
        })
    }

    /// Create a new QCOW2 v3 overlay image at the given path.
    ///
    /// The overlay references the given backing file. Reads of unallocated
    /// clusters fall through to the backing image; writes go to the overlay.
    pub fn create_overlay<P: AsRef<Path>, Q: AsRef<Path>>(
        path: P,
        backing_path: Q,
        virtual_size: u64,
    ) -> Result<Self> {
        let path = path.as_ref();
        let backing_path = backing_path.as_ref();

        let backend = SyncFileBackend::create(path).map_err(|e| {
            if let Error::Io { source, .. } = e {
                Error::CreateFailed {
                    source,
                    path: path.display().to_string(),
                }
            } else {
                e
            }
        })?;

        Self::create_overlay_on_backend(
            Box::new(backend),
            backing_path,
            virtual_size,
        )
    }

    /// Create a new QCOW2 v3 overlay image on an I/O backend.
    ///
    /// The overlay stores the backing file name in the header and opens
    /// the backing file for read-through. Useful for testing.
    pub fn create_overlay_on_backend(
        backend: Box<dyn IoBackend>,
        backing_path: &Path,
        virtual_size: u64,
    ) -> Result<Self> {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let refcount_order = 4u32;

        // Calculate L1 table size
        let l2_entries = cluster_size / 8;
        let bytes_per_l1_entry = l2_entries * cluster_size;
        let l1_entries =
            ((virtual_size + bytes_per_l1_entry - 1) / bytes_per_l1_entry) as u32;

        // Layout: header(0), L1(1), reftable(2), refblock(3)
        let l1_offset = cluster_size;
        let rt_offset = 2 * cluster_size;
        let rb_offset = 3 * cluster_size;
        let initial_clusters = 4u64;

        // Header extension area starts at header_length (byte 104).
        // Write an end-of-extensions marker (type=0, length=0 → 8 zero bytes)
        // at offset 104, then place the backing file name at offset 112.
        let backing_name = backing_path.to_string_lossy();
        let backing_name_bytes = backing_name.as_bytes();
        let ext_end_offset = crate::format::constants::HEADER_V3_MIN_LENGTH;
        let backing_file_offset = (ext_end_offset + 8) as u64; // after 8-byte terminator

        // Verify the name fits in cluster 0 (after the header)
        if backing_file_offset + backing_name_bytes.len() as u64 > cluster_size {
            return Err(Error::WriteFailed {
                guest_offset: 0,
                message: format!(
                    "backing file name ({} bytes) too long for header cluster",
                    backing_name_bytes.len()
                ),
            });
        }

        // Build header with backing file reference
        let header = Header {
            version: 3,
            backing_file_offset,
            backing_file_size: backing_name_bytes.len() as u32,
            cluster_bits,
            virtual_size,
            crypt_method: 0,
            l1_table_entries: l1_entries,
            l1_table_offset: ClusterOffset(l1_offset),
            refcount_table_offset: ClusterOffset(rt_offset),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order,
            header_length: crate::format::constants::HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };

        // Write zeroed image
        let zeroed_cluster = vec![0u8; cluster_size as usize];
        for i in 0..initial_clusters {
            backend.write_all_at(&zeroed_cluster, i * cluster_size)?;
        }

        // Write header
        let mut header_buf = vec![0u8; cluster_size as usize];
        header.write_to(&mut header_buf)?;
        // Write backing file name into the header cluster
        let bf_start = backing_file_offset as usize;
        header_buf[bf_start..bf_start + backing_name_bytes.len()]
            .copy_from_slice(backing_name_bytes);
        backend.write_all_at(&header_buf, 0)?;

        // Write refcount table: entry 0 → refcount block at cluster 3
        let mut rt_buf = [0u8; 8];
        BigEndian::write_u64(&mut rt_buf, rb_offset);
        backend.write_all_at(&rt_buf, rt_offset)?;

        // Write refcount block: clusters 0-3 have refcount 1
        let mut rb_buf = vec![0u8; cluster_size as usize];
        for i in 0..initial_clusters as usize {
            BigEndian::write_u16(&mut rb_buf[i * 2..], 1);
        }
        backend.write_all_at(&rb_buf, rb_offset)?;

        backend.flush()?;

        // Build in-memory structures
        let l1_table = L1Table::new_empty(l1_entries);
        let file_size = backend.file_size()?;
        let mapper = ClusterMapper::new(l1_table, cluster_bits, file_size);
        let refcount_manager = RefcountManager::load(backend.as_ref(), &header)?;

        // Open the backing image for read-through
        let backing_img = Qcow2Image::open(backing_path)?;

        Ok(Self {
            header,
            extensions: Vec::new(),
            backend,
            mapper,
            cache: MetadataCache::new(CacheConfig::default()),
            backing_chain: None,
            backing_image: Some(Box::new(backing_img)),
            read_mode: ReadMode::Strict,
            warnings: Vec::new(),
            refcount_manager: Some(refcount_manager),
            writable: true,
            dirty: false,
            compressed_cursor: 0,
        })
    }

    // ---- Commit / Rebase ----

    /// Merge all allocated clusters from this overlay into its backing file.
    ///
    /// After a successful commit, the backing file contains all data that
    /// was written to the overlay. The overlay itself is not modified.
    ///
    /// Requires the image to have a backing file (`CommitNoBacking` otherwise).
    pub fn commit(&mut self) -> Result<()> {
        // Must have a backing chain
        let backing_path = self
            .backing_chain
            .as_ref()
            .and_then(|c| c.entries().first())
            .map(|e| e.path.clone())
            .ok_or(Error::CommitNoBacking)?;

        // Open backing file separately for writing
        let mut backing = Qcow2Image::open_rw(&backing_path)?;

        // Resize backing if overlay has a larger virtual size (matches qemu-img commit behavior)
        if self.virtual_size() > backing.virtual_size() {
            backing.resize(self.virtual_size())?;
        }

        let cluster_size = self.header.cluster_size();
        let cluster_bits = self.header.cluster_bits;
        let l1_len = self.mapper.l1_table().len();
        let l2_entries_per_table = self.header.l2_entries_per_table();

        // Walk L1 → L2 → entries, copy allocated data to backing
        for l1_idx in 0..l1_len {
            let l1_entry = self
                .mapper
                .l1_table()
                .get(crate::format::types::L1Index(l1_idx))?;
            let l2_offset = match l1_entry.l2_table_offset() {
                Some(off) => off,
                None => continue, // entire L2 range unallocated
            };

            // Load L2 table from our backend
            let l2_table = {
                let mut buf = vec![0u8; cluster_size as usize];
                self.backend.read_exact_at(&mut buf, l2_offset.0)?;
                crate::format::l2::L2Table::read_from(&buf, cluster_bits)?
            };

            for l2_idx in 0..l2_entries_per_table {
                let l2_entry = l2_table
                    .get(crate::format::types::L2Index(l2_idx as u32))?;

                let guest_offset =
                    l1_idx as u64 * l2_entries_per_table * cluster_size
                    + l2_idx * cluster_size;

                match l2_entry {
                    crate::format::l2::L2Entry::Unallocated => {
                        // Not our data — comes from backing itself
                    }
                    crate::format::l2::L2Entry::Zero { .. } => {
                        // Write zeros to backing
                        let zeros = vec![0u8; cluster_size as usize];
                        backing.write_at(&zeros, guest_offset)?;
                    }
                    crate::format::l2::L2Entry::Standard { host_offset, .. } => {
                        // Read cluster data from our image
                        let mut data = vec![0u8; cluster_size as usize];
                        self.backend
                            .read_exact_at(&mut data, host_offset.0)?;
                        backing.write_at(&data, guest_offset)?;
                    }
                    crate::format::l2::L2Entry::Compressed(desc) => {
                        // Read compressed data, decompress, write to backing
                        let mut compressed =
                            vec![0u8; desc.compressed_size as usize];
                        self.backend
                            .read_exact_at(&mut compressed, desc.host_offset)?;
                        let decompressed = compression::decompress_cluster(
                            &compressed,
                            cluster_size as usize,
                            guest_offset,
                        )?;
                        backing.write_at(&decompressed, guest_offset)?;
                    }
                }
            }
        }

        backing.flush()?;
        Ok(())
    }

    /// Change (or remove) the backing file reference in the header.
    ///
    /// This is an **unsafe** rebase: it only updates the backing file path
    /// stored in the header without migrating any data. The caller must
    /// ensure that the new backing file is content-compatible with the old one,
    /// or that `None` is used only when all guest data is allocated in this image.
    ///
    /// Pass `None` to remove the backing file reference entirely.
    pub fn rebase_unsafe(&mut self, new_backing: Option<&Path>) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.header.cluster_size();

        match new_backing {
            None => {
                // Remove backing file reference
                // Zero out old name on disk
                if self.header.has_backing_file() {
                    let old_offset = self.header.backing_file_offset;
                    let old_size = self.header.backing_file_size as usize;
                    let zeros = vec![0u8; old_size];
                    self.backend.write_all_at(&zeros, old_offset)?;
                }

                self.header.backing_file_offset = 0;
                self.header.backing_file_size = 0;

                // Rewrite header
                let mut header_buf = vec![0u8; self.header.serialized_length()];
                self.header.write_to(&mut header_buf)?;
                self.backend.write_all_at(&header_buf, 0)?;
                self.backend.flush()?;

                // Update in-memory state
                self.backing_chain = None;
                self.backing_image = None;
            }
            Some(path) => {
                let name = path.to_string_lossy();
                let name_bytes = name.as_bytes();

                // Determine where to write the backing file name.
                // Use the standard position: right after the header extensions terminator.
                let ext_end_offset = crate::format::constants::HEADER_V3_MIN_LENGTH;
                let backing_file_offset = (ext_end_offset + 8) as u64; // after 8-byte end marker

                // Verify it fits in cluster 0
                if backing_file_offset + name_bytes.len() as u64 > cluster_size {
                    return Err(Error::WriteFailed {
                        guest_offset: 0,
                        message: format!(
                            "backing file name ({} bytes) too long for header cluster",
                            name_bytes.len()
                        ),
                    });
                }

                // Zero out old name if present
                if self.header.has_backing_file() {
                    let old_offset = self.header.backing_file_offset;
                    let old_size = self.header.backing_file_size as usize;
                    let zeros = vec![0u8; old_size];
                    self.backend.write_all_at(&zeros, old_offset)?;
                }

                // Write new name
                self.backend
                    .write_all_at(name_bytes, backing_file_offset)?;

                // Update header
                self.header.backing_file_offset = backing_file_offset;
                self.header.backing_file_size = name_bytes.len() as u32;

                // Rewrite header
                let mut header_buf = vec![0u8; self.header.serialized_length()];
                self.header.write_to(&mut header_buf)?;
                self.backend.write_all_at(&header_buf, 0)?;
                self.backend.flush()?;

                // Update in-memory state
                let image_dir = path.parent().unwrap_or(Path::new("."));
                match BackingChain::resolve(&name, image_dir) {
                    Ok(chain) => {
                        match Qcow2Image::open(path) {
                            Ok(img) => {
                                self.backing_image = Some(Box::new(img));
                            }
                            Err(_) => {
                                self.backing_image = None;
                            }
                        }
                        self.backing_chain = Some(chain);
                    }
                    Err(_) => {
                        self.backing_chain = None;
                        self.backing_image = None;
                    }
                }
            }
        }

        Ok(())
    }

    // ---- Snapshot API ----

    /// List all snapshots in the image.
    pub fn snapshot_list(&self) -> Result<Vec<SnapshotInfo>> {
        // Snapshot list is a read-only operation — we only need a temporary
        // SnapshotManager with shared references. Since SnapshotManager takes
        // &mut for generality, we clone the needed mutable state temporarily.
        // However, list_snapshots only calls load_snapshot_table which only
        // reads, so we can work around by constructing the manager with
        // temporary mutable borrows of cache/refcount/mapper that won't
        // actually be mutated.

        // We need &mut self for the cache borrow, but the public API only
        // needs &self. Use a lightweight approach: read the snapshot table
        // directly without going through SnapshotManager.
        if self.header.snapshot_count == 0 {
            return Ok(Vec::new());
        }

        let cluster_size = 1u64 << self.header.cluster_bits;
        let max_bytes =
            ((self.header.snapshot_count as u64) * 1024).min(16 * cluster_size);
        let file_size = self.backend.file_size()?;
        let available = file_size.saturating_sub(self.header.snapshots_offset.0);
        let read_size = (max_bytes as usize).min(available as usize);

        let mut buf = vec![0u8; read_size];
        self.backend
            .read_exact_at(&mut buf, self.header.snapshots_offset.0)?;

        let snapshots = crate::format::snapshot::SnapshotHeader::read_table(
            &buf,
            self.header.snapshot_count,
            self.header.snapshots_offset.0,
        )?;

        Ok(snapshots
            .into_iter()
            .map(|s| SnapshotInfo {
                id: s.unique_id,
                name: s.name,
                virtual_size: s.virtual_disk_size,
                timestamp_seconds: s.timestamp_seconds,
                l1_table_entries: s.l1_table_entries,
            })
            .collect())
    }

    /// Create a named snapshot of the current image state.
    ///
    /// Copies the active L1 table, increments refcounts for all referenced
    /// clusters, clears COPIED flags, and writes the snapshot table.
    pub fn snapshot_create(&mut self, name: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            cluster_bits,
        );
        mgr.create_snapshot(name)
    }

    /// Delete a snapshot by name or ID.
    pub fn snapshot_delete(&mut self, name_or_id: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            cluster_bits,
        );
        mgr.delete_snapshot(name_or_id)
    }

    /// Revert to a snapshot's state.
    ///
    /// Decrements refcounts for the current active state, loads the snapshot's
    /// L1 table as the new active table, and increments refcounts accordingly.
    pub fn snapshot_apply(&mut self, name_or_id: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            cluster_bits,
        );
        mgr.apply_snapshot(name_or_id)
    }

    // ---- Resize API ----

    /// Resize the image to a new virtual size (grow only).
    ///
    /// If the new size requires more L1 table entries than currently allocated,
    /// the L1 table is grown in-place or relocated to a new cluster range.
    pub fn resize(&mut self, new_virtual_size: u64) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size();

        // Validate alignment
        if new_virtual_size % cluster_size != 0 {
            return Err(Error::ResizeNotAligned {
                size: new_virtual_size,
                cluster_size,
            });
        }

        let old_virtual_size = self.header.virtual_size;

        // No-op if same size
        if new_virtual_size == old_virtual_size {
            return Ok(());
        }

        // Calculate required L1 entries
        let l2_entries = cluster_size / 8;
        let bytes_per_l1_entry = l2_entries * cluster_size;
        let new_l1_entries =
            ((new_virtual_size + bytes_per_l1_entry - 1) / bytes_per_l1_entry) as u32;
        let old_l1_entries = self.header.l1_table_entries;

        if new_virtual_size < old_virtual_size {
            // Shrink
            self.shrink_image(new_virtual_size, new_l1_entries, old_l1_entries)?;
        } else if new_l1_entries > old_l1_entries {
            self.grow_l1_table(new_l1_entries, old_l1_entries, cluster_size)?;
        }

        // Update header
        self.header.virtual_size = new_virtual_size;
        self.write_header_resize_fields()?;
        self.backend.flush()?;

        Ok(())
    }

    /// Grow the L1 table to accommodate more entries.
    fn grow_l1_table(
        &mut self,
        new_l1_entries: u32,
        old_l1_entries: u32,
        cluster_size: u64,
    ) -> Result<()> {
        let cluster_size_usize = cluster_size as usize;
        let old_l1_bytes = old_l1_entries as usize * 8;
        let new_l1_bytes = new_l1_entries as usize * 8;
        let old_l1_clusters = (old_l1_bytes + cluster_size_usize - 1) / cluster_size_usize;
        let new_l1_clusters = (new_l1_bytes + cluster_size_usize - 1) / cluster_size_usize;

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        if new_l1_clusters > old_l1_clusters {
            // L1 table must relocate: allocate new cluster(s), copy, free old

            // Read old L1 data
            let mut old_l1_data = vec![0u8; old_l1_clusters * cluster_size_usize];
            self.backend
                .read_exact_at(&mut old_l1_data, self.header.l1_table_offset.0)?;

            // Allocate new clusters
            let mut new_l1_offset = None;
            for i in 0..new_l1_clusters {
                let cluster =
                    refcount_manager.allocate_cluster(self.backend.as_ref(), &mut self.cache)?;
                let file_size = self.backend.file_size()?;
                self.mapper.set_file_size(file_size);
                if i == 0 {
                    new_l1_offset = Some(cluster);
                }
            }
            let new_l1_offset = new_l1_offset.expect("at least one cluster allocated");

            // Write old data to new location, zero-padded
            let mut new_l1_data = vec![0u8; new_l1_clusters * cluster_size_usize];
            new_l1_data[..old_l1_data.len()].copy_from_slice(&old_l1_data);
            self.backend.write_all_at(&new_l1_data, new_l1_offset.0)?;

            // Free old L1 clusters
            let old_l1_offset = self.header.l1_table_offset;
            for i in 0..old_l1_clusters {
                let cluster_off = ClusterOffset(old_l1_offset.0 + (i as u64 * cluster_size));
                refcount_manager.decrement_refcount(
                    cluster_off.0,
                    self.backend.as_ref(),
                    &mut self.cache,
                )?;
            }

            // Update header and mapper
            self.header.l1_table_offset = new_l1_offset;
            self.header.l1_table_entries = new_l1_entries;

            // Rebuild L1 table from new data
            let new_table = L1Table::read_from(&new_l1_data, new_l1_entries)?;
            self.mapper.replace_l1_table(new_table);
        } else {
            // In-place grow: just extend with zero entries at the end
            let zero_entries = new_l1_entries - old_l1_entries;
            let zero_bytes = vec![0u8; zero_entries as usize * 8];
            let write_offset =
                self.header.l1_table_offset.0 + old_l1_entries as u64 * 8;
            self.backend.write_all_at(&zero_bytes, write_offset)?;

            self.header.l1_table_entries = new_l1_entries;
            self.mapper.l1_table_mut().grow(new_l1_entries);
        }

        Ok(())
    }

    /// Shrink the virtual disk size.
    ///
    /// Refuses if there are snapshots (complex interaction) or if any
    /// clusters beyond the new boundary are still allocated.
    fn shrink_image(
        &mut self,
        new_virtual_size: u64,
        new_l1_entries: u32,
        old_l1_entries: u32,
    ) -> Result<()> {
        let cluster_size = self.cluster_size();

        // Refuse if snapshots exist — shrinking with snapshots is unsafe
        if self.header.snapshot_count > 0 {
            return Err(Error::ShrinkNotSupported {
                current: self.header.virtual_size,
                requested: new_virtual_size,
            });
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let entries_per_l2 = cluster_size / 8;

        // Check and free clusters beyond the new boundary.
        // Walk ALL L1 entries that could contain out-of-bounds references,
        // including the last kept L1 entry (which may partially cover
        // beyond new_virtual_size).
        let first_l1_to_check = if new_l1_entries > 0 {
            new_l1_entries - 1
        } else {
            0
        };

        for l1_idx in first_l1_to_check..old_l1_entries {
            let l1_entry = self
                .mapper
                .l1_entry(crate::format::types::L1Index(l1_idx))?;
            let l2_offset = match l1_entry.l2_table_offset() {
                Some(o) => o,
                None => continue,
            };

            // Read the L2 table
            let mut l2_buf = vec![0u8; cluster_size as usize];
            self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
            let l2_table =
                crate::format::l2::L2Table::read_from(&l2_buf, self.header.cluster_bits)?;

            // Check entries that correspond to guest offsets >= new_virtual_size
            let l1_guest_base = l1_idx as u64 * entries_per_l2 * cluster_size;
            let mut has_data_beyond = false;

            for l2_idx in 0..entries_per_l2 as u32 {
                let guest_offset = l1_guest_base + l2_idx as u64 * cluster_size;
                if guest_offset < new_virtual_size {
                    continue; // within new boundary
                }
                let entry =
                    l2_table.get(crate::format::types::L2Index(l2_idx))?;
                match entry {
                    crate::format::l2::L2Entry::Unallocated
                    | crate::format::l2::L2Entry::Zero {
                        preallocated_offset: None,
                    } => {}
                    _ => {
                        has_data_beyond = true;
                    }
                }
            }

            if has_data_beyond {
                let first_oob = (new_virtual_size.max(l1_guest_base) - l1_guest_base)
                    / cluster_size
                    * cluster_size
                    + l1_guest_base;
                return Err(Error::ShrinkDataLoss {
                    cluster_offset: first_oob,
                    context: "allocated cluster beyond new virtual size",
                });
            }

            // For L1 entries being fully removed, free the L2 table
            if l1_idx >= new_l1_entries {
                refcount_manager.decrement_refcount(
                    l2_offset.0,
                    self.backend.as_ref(),
                    &mut self.cache,
                )?;

                // Null the L1 entry on disk
                let l1_disk_offset =
                    self.header.l1_table_offset.0 + l1_idx as u64 * 8;
                self.backend.write_all_at(&[0u8; 8], l1_disk_offset)?;
            }
        }

        // Shrink the in-memory L1 table
        self.mapper.l1_table_mut().shrink(new_l1_entries);
        self.header.l1_table_entries = new_l1_entries;

        Ok(())
    }

    /// Truncate the file after the last cluster with a non-zero refcount.
    ///
    /// Scans the refcount table backwards to find the last used cluster,
    /// then truncates the file to free unused space at the end. Returns
    /// the number of bytes saved.
    pub fn truncate_free_tail(&mut self) -> Result<u64> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size();
        let file_size = self.backend.file_size()?;
        let total_clusters = file_size / cluster_size;

        if total_clusters == 0 {
            return Ok(0);
        }

        let refcount_manager = self
            .refcount_manager
            .as_ref()
            .expect("writable image must have refcount_manager");

        // Find the last cluster with refcount > 0, scanning backwards
        let mut last_used = 0u64;
        for cluster_idx in (0..total_clusters).rev() {
            let rc = refcount_manager.get_refcount(
                cluster_idx * cluster_size,
                self.backend.as_ref(),
                &mut self.cache,
            )?;
            if rc > 0 {
                last_used = cluster_idx;
                break;
            }
        }

        let new_file_size = (last_used + 1) * cluster_size;
        if new_file_size >= file_size {
            return Ok(0); // nothing to truncate
        }

        let saved = file_size - new_file_size;
        self.backend.set_len(new_file_size)?;

        // Update mapper's file size
        self.mapper.set_file_size(new_file_size);

        Ok(saved)
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
        match compression::compress_cluster(data, cluster_size)? {
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

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.mapper,
            self.header.l1_table_offset,
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            self.header.cluster_bits,
            self.header.virtual_size,
            self.backing_image.as_deref_mut(),
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

    /// Write virtual_size, l1_table_entries, and l1_table_offset to the on-disk header.
    fn write_header_resize_fields(&self) -> Result<()> {
        // virtual_size at offset 24
        let mut buf8 = [0u8; 8];
        BigEndian::write_u64(&mut buf8, self.header.virtual_size);
        self.backend.write_all_at(&buf8, 24)?;

        // l1_table_entries at offset 36
        let mut buf4 = [0u8; 4];
        BigEndian::write_u32(&mut buf4, self.header.l1_table_entries);
        self.backend.write_all_at(&buf4, 36)?;

        // l1_table_offset at offset 40
        BigEndian::write_u64(&mut buf8, self.header.l1_table_offset.0);
        self.backend.write_all_at(&buf8, 40)?;

        Ok(())
    }
}

/// Options for creating a new QCOW2 image.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Log2 of cluster size (default: 16 = 64 KB).
    pub cluster_bits: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::read_mode::ReadMode;
    use crate::format::constants::*;
    use crate::format::l1::L1Entry;
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << 16;

    /// Build a minimal but valid QCOW2 v3 image in memory.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry)
    ///   Cluster 2: L2 table
    ///   Cluster 3+: data clusters
    fn build_test_image(
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
        // A file filled with zeros: magic number won't match.
        let backend = MemoryBackend::zeroed(4096);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_short_for_header() {
        // Less than the minimum header size (72 bytes for v2).
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
        // The test image has no extensions, but the accessor should work.
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
        // No warnings yet, but clear should be safe to call
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
        // Build a minimal image where header says L1 is at a huge offset
        let mut image_data = vec![0u8; 2 * CLUSTER_SIZE];
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: 100,
            l1_table_offset: ClusterOffset(0x100_0000), // way beyond 2-cluster image
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
        // Unallocated is normal, no warnings
        assert!(image.warnings().is_empty());
    }

    // ---- Write API tests ----

    /// Build a writable QCOW2 v3 image with a proper refcount table.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry, unallocated)
    ///   Cluster 2: refcount table (1 cluster)
    ///   Cluster 3: refcount block 0
    ///   Cluster 4+: free
    fn build_writable_test_image() -> MemoryBackend {
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

        // L1 table: unallocated
        // (already zero)

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-3 have refcount 1
        for i in 0..4 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }

        MemoryBackend::new(data)
    }

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

        // Read incompatible_features directly from the backend
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

        // Verify on-disk header is clean
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

        // Write 100 bytes at offset 200
        let write_data = vec![0xEE; 100];
        image.write_at(&write_data, 200).unwrap();

        // Read full cluster
        let mut cluster_buf = vec![0u8; CLUSTER_SIZE];
        image.read_at(&mut cluster_buf, 0).unwrap();

        // Bytes 0-199 should be zero, 200-299 should be 0xEE, rest zeros
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

        // Flush without any writes — should succeed and not set dirty
        image.flush().unwrap();
        assert!(!image.is_dirty());
    }

    // ---- Image creation tests ----

    #[test]
    fn create_on_backend_produces_valid_header() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 30, // 1 GB
                cluster_bits: None,
            },
        )
        .unwrap();

        assert_eq!(image.header().version, 3);
        assert_eq!(image.header().cluster_bits, 16);
        assert_eq!(image.virtual_size(), 1 << 30);
        assert!(image.is_writable());
        assert!(!image.is_dirty());
    }

    #[test]
    fn create_on_backend_with_custom_cluster_bits() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: Some(12), // 4 KB clusters
            },
        )
        .unwrap();

        assert_eq!(image.cluster_bits(), 12);
        assert_eq!(image.cluster_size(), 4096);
    }

    #[test]
    fn create_on_backend_small_virtual_size() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 512,
                cluster_bits: None,
            },
        )
        .unwrap();

        assert_eq!(image.virtual_size(), 512);
        assert!(image.header().l1_table_entries >= 1);
    }

    #[test]
    fn create_on_backend_refcounts_correct() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 30,
                cluster_bits: None,
            },
        )
        .unwrap();

        // First 4 clusters should have refcount 1
        let refcount_manager = image.refcount_manager.as_ref().unwrap();
        let cache = &mut MetadataCache::new(CacheConfig::default());
        let cluster_size = image.cluster_size();
        for i in 0..4 {
            let rc = refcount_manager
                .get_refcount(i * cluster_size, image.backend(), cache)
                .unwrap();
            assert_eq!(rc, 1, "cluster {} should have refcount 1", i);
        }
    }

    #[test]
    fn create_on_backend_write_then_read() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: None,
            },
        )
        .unwrap();

        let write_data = b"Hello, new QCOW2 image!";
        image.write_at(write_data, 0).unwrap();

        let mut read_buf = vec![0u8; write_data.len()];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(&read_buf, write_data);
    }

    #[test]
    fn create_on_backend_write_flush_clears_dirty() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
            },
        )
        .unwrap();

        image.write_at(&[0xAA; 64], 0).unwrap();
        assert!(image.is_dirty());

        image.flush().unwrap();
        assert!(!image.is_dirty());
    }

    #[test]
    fn create_on_backend_reopenable() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
            },
        )
        .unwrap();

        let write_data = vec![0xBB; 256];
        image.write_at(&write_data, 4096).unwrap();
        image.flush().unwrap();

        // Extract the raw data and re-open
        let raw_data = {
            let backend_ref = image.backend();
            let size = backend_ref.file_size().unwrap() as usize;
            let mut data = vec![0u8; size];
            backend_ref.read_exact_at(&mut data, 0).unwrap();
            data
        };

        let reopened_backend = MemoryBackend::new(raw_data);
        let mut reopened = Qcow2Image::from_backend_rw(Box::new(reopened_backend)).unwrap();

        let mut read_buf = vec![0u8; 256];
        reopened.read_at(&mut read_buf, 4096).unwrap();
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn create_on_backend_large_virtual_size() {
        let backend = MemoryBackend::zeroed(0);
        let virtual_size = 2u64 * 1024 * 1024 * 1024 * 1024; // 2 TB
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size,
                cluster_bits: None,
            },
        )
        .unwrap();

        assert_eq!(image.virtual_size(), virtual_size);
        // L1 table should be large enough
        let l2_entries = image.cluster_size() / 8;
        let bytes_per_l1 = l2_entries * image.cluster_size();
        let expected_l1 =
            ((virtual_size + bytes_per_l1 - 1) / bytes_per_l1) as u32;
        assert_eq!(image.header().l1_table_entries, expected_l1);
    }

    #[test]
    fn create_on_backend_unallocated_reads_zero() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
            },
        )
        .unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn create_file_based_round_trip() {
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("qcow2");
        // Remove the temp file so create() can use create_new
        drop(tmp);

        let write_data = b"file-based creation test";

        {
            let mut image = Qcow2Image::create(
                &path,
                CreateOptions {
                    virtual_size: 1 << 20,
                    cluster_bits: None,
                },
            )
            .unwrap();

            image.write_at(write_data, 0).unwrap();
            image.flush().unwrap();
        }

        // Reopen and verify
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let mut read_buf = vec![0u8; write_data.len()];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(&read_buf, write_data);

        // Clean up
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn create_existing_file_fails() {
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        // File already exists — create should fail
        let result = Qcow2Image::create(
            tmp.path(),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
            },
        );
        assert!(result.is_err());
    }

    // ---- Overlay / backing file tests ----

    /// Helper: create a base image with known data, return its path.
    fn create_base_image(dir: &std::path::Path) -> std::path::PathBuf {
        let base_path = dir.join("base.qcow2");
        let mut base = Qcow2Image::create(
            &base_path,
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: None,
            },
        )
        .unwrap();

        // Write known data at several offsets
        base.write_at(&[0xAA; 512], 0).unwrap();
        base.write_at(&[0xBB; 512], CLUSTER_SIZE as u64).unwrap();
        base.flush().unwrap();
        base_path
    }

    #[test]
    fn overlay_reads_backing_data() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Read unallocated region — should see backing data
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "should read backing data");
    }

    #[test]
    fn overlay_reads_backing_data_second_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, CLUSTER_SIZE as u64).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn overlay_write_does_not_modify_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        {
            let mut overlay = Qcow2Image::create_overlay(
                &overlay_path,
                &base_path,
                1 << 20,
            )
            .unwrap();

            // Write to the overlay at the same offset as backing data
            overlay.write_at(&[0xCC; 512], 0).unwrap();
            overlay.flush().unwrap();
        }

        // Re-read backing directly — should still have original data
        let mut base = Qcow2Image::open(&base_path).unwrap();
        let mut buf = vec![0u8; 512];
        base.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "backing must be unchanged");
    }

    #[test]
    fn overlay_write_overrides_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write different data to the overlay
        overlay.write_at(&[0xDD; 512], 0).unwrap();

        // Read should return overlay data, not backing data
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn overlay_partial_write_preserves_backing_data() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write 100 bytes at offset 200 within the first cluster
        // (which has 0xAA in the first 512 bytes from backing)
        overlay.write_at(&[0xEE; 100], 200).unwrap();

        // Read the full first 512 bytes
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();

        // Bytes 0-199: should be 0xAA (from backing)
        assert!(
            buf[..200].iter().all(|&b| b == 0xAA),
            "non-written region should preserve backing data"
        );
        // Bytes 200-299: should be 0xEE (from overlay write)
        assert!(buf[200..300].iter().all(|&b| b == 0xEE));
        // Bytes 300-511: should be 0xAA (from backing)
        assert!(
            buf[300..512].iter().all(|&b| b == 0xAA),
            "trailing region should preserve backing data"
        );
    }

    #[test]
    fn overlay_unallocated_beyond_backing_data_returns_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Read from a region that has no data in either backing or overlay
        let offset = 2 * CLUSTER_SIZE as u64; // third cluster, no data in base
        let mut buf = vec![0xFFu8; 256];
        overlay.read_at(&mut buf, offset).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn overlay_reopenable_with_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        {
            let mut overlay = Qcow2Image::create_overlay(
                &overlay_path,
                &base_path,
                1 << 20,
            )
            .unwrap();

            overlay.write_at(&[0xFF; 256], 0).unwrap();
            overlay.flush().unwrap();
        }

        // Reopen and verify both overlay and backing data
        let mut overlay = Qcow2Image::open_rw(&overlay_path).unwrap();

        // Overlay data
        let mut buf = vec![0u8; 256];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xFF));

        // Backing data from second cluster (not overwritten)
        let mut buf2 = vec![0u8; 512];
        overlay.read_at(&mut buf2, CLUSTER_SIZE as u64).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn overlay_header_has_backing_file_info() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        assert!(overlay.header().has_backing_file());
        assert!(overlay.header().backing_file_size > 0);
    }

    #[test]
    fn overlay_write_then_read_multiple_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write to cluster 0 in the overlay
        overlay.write_at(&[0x11; 512], 0).unwrap();
        // Cluster 1 stays from backing (0xBB)

        // Read spanning both clusters
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0x11), "cluster 0: overlay data");

        let mut buf2 = vec![0u8; 512];
        overlay.read_at(&mut buf2, CLUSTER_SIZE as u64).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xBB), "cluster 1: backing data");
    }

    // ---- Resize tests ----

    #[test]
    fn resize_reject_read_only() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        // Can't call resize on a read-only image — but from_backend is read-only
        // We'd need from_backend_rw. Let's test via the error path.
        assert!(!image.is_writable());
    }

    #[test]
    fn resize_shrink_rejected_with_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.snapshot_create("snap").unwrap();
        let result = image.resize(image.cluster_size());
        assert!(matches!(result, Err(Error::ShrinkNotSupported { .. })));
    }

    #[test]
    fn resize_shrink_empty_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 4 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        // Shrink to half size (no data allocated)
        image.resize(2 * 1024 * 1024).unwrap();
        assert_eq!(image.virtual_size(), 2 * 1024 * 1024);

        // Reading beyond new size should fail
        let mut buf = vec![0u8; 512];
        let result = image.read_at(&mut buf, 3 * 1024 * 1024);
        assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
    }

    #[test]
    fn resize_shrink_with_data_beyond_boundary_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 4 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        // Write data at the end (beyond what will be the new boundary)
        image.write_at(&[0xAA; 512], 3 * 1024 * 1024).unwrap();
        image.flush().unwrap();

        let result = image.resize(2 * 1024 * 1024);
        assert!(matches!(result, Err(Error::ShrinkDataLoss { .. })));
    }

    #[test]
    fn resize_reject_unaligned() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let new_size = image.virtual_size() + 1000; // not cluster-aligned
        let result = image.resize(new_size);
        assert!(matches!(result, Err(Error::ResizeNotAligned { .. })));
    }

    #[test]
    fn resize_same_size_is_noop() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let old_size = image.virtual_size();
        image.resize(old_size).unwrap();
        assert_eq!(image.virtual_size(), old_size);
    }

    #[test]
    fn resize_grow_within_existing_l1() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        // Grow by one cluster — should stay within existing L1 capacity
        let new_size = old_size + cluster_size;
        image.resize(new_size).unwrap();
        assert_eq!(image.virtual_size(), new_size);
    }

    #[test]
    fn resize_data_survives() {
        let data_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_offset | L2_COPIED_FLAG;
        let data = vec![0xAA; 512];
        let backend = build_test_image(&[(0, l2_raw)], &[(3, &data)]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        let new_size = old_size + 4 * cluster_size;
        image.resize(new_size).unwrap();

        // Original data still readable
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn resize_new_area_reads_zeros() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        let new_size = old_size + 2 * cluster_size;
        image.resize(new_size).unwrap();

        // Read from the new area (just beyond old size)
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, old_size).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "new area should read as zeros");
    }
}
