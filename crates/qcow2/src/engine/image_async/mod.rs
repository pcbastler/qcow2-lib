//! Thread-safe parallel I/O wrapper for QCOW2 images.
//!
//! [`Qcow2ImageAsync`] wraps a [`Qcow2Image`] with per-L2 `RwLock`s and a
//! global `Mutex<ImageMeta>` to allow safe concurrent reads and writes from
//! multiple threads. The metadata mutex is held only for microseconds
//! (cluster resolution), never during data I/O.
//!
//! # Concurrency
//!
//! | Thread A | Thread B | Same L2? | Behavior |
//! |----------|----------|----------|----------|
//! | Read | Read | yes | Parallel (shared lock) |
//! | Read | Read | no | Parallel |
//! | Read | Write | yes | Write waits |
//! | Read | Write | no | Parallel |
//! | Write | Write | yes | Serialized |
//! | Write | Write | no | Parallel |

use std::sync::{Mutex, RwLock};

use crate::engine::compression;
use crate::engine::image::Qcow2Image;
use crate::engine::image_meta::ImageMeta;
use crate::engine::reader::Qcow2Reader;
use crate::engine::writer::Qcow2Writer;
use crate::error::{Error, IoErrorKind, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::io::IoBackend;

/// Helper to create a lock-poisoned error.
fn poisoned_err() -> Error {
    Error::Io {
        kind: IoErrorKind::Other,
        message: "lock poisoned".into(),
        offset: 0,
        context: "Qcow2ImageAsync lock acquisition",
    }
}

/// Zero-cost adapter: implements `BackingImage` (`&mut self`) by delegating
/// to `Qcow2ImageAsync::read_at` (`&self`). Lives on the stack, no allocation.
struct AsyncBackingAdapter<'a>(&'a Qcow2ImageAsync);

impl crate::io::BackingImage for AsyncBackingAdapter<'_> {
    fn virtual_size(&self) -> u64 {
        self.0.virtual_size().unwrap_or(0)
    }

    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        self.0.read_at(buf, guest_offset)
    }
}

/// Thread-safe QCOW2 image supporting parallel reads and writes.
///
/// Created from a [`Qcow2Image`] via [`from_image`](Self::from_image) and can
/// be converted back via [`into_image`](Self::into_image). All methods take
/// `&self` — concurrent access is safe through internal locking.
pub struct Qcow2ImageAsync {
    /// Global metadata state, held ~1-5 µs per operation.
    meta: Mutex<ImageMeta>,
    /// Per-L2 table locks (one per L1 index = per 512 MB guest range at 64K clusters).
    l2_locks: Vec<RwLock<()>>,
    /// Main I/O backend (metadata + data unless external data file).
    backend: Box<dyn IoBackend>,
    /// Separate I/O backend for guest data when using an external data file.
    data_backend: Option<Box<dyn IoBackend>>,
    /// Encryption context for encrypted images.
    crypt_context: Option<crate::engine::encryption::CryptContext>,
    /// Compression backend.
    compressor: compression::StdCompressor,
    /// Cached cluster_bits from header (immutable after open).
    cluster_bits: u32,
    /// Cached extended_l2 flag from header (immutable after open).
    extended_l2: bool,
    /// Backing image for unallocated cluster fallback (recursively async).
    backing: Option<Box<Qcow2ImageAsync>>,
}

// SAFETY: IoBackend is Send + Sync, Mutex/RwLock handle thread safety.
unsafe impl Send for Qcow2ImageAsync {}
unsafe impl Sync for Qcow2ImageAsync {}

impl Qcow2ImageAsync {
    /// Create a thread-safe image from an existing `Qcow2Image`.
    ///
    /// If the image has a backing file, it is recursively converted to
    /// a `Qcow2ImageAsync` so backing reads are also parallel.
    pub fn from_image(image: Qcow2Image) -> Result<Self> {
        let (meta, backend, data_backend, _backing_chain, backing_image, crypt_context, compressor) =
            image.into_parts();

        let backing = match backing_image {
            Some(img) => Some(Box::new(Qcow2ImageAsync::from_image(*img)?)),
            None => None,
        };

        let cluster_bits = meta.header.cluster_bits;
        let extended_l2 = meta.mapper.geometry().extended_l2;
        let l1_len = meta.mapper.l1_table().len() as usize;
        let l2_locks: Vec<RwLock<()>> = (0..l1_len).map(|_| RwLock::new(())).collect();

        Ok(Self {
            meta: Mutex::new(meta),
            l2_locks,
            backend,
            data_backend,
            crypt_context,
            compressor,
            cluster_bits,
            extended_l2,
            backing,
        })
    }

    /// Convert back to a single-threaded `Qcow2Image`.
    pub fn into_image(self) -> Qcow2Image {
        // Use ManuallyDrop to prevent Drop from running, then extract fields.
        let me = std::mem::ManuallyDrop::new(self);

        // Safety: we take ownership of each field exactly once and never use `me` again.
        let meta = unsafe { std::ptr::read(&me.meta) }
            .into_inner()
            .expect("mutex poisoned");
        let backend = unsafe { std::ptr::read(&me.backend) };
        let data_backend = unsafe { std::ptr::read(&me.data_backend) };
        let crypt_context = unsafe { std::ptr::read(&me.crypt_context) };
        let compressor = unsafe { std::ptr::read(&me.compressor) };
        let backing = unsafe { std::ptr::read(&me.backing) };

        let backing_image = backing.map(|b| Box::new(b.into_image()));

        Qcow2Image::from_parts(
            meta,
            backend,
            data_backend,
            None, // backing_chain
            backing_image,
            crypt_context,
            compressor,
        )
    }

    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Multiple reads to different L2 ranges run in parallel.
    /// Reads to the same L2 range as a concurrent write will wait.
    pub fn read_at(&self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        // RAW_EXTERNAL: identity-mapped reads bypass L2 entirely
        if let Some(ref data_be) = self.data_backend {
            return data_be.read_exact_at(buf, guest_offset);
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left);
            let (chunk, rest) = remaining.split_at_mut(chunk_size);

            self.read_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Read a single chunk within one L2 range.
    fn read_chunk(
        &self,
        buf: &mut [u8],
        guest_offset: u64,
    ) -> Result<()> {
        let l1_index = self.l1_index_for(guest_offset);

        // Hold L2 read lock during the entire read (prevents use-after-free)
        let _l2_guard = if l1_index < self.l2_locks.len() {
            Some(self.l2_locks[l1_index].read().map_err(|_| poisoned_err())?)
        } else {
            None
        };

        // Lock meta to resolve cluster mapping + perform I/O
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;

        let mut backing_adapter = self.backing.as_deref().map(AsyncBackingAdapter);
        let mut reader = Qcow2Reader::new(
            &meta_ref.mapper,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut meta_ref.cache,
            self.cluster_bits,
            meta_ref.header.virtual_size,
            meta_ref.header.compression_type,
            meta_ref.read_mode,
            &mut meta_ref.warnings,
            backing_adapter.as_mut().map(|a| a as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        reader.read_at(buf, guest_offset)?;

        drop(meta);
        Ok(())
    }

    /// Write `buf` starting at the given guest offset.
    ///
    /// Multiple writes to different L2 ranges run in parallel.
    /// Writes to the same L2 range are serialized.
    pub fn write_at(&self, buf: &[u8], guest_offset: u64) -> Result<()> {
        {
            let meta_guard = self.meta.lock().map_err(|_| poisoned_err())?;
            if !meta_guard.writable {
                return Err(Error::ReadOnly);
            }
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left);
            let (chunk, rest) = remaining.split_at(chunk_size);

            self.write_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Write a single chunk within one L2 range.
    fn write_chunk(
        &self,
        buf: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        let l1_index = self.l1_index_for(guest_offset);

        // Hold L2 write lock (exclusive) for the entire write
        let _l2_guard = if l1_index < self.l2_locks.len() {
            Some(self.l2_locks[l1_index].write().map_err(|_| poisoned_err())?)
        } else {
            None
        };

        // Lock meta for the entire write operation
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;

        // Set dirty flag on first write
        if !meta.dirty {
            Self::mark_dirty_inner(&mut meta, self.backend.as_ref())?;
        }

        let raw_external = self.data_backend.is_some();
        let data_be: &dyn IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };

        // Destructure meta to satisfy the borrow checker — we need simultaneous
        // mutable borrows of mapper, cache, and refcount_manager.
        let meta_ref = &mut *meta;
        let refcount_manager = meta_ref
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut backing_adapter = self.backing.as_deref().map(AsyncBackingAdapter);
        let mut writer = Qcow2Writer::new(
            &mut meta_ref.mapper,
            meta_ref.header.l1_table_offset,
            self.backend.as_ref(),
            data_be,
            &mut meta_ref.cache,
            refcount_manager,
            meta_ref.header.cluster_bits,
            meta_ref.header.virtual_size,
            meta_ref.header.compression_type,
            raw_external,
            backing_adapter.as_mut().map(|a| a as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.write_at(buf, guest_offset)?;

        drop(meta);
        Ok(())
    }

    /// Write a cluster, attempting compression first.
    ///
    /// Compression runs **outside** any lock (CPU-bound parallelism).
    /// The compressed data is then written under the meta mutex with full
    /// packing support (`compressed_cursor`), so space efficiency is preserved.
    ///
    /// `guest_offset` must be cluster-aligned and `data.len()` must equal
    /// the cluster size.
    pub fn write_cluster_maybe_compressed(
        &self,
        data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        let cluster_size = 1usize << self.cluster_bits;
        let compression_type = {
            let meta = self.meta.lock().map_err(|_| poisoned_err())?;
            meta.header.compression_type
        };

        // Compress OUTSIDE the lock — this is the CPU-bound work that
        // benefits from parallelism.
        match compression::compress_cluster(data, cluster_size, compression_type)? {
            Some(compressed) => self.write_compressed_chunk(&compressed, guest_offset),
            None => self.write_chunk(data, guest_offset),
        }
    }

    /// Write pre-compressed data as a compressed cluster.
    ///
    /// Holds the L2 write lock and meta mutex for the entire operation
    /// (allocation + write + L2 update + cursor advance). The data written
    /// is small (compressed), so the lock duration is brief.
    fn write_compressed_chunk(
        &self,
        compressed_data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        let l1_index = self.l1_index_for(guest_offset);

        // Hold L2 write lock (exclusive) for the entire write
        let _l2_guard = if l1_index < self.l2_locks.len() {
            Some(self.l2_locks[l1_index].write().map_err(|_| poisoned_err())?)
        } else {
            None
        };

        // Lock meta for the entire compressed write operation
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;

        if !meta.writable {
            return Err(Error::ReadOnly);
        }

        // Set dirty flag on first write
        if !meta.dirty {
            Self::mark_dirty_inner(&mut meta, self.backend.as_ref())?;
        }

        if self.data_backend.is_some() {
            return Err(Error::CompressedWithExternalData);
        }
        if self.crypt_context.is_some() {
            return Err(Error::EncryptionWithCompression);
        }

        let meta_ref = &mut *meta;
        let refcount_manager = meta_ref
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut backing_adapter = self.backing.as_deref().map(AsyncBackingAdapter);
        let mut writer = Qcow2Writer::new(
            &mut meta_ref.mapper,
            meta_ref.header.l1_table_offset,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            meta_ref.header.cluster_bits,
            meta_ref.header.virtual_size,
            meta_ref.header.compression_type,
            false, // no external data file for compressed
            backing_adapter.as_mut().map(|a| a as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.set_compressed_cursor(meta_ref.compressed_cursor);
        let result = writer.write_compressed_at(compressed_data, guest_offset);
        meta_ref.compressed_cursor = writer.compressed_cursor();
        result
    }

    /// Flush all dirty cached metadata to disk and clear the DIRTY flag.
    pub fn flush(&self) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;

        if !meta.writable {
            return Err(Error::ReadOnly);
        }

        let meta_ref = &mut *meta;
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        self.backend.flush()?;

        if meta.dirty {
            Self::clear_dirty_inner(&mut meta, self.backend.as_ref())?;
        }

        Ok(())
    }

    /// The parsed image header (cloned, since access requires locking).
    pub fn header(&self) -> Result<Header> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.clone())
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> Result<u64> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.virtual_size)
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> Result<u64> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.cluster_size())
    }

    // ---- Hash API ----

    /// Whether the image has a BLAKE3 hash extension.
    pub fn has_hashes(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.has_hashes)
    }

    /// Get summary info about the hash extension.
    pub fn hash_info(&self) -> Result<Option<crate::engine::hash_manager::HashInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        use crate::engine::hash_manager;
        use crate::format::feature_flags::AutoclearFeatures;
        use crate::format::header_extension::HeaderExtension;

        if !hash_manager::detect_hashes(&meta.extensions) {
            return Ok(None);
        }
        let ext = meta.extensions.iter().find_map(|e| match e {
            HeaderExtension::Blake3Hashes(ext) => Some(ext),
            _ => None,
        });
        match ext {
            Some(ext) => {
                let resolved_bits = if ext.hash_chunk_bits == 0 {
                    crate::format::constants::BLAKE3_DEFAULT_HASH_CHUNK_BITS
                } else {
                    ext.hash_chunk_bits
                };
                Ok(Some(hash_manager::HashInfo {
                    hash_size: ext.hash_size,
                    hash_table_entries: ext.hash_table_entries,
                    consistent: meta
                        .header
                        .autoclear_features
                        .contains(AutoclearFeatures::BLAKE3_HASHES),
                    hash_chunk_bits: resolved_bits,
                }))
            }
            None => unreachable!(),
        }
    }

    /// Get the stored hash for a specific hash chunk index.
    pub fn hash_get(&self, hash_chunk_index: u64) -> Result<Option<Vec<u8>>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.get_hash(hash_chunk_index)
    }

    /// Export hashes for a range of guest bytes (or all if range is None).
    pub fn hash_export(&self, range: Option<(u64, u64)>) -> Result<Vec<crate::engine::hash_manager::HashEntry>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.export_hashes(range)
    }

    /// Verify all stored hashes. Returns a list of mismatches (empty = all OK).
    pub fn hash_verify(&self) -> Result<Vec<crate::engine::hash_manager::HashMismatch>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.verify()
    }

    /// Initialize the BLAKE3 per-hash-chunk hash extension.
    pub fn hash_init(&self, hash_size: Option<u8>, hash_chunk_bits: Option<u8>) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let hs = hash_size.unwrap_or(crate::format::constants::BLAKE3_DEFAULT_HASH_SIZE);
        let hcb = hash_chunk_bits.unwrap_or(0);

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.init_hashes(hs, hcb)?;
        meta_ref.has_hashes = true;
        Ok(())
    }

    /// Rehash all allocated clusters. Returns the number of clusters hashed.
    pub fn hash_rehash(&self) -> Result<u64> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.rehash()
    }

    /// Remove the hash extension and free all hash clusters.
    pub fn hash_remove(&self) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::hash_manager::HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.remove_hashes()?;
        meta_ref.has_hashes = false;
        Ok(())
    }

    // ---- Snapshot API ----

    /// List all snapshots in the image.
    pub fn snapshot_list(&self) -> Result<Vec<crate::engine::snapshot_manager::SnapshotInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;

        if meta.header.snapshot_count == 0 {
            return Ok(Vec::new());
        }

        let cluster_size = 1u64 << meta.header.cluster_bits;
        let max_bytes = ((meta.header.snapshot_count as u64) * 1024).min(16 * cluster_size);
        let file_size = self.backend.file_size()?;
        let available = file_size.saturating_sub(meta.header.snapshots_offset.0);
        let read_size = (max_bytes as usize).min(available as usize);

        let mut buf = vec![0u8; read_size];
        self.backend.read_exact_at(&mut buf, meta.header.snapshots_offset.0)?;

        let snapshots = crate::format::snapshot::SnapshotHeader::read_table(
            &buf,
            meta.header.snapshot_count,
            meta.header.snapshots_offset.0,
        )?;

        Ok(snapshots
            .into_iter()
            .map(|s| crate::engine::snapshot_manager::SnapshotInfo {
                id: s.unique_id,
                name: s.name,
                virtual_size: s.virtual_disk_size,
                timestamp_seconds: s.timestamp_seconds,
                l1_table_entries: s.l1_table_entries,
            })
            .collect())
    }

    /// Create a named snapshot of the current image state.
    pub fn snapshot_create(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        // Flush dirty metadata so snapshot sees current on-disk state
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = crate::engine::snapshot_manager::SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        mgr.create_snapshot(name, timestamp)
    }

    /// Delete a snapshot by name or ID.
    pub fn snapshot_delete(&self, name_or_id: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = crate::engine::snapshot_manager::SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        mgr.delete_snapshot(name_or_id)
    }

    /// Revert to a snapshot's state.
    pub fn snapshot_apply(&self, name_or_id: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = crate::engine::snapshot_manager::SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        mgr.apply_snapshot(name_or_id)?;

        meta_ref.has_hashes = crate::engine::hash_manager::detect_hashes(&meta_ref.extensions);
        Ok(())
    }

    // ---- Bitmap API ----

    /// List all persistent bitmaps in the image.
    pub fn bitmap_list(&self) -> Result<Vec<crate::engine::bitmap_manager::BitmapInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;

        let ext = match meta.extensions.iter().find_map(|e| match e {
            crate::format::header_extension::HeaderExtension::Bitmaps(b) => Some(b),
            _ => None,
        }) {
            Some(ext) => ext,
            None => return Ok(Vec::new()),
        };

        if ext.nb_bitmaps == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; ext.bitmap_directory_size as usize];
        self.backend.read_exact_at(&mut buf, ext.bitmap_directory_offset)?;

        let entries = crate::format::bitmap::BitmapDirectoryEntry::read_directory(&buf, ext.nb_bitmaps)?;
        Ok(entries
            .iter()
            .map(|e| crate::engine::bitmap_manager::BitmapInfo {
                name: e.name.clone(),
                granularity: e.granularity(),
                granularity_bits: e.granularity_bits,
                in_use: e.is_in_use(),
                auto: e.is_auto(),
                bitmap_type: e.bitmap_type,
                table_size: e.bitmap_table_size,
            })
            .collect())
    }

    /// Create a new persistent bitmap.
    pub fn bitmap_create(&self, name: &str, granularity_bits: Option<u8>, auto: bool) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let granularity = granularity_bits.unwrap_or(crate::format::constants::BITMAP_DEFAULT_GRANULARITY_BITS);
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.create_bitmap(name, granularity, auto)?;
        if auto {
            meta_ref.has_auto_bitmaps = true;
        }
        Ok(())
    }

    /// Delete a persistent bitmap by name.
    pub fn bitmap_delete(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.delete_bitmap(name)?;

        // Re-check auto-bitmap flag
        meta_ref.has_auto_bitmaps = crate::engine::image::Qcow2Image::detect_auto_bitmaps(self.backend.as_ref(), &meta_ref.extensions);
        Ok(())
    }

    /// Query whether a specific guest offset is dirty in a bitmap.
    pub fn bitmap_get_dirty(&self, name: &str, guest_offset: u64) -> Result<bool> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.get_dirty(name, guest_offset)
    }

    /// Mark a range of guest offsets as dirty in a bitmap.
    pub fn bitmap_set_dirty(&self, name: &str, guest_offset: u64, len: u64) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.set_dirty(name, guest_offset, len)
    }

    /// Clear all dirty bits in a bitmap.
    pub fn bitmap_clear(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.clear_bitmap(name)
    }

    /// Enable auto-tracking on a bitmap.
    pub fn bitmap_enable_tracking(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.enable_tracking(name)?;
        meta_ref.has_auto_bitmaps = true;
        Ok(())
    }

    /// Disable auto-tracking on a bitmap.
    pub fn bitmap_disable_tracking(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = crate::engine::bitmap_manager::BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.disable_tracking(name)?;

        meta_ref.has_auto_bitmaps = crate::engine::image::Qcow2Image::detect_auto_bitmaps(self.backend.as_ref(), &meta_ref.extensions);
        Ok(())
    }

    // ---- Integrity API ----

    /// Check image integrity by verifying all refcounts.
    pub fn check_integrity(&self) -> Result<crate::engine::integrity::IntegrityReport> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if meta.writable {
            let cluster_bits = meta.header.cluster_bits;
            qcow2_core::engine::metadata_io::flush_dirty_metadata(
                self.backend.as_ref(),
                &mut meta.cache,
                cluster_bits,
            )?;
        }
        crate::engine::integrity::check_integrity(self.backend.as_ref(), &meta.header)
    }

    /// Check integrity and optionally repair mismatches.
    pub fn check_and_repair(
        &self,
        mode: Option<crate::engine::integrity::RepairMode>,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let cluster_bits = meta_ref.header.cluster_bits;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            cluster_bits,
        )?;

        let report = crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &meta_ref.header,
        )?;

        if let Some(repair_mode) = mode {
            if !report.is_clean() {
                let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;
                crate::engine::integrity::repair_refcounts(
                    self.backend.as_ref(),
                    &meta_ref.header,
                    refcount_manager,
                    &mut meta_ref.cache,
                    repair_mode,
                )?;
                self.backend.flush()?;
            }
        }

        Ok(report)
    }

    // ---- Additional accessors ----

    /// The parsed extensions list (cloned).
    pub fn extensions(&self) -> Result<Vec<crate::format::header_extension::HeaderExtension>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.extensions.clone())
    }

    /// Whether the image is encrypted.
    pub fn is_encrypted(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.crypt_method != 0)
    }

    /// Whether the image is writable.
    pub fn is_writable(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.writable)
    }

    /// Whether the image has the DIRTY flag set.
    pub fn is_dirty(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.dirty)
    }

    /// Compute L1 index for a guest offset.
    fn l1_index_for(&self, guest_offset: u64) -> usize {
        let l2_entry_shift = if self.extended_l2 { 4 } else { 3 };
        let l2_bits = self.cluster_bits - l2_entry_shift;
        (guest_offset >> (self.cluster_bits as u64 + l2_bits as u64)) as usize
    }

    /// Set DIRTY flag on the on-disk header.
    fn mark_dirty_inner(meta: &mut ImageMeta, backend: &dyn IoBackend) -> Result<()> {
        meta.header.incompatible_features |= IncompatibleFeatures::DIRTY;

        if meta.has_auto_bitmaps
            && meta.header.autoclear_features.contains(AutoclearFeatures::BITMAPS)
        {
            meta.header.autoclear_features -= AutoclearFeatures::BITMAPS;
        }
        if meta.has_hashes
            && meta.header.autoclear_features.contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            meta.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
        }

        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            backend,
            meta.header.incompatible_features,
            meta.header.autoclear_features,
        )?;

        backend.flush()?;
        meta.dirty = true;
        Ok(())
    }

    /// Clear DIRTY flag on the on-disk header.
    fn clear_dirty_inner(meta: &mut ImageMeta, backend: &dyn IoBackend) -> Result<()> {
        meta.header.incompatible_features -= IncompatibleFeatures::DIRTY;

        if meta.has_auto_bitmaps
            && !meta.header.autoclear_features.contains(AutoclearFeatures::BITMAPS)
        {
            meta.header.autoclear_features |= AutoclearFeatures::BITMAPS;
        }
        if meta.has_hashes
            && !meta.header.autoclear_features.contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            meta.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
        }

        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            backend,
            meta.header.incompatible_features,
            meta.header.autoclear_features,
        )?;

        backend.flush()?;
        meta.dirty = false;
        Ok(())
    }
}

impl Drop for Qcow2ImageAsync {
    fn drop(&mut self) {
        if let Ok(mut meta) = self.meta.lock() {
            if meta.writable {
                let cluster_bits = meta.header.cluster_bits;
                let _ = qcow2_core::engine::metadata_io::flush_dirty_metadata(
                    self.backend.as_ref(),
                    &mut meta.cache,
                    cluster_bits,
                );
                let _ = self.backend.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests;
