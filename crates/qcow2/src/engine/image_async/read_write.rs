//! Read, write, flush, and compressed write operations on `Qcow2ImageAsync`.

use crate::engine::compression;
use crate::engine::reader::Qcow2Reader;
use crate::engine::writer::Qcow2Writer;
use crate::error::{Error, Result};
use crate::io::IoBackend;

use super::{poisoned_err, AsyncBackingAdapter, Qcow2ImageAsync};

impl Qcow2ImageAsync {
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
    pub(super) fn write_chunk(
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
}
