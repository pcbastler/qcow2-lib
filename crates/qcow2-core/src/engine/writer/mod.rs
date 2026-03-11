//! QCOW2 write engine: translates guest writes into host cluster operations.
//!
//! Handles cluster allocation, L1/L2 table updates, and metadata
//! persistence. In **WriteBack** mode, L2 modifications stay in the cache
//! and are flushed lazily; in **WriteThrough** mode, every L2 update is
//! written to disk immediately. Supports writing to unallocated, zero, and
//! standard (copied) clusters. Compressed clusters are decompressed
//! before applying the write.

mod compressed;
mod data_ops;

extern crate alloc;

use alloc::vec;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::io::Compressor;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, Result};
use crate::format::constants::{L2_ENTRY_SIZE, L2_ENTRY_SIZE_EXTENDED};
use crate::format::l1::L1Entry;
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap};
use crate::format::types::*;
use crate::engine::encryption::CryptContext;
use crate::io::IoBackend;

/// Writes guest data to a QCOW2 image.
///
/// Borrows the mutable state needed for write operations. Created on
/// demand by `Qcow2Image` for each write call.
///
/// When a backing image is provided, partial writes to unallocated
/// clusters read the existing data from the backing image before
/// merging the new data, instead of zero-filling.
pub struct Qcow2Writer<'a> {
    pub(crate) mapper: &'a mut ClusterMapper,
    pub(crate) l1_table_offset: ClusterOffset,
    pub(crate) backend: &'a dyn IoBackend,
    /// Backend for guest data clusters (external data file or same as backend).
    pub(crate) data_backend: &'a dyn IoBackend,
    pub(crate) cache: &'a mut MetadataCache,
    pub(crate) refcount_manager: &'a mut RefcountManager,
    pub(crate) cluster_bits: u32,
    pub(crate) virtual_size: u64,
    pub(crate) compression_type: u8,
    /// When true, data clusters use identity-mapped offsets (host = guest).
    pub(crate) raw_external: bool,
    pub(crate) backing_image: Option<&'a mut dyn crate::io::BackingImage>,
    /// Byte offset for the next compressed write within a shared host cluster.
    /// Zero means no active compressed packing cluster.
    pub(crate) compressed_cursor: u64,
    pub(crate) crypt_context: Option<&'a CryptContext>,
    pub(crate) compressor: &'a dyn Compressor,
}

impl<'a> Qcow2Writer<'a> {
    /// Create a new writer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapper: &'a mut ClusterMapper,
        l1_table_offset: ClusterOffset,
        backend: &'a dyn IoBackend,
        data_backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        cluster_bits: u32,
        virtual_size: u64,
        compression_type: u8,
        raw_external: bool,
        backing_image: Option<&'a mut dyn crate::io::BackingImage>,
        crypt_context: Option<&'a CryptContext>,
        compressor: &'a dyn Compressor,
    ) -> Self {
        Self {
            mapper,
            l1_table_offset,
            backend,
            data_backend,
            cache,
            refcount_manager,
            cluster_bits,
            virtual_size,
            compression_type,
            raw_external,
            backing_image,
            compressed_cursor: 0,
            crypt_context,
            compressor,
        }
    }

    /// Set the compressed packing cursor from a previous write session.
    pub fn set_compressed_cursor(&mut self, cursor: u64) {
        self.compressed_cursor = cursor;
    }

    /// Return the current compressed packing cursor position.
    pub fn compressed_cursor(&self) -> u64 {
        self.compressed_cursor
    }

    // ---- Write dispatch ----

    /// Write `buf` starting at the given guest offset.
    ///
    /// Handles writes that span multiple clusters by splitting them
    /// into per-cluster chunks.
    pub fn write_at(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        let write_end = guest_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            })?;

        if write_end > self.virtual_size {
            return Err(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            });
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left_in_cluster = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left_in_cluster);
            let (chunk, rest) = remaining.split_at(chunk_size);

            self.write_cluster_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Write a chunk of data to a single cluster.
    fn write_cluster_chunk(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        let (l1_index, l2_index, intra) = GuestOffset(guest_offset).split(self.mapper.geometry());
        let cluster_size = 1u64 << self.cluster_bits;

        // Step 1: Ensure L2 table exists
        let l2_offset = self.ensure_l2_table(l1_index)?;

        // Step 2: Read L2 entry (no full table clone needed)
        let l2_entry = self.read_l2_entry(l2_offset, l2_index)?;

        // Step 3: Dispatch on L2 entry type
        let guest_cluster_offset = guest_offset - intra.0 as u64;
        let new_l2_entry = match l2_entry {
            L2Entry::Unallocated => {
                self.write_to_new_cluster(
                    buf, intra, cluster_size, guest_cluster_offset,
                    SubclusterBitmap::all_unallocated(),
                )?
            }
            L2Entry::Zero { preallocated_offset, subclusters } => {
                let result = self.write_to_new_cluster(
                    buf, intra, cluster_size, guest_cluster_offset, subclusters,
                )?;
                if let Some(prealloc) = preallocated_offset {
                    self.refcount_manager.decrement_refcount(
                        prealloc.0, self.backend, self.cache,
                    )?;
                }
                result
            }
            L2Entry::Standard { host_offset, copied, subclusters } => {
                if copied {
                    self.write_in_place(buf, host_offset, intra, cluster_size, subclusters)?
                } else {
                    self.cow_data_cluster(buf, host_offset, intra, cluster_size, subclusters)?
                }
            }
            L2Entry::Compressed(descriptor) => {
                self.write_to_compressed_cluster(buf, descriptor, intra, cluster_size)?
            }
        };

        // Step 4: Update L2 entry on disk if changed
        if new_l2_entry != l2_entry {
            self.write_l2_entry(l2_offset, l2_index, new_l2_entry)?;
        }

        Ok(())
    }

    // ---- L2 table management ----

    /// Ensure an L2 table exists for the given L1 index, allocating one if needed.
    ///
    /// If the L1 entry has the COPIED flag clear (shared with a snapshot),
    /// performs copy-on-write on the L2 table before returning.
    pub(crate) fn ensure_l2_table(&mut self, l1_index: L1Index) -> Result<ClusterOffset> {
        let l1_entry = self.mapper.l1_entry(l1_index)?;

        match l1_entry.l2_table_offset() {
            Some(offset) if l1_entry.is_copied() => return Ok(offset),
            Some(old_offset) => return self.cow_l2_table(l1_index, old_offset),
            None => {}
        }

        // Allocate a new L2 table cluster
        let new_l2_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;

        // Write a zeroed L2 table to disk
        let cluster_size = 1usize << self.cluster_bits;
        let zeroed = vec![0u8; cluster_size];
        self.backend.write_all_at(&zeroed, new_l2_offset.0)?;

        // Update the file size in the mapper (from refcount manager's tracked offset)
        self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);

        // Update L1 entry (with COPIED flag since refcount is 1)
        let new_l1_entry = L1Entry::with_l2_offset(new_l2_offset, true);
        self.mapper.set_l1_entry(l1_index, new_l1_entry)?;

        // Write L1 entry to disk (write-through)
        self.write_l1_entry(l1_index, new_l1_entry)?;

        Ok(new_l2_offset)
    }

    /// Copy-on-write an L2 table shared with a snapshot (L1 COPIED flag clear).
    ///
    /// Allocates a new cluster, copies the L2 table data, decrements the old
    /// cluster's refcount, and updates the L1 entry with the COPIED flag set.
    fn cow_l2_table(
        &mut self,
        l1_index: L1Index,
        old_offset: ClusterOffset,
    ) -> Result<ClusterOffset> {
        let cluster_size = 1usize << self.cluster_bits;

        // Flush dirty L2 to disk before COW reads from disk, otherwise
        // dirty modifications would be lost (the disk read would see stale data).
        self.cache.flush_single_l2(old_offset, |offset, table| {
            let mut buf = vec![0u8; cluster_size];
            // flush_single_l2 only calls us if dirty, ignore write errors
            // (they'll surface on the next explicit write).
            let _ = table.write_to(&mut buf);
            let _ = self.backend.write_all_at(&buf, offset);
        });

        // Read existing L2 table
        let mut l2_data = vec![0u8; cluster_size];
        self.backend.read_exact_at(&mut l2_data, old_offset.0)?;

        // Allocate new cluster for L2 table
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);

        // Write L2 table to new cluster
        self.backend.write_all_at(&l2_data, new_offset.0)?;

        // Decrement refcount of old L2 table
        self.refcount_manager.decrement_refcount(
            old_offset.0,
            self.backend,
            self.cache,
        )?;

        // Update L1 entry: new offset, copied=true
        let new_l1_entry = L1Entry::with_l2_offset(new_offset, true);
        self.mapper.set_l1_entry(l1_index, new_l1_entry)?;
        self.write_l1_entry(l1_index, new_l1_entry)?;

        // Evict old L2 from cache
        self.cache.evict_l2_table(old_offset);

        Ok(new_offset)
    }

    /// Write a single L1 entry to disk (write-through).
    fn write_l1_entry(&self, index: L1Index, entry: L1Entry) -> Result<()> {
        let offset = self.l1_table_offset.0 + (index.0 as u64 * 8);
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, entry.raw());
        self.backend.write_all_at(&buf, offset)?;
        Ok(())
    }

    /// Update a single L2 entry.
    ///
    /// In **WriteBack** mode: modifies the entry in the cache and marks it dirty.
    /// In **WriteThrough** mode: writes to disk and evicts the cache entry (legacy).
    pub(crate) fn write_l2_entry(
        &mut self,
        l2_table_offset: ClusterOffset,
        index: L2Index,
        entry: L2Entry,
    ) -> Result<()> {
        // WriteBack path: modify in-place in cache
        if let Some(cache_entry) = self.cache.get_l2_entry_mut(l2_table_offset) {
            cache_entry.value.set(index, entry)?;
            cache_entry.dirty = true;
            return Ok(());
        }

        // WriteThrough path (or WriteBack cache miss — shouldn't happen after load_l2_table):
        // write entry bytes to disk
        let geo = self.mapper.geometry();
        let entry_size = geo.l2_entry_size() as u64;
        let offset = l2_table_offset.0 + (index.0 as u64 * entry_size);

        if geo.extended_l2 {
            let mut buf = [0u8; L2_ENTRY_SIZE_EXTENDED];
            BigEndian::write_u64(&mut buf[..8], entry.encode(geo));
            BigEndian::write_u64(&mut buf[8..], entry.encode_bitmap());
            self.backend.write_all_at(&buf, offset)?;
        } else {
            let mut buf = [0u8; L2_ENTRY_SIZE];
            BigEndian::write_u64(&mut buf, entry.encode(geo));
            self.backend.write_all_at(&buf, offset)?;
        }

        // Evict so next read reloads the updated table
        self.cache.evict_l2_table(l2_table_offset);
        Ok(())
    }

    /// Read a single L2 entry from cache or disk (no L2Table clone).
    fn read_l2_entry(&mut self, l2_offset: ClusterOffset, index: L2Index) -> Result<L2Entry> {
        if let Some(table) = self.cache.get_l2_table(l2_offset) {
            return table.get(index).map_err(Into::into);
        }
        self.load_l2_table_into_cache(l2_offset)?;
        let table = self.cache.get_l2_table(l2_offset).expect("just inserted");
        table.get(index).map_err(Into::into)
    }

    /// Load an L2 table from disk and insert it into the cache.
    fn load_l2_table_into_cache(&mut self, offset: ClusterOffset) -> Result<()> {
        let cluster_size = 1usize << self.cluster_bits;
        let mut buf = vec![0u8; cluster_size];
        self.backend.read_exact_at(&mut buf, offset.0)?;
        let table = L2Table::read_from(&buf, self.mapper.geometry())?;

        self.cache.insert_l2_table(offset, table, false);
        self.flush_pending_l2_evictions()?;
        Ok(())
    }

    /// Write any dirty L2 tables that were evicted from the cache by LRU pressure.
    fn flush_pending_l2_evictions(&mut self) -> Result<()> {
        let pending = self.cache.take_pending_l2_evictions();
        let cluster_size = 1usize << self.cluster_bits;
        for (offset, table) in &pending {
            let mut buf = vec![0u8; cluster_size];
            table.write_to(&mut buf)?;
            self.backend.write_all_at(&buf, *offset)?;
        }
        Ok(())
    }
}
