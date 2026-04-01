//! Cluster allocation and refcount management.
//!
//! The [`RefcountManager`] tracks reference counts for every cluster in the
//! image and allocates new clusters for the write path. Two allocation modes
//! are supported via [`AllocationMode`]:
//!
//! - **Append** — always allocates at the end of the file. Simple, fast, no
//!   fragmentation during sequential writes, but never reuses freed clusters.
//! - **Scanning** (default) — scans refcount blocks for clusters with
//!   refcount 0 before falling back to append. Reuses space freed by snapshot
//!   deletes, bitmap removal, hash removal, and similar operations.

extern crate alloc;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use crate::engine::cache::MetadataCache;
use crate::error::{Error, Result};
use crate::format::constants::REFCOUNT_TABLE_ENTRY_SIZE;
use crate::format::header::Header;
use crate::format::refcount::{
    read_refcount_table, write_refcount_table, RefcountBlock, RefcountTableEntry,
};
use crate::format::types::ClusterOffset;
use crate::io::IoBackend;

/// Controls how the [`RefcountManager`] finds free clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllocationMode {
    /// Always allocate at the end of the file. Simple, fast, but never
    /// reuses freed clusters — the image file only grows.
    Append,
    /// Scan refcount blocks for clusters with refcount 0 before falling
    /// back to append. This reuses space freed by snapshot deletes, bitmap
    /// removal, and similar operations.
    #[default]
    Scanning,
}

/// Shared state accessible to allocation strategies.
#[derive(Debug)]
pub struct RefcountManagerState {
    /// The in-memory refcount table.
    pub refcount_table: Vec<RefcountTableEntry>,
    /// Host offset of the refcount table on disk.
    pub refcount_table_offset: ClusterOffset,
    /// Refcount order (refcount width = `1 << refcount_order` bits).
    pub refcount_order: u32,
    /// Log2 of the cluster size.
    pub cluster_bits: u32,
    /// Current end of file = next cluster to allocate for append strategy.
    pub next_cluster_offset: u64,
}

/// Manages cluster reference counts and allocation.
#[derive(Debug)]
pub struct RefcountManager {
    state: RefcountManagerState,
    mode: AllocationMode,
    /// Cluster index where the scanning allocator starts looking next.
    next_scan_index: u64,
}

impl RefcountManager {
    /// Load the refcount manager from an image header, using the default
    /// [`AllocationMode::Scanning`].
    pub fn load(backend: &dyn IoBackend, header: &Header) -> Result<Self> {
        Self::load_with_mode(backend, header, AllocationMode::default())
    }

    /// Load the refcount manager with a specific allocation mode.
    pub fn load_with_mode(
        backend: &dyn IoBackend,
        header: &Header,
        mode: AllocationMode,
    ) -> Result<Self> {
        let cluster_size = 1u64 << header.cluster_bits;
        let table_byte_size =
            header.refcount_table_clusters as u64 * cluster_size;
        let entry_count = table_byte_size as usize / REFCOUNT_TABLE_ENTRY_SIZE;

        let mut table_buf = vec![0u8; table_byte_size as usize];
        backend.read_exact_at(&mut table_buf, header.refcount_table_offset.0)?;

        let refcount_table = read_refcount_table(&table_buf, entry_count as u32)?;
        let file_size = backend.file_size()?;

        // Align next_cluster_offset to cluster boundary
        let next_cluster_offset = (file_size + cluster_size - 1) & !(cluster_size - 1);

        Ok(Self {
            state: RefcountManagerState {
                refcount_table,
                refcount_table_offset: header.refcount_table_offset,
                refcount_order: header.refcount_order,
                cluster_bits: header.cluster_bits,
                next_cluster_offset,
            },
            mode,
            next_scan_index: 0,
        })
    }

    /// The current allocation mode.
    pub fn allocation_mode(&self) -> AllocationMode {
        self.mode
    }

    /// Allocate a new cluster: find free space, set refcount to 1, return offset.
    ///
    /// In [`AllocationMode::Scanning`], scans refcount blocks for freed clusters
    /// before falling back to append. In [`AllocationMode::Append`], always
    /// allocates at the end of the file.
    pub fn allocate_cluster(
        &mut self,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<ClusterOffset> {
        let offset = match self.mode {
            AllocationMode::Append => self.state.next_cluster_offset,
            AllocationMode::Scanning => self
                .scan_for_free_cluster(backend, cache)?
                .unwrap_or(self.state.next_cluster_offset),
        };

        // Ensure refcount coverage exists for this offset
        self.ensure_refcount_coverage(offset, backend, cache)?;

        // Set refcount to 1
        self.set_refcount_internal(offset, 1, backend, cache)?;

        // Advance next_cluster_offset past this allocation
        let cluster_size = 1u64 << self.state.cluster_bits;
        let end = offset + cluster_size;
        if end > self.state.next_cluster_offset {
            self.state.next_cluster_offset = end;
        }

        Ok(ClusterOffset(offset))
    }

    /// Allocate `count` contiguous clusters at the end of the file.
    ///
    /// Always uses append semantics (regardless of allocation mode) to
    /// guarantee that the returned clusters are contiguous. Returns the
    /// offset of the first cluster.
    pub fn allocate_contiguous_clusters(
        &mut self,
        count: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<ClusterOffset> {
        assert!(count > 0, "must allocate at least one cluster");
        let cluster_size = 1u64 << self.state.cluster_bits;

        // Phase 1: Ensure refcount coverage for the entire range.
        // This may allocate refcount blocks at the end, advancing
        // next_cluster_offset. We must do this before reading
        // first_offset to avoid interleaving data and metadata clusters.
        for i in 0..count {
            self.ensure_refcount_coverage(
                self.state.next_cluster_offset + i * cluster_size,
                backend,
                cache,
            )?;
        }

        // Phase 2: Allocate from the (possibly advanced) next_cluster_offset.
        // The second ensure_refcount_coverage calls are no-ops since coverage
        // was established in Phase 1.
        let first_offset = self.state.next_cluster_offset;
        for i in 0..count {
            let offset = first_offset + i * cluster_size;
            self.ensure_refcount_coverage(offset, backend, cache)?;
            self.set_refcount_internal(offset, 1, backend, cache)?;
        }
        self.state.next_cluster_offset = first_offset + count * cluster_size;

        Ok(ClusterOffset(first_offset))
    }

    /// Get the refcount for a cluster at the given host offset.
    ///
    /// Reads a single value from the refcount block without cloning the
    /// full block. The block is loaded into the cache on first access.
    pub fn get_refcount(
        &self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<u64> {
        let (table_index, block_index) = self.cluster_to_refcount_index(cluster_offset);

        let block_offset = match self.state.refcount_table.get(table_index).and_then(|e| e.block_offset()) {
            Some(offset) => offset,
            None => return Ok(0),
        };

        // Try cache first (no clone)
        if let Some(block) = cache.get_refcount_block(block_offset) {
            return Ok(block.get(block_index)?);
        }

        // Cache miss: load into cache, then read from cache reference
        self.load_refcount_block_into_cache(block_offset, backend, cache)?;
        let block = cache.get_refcount_block(block_offset)
            .ok_or(Error::CacheInconsistency { offset: block_offset.0 })?;
        Ok(block.get(block_index)?)
    }

    /// Set the refcount for a cluster at the given host offset.
    pub fn set_refcount(
        &mut self,
        cluster_offset: u64,
        value: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        self.ensure_refcount_coverage(cluster_offset, backend, cache)?;
        self.set_refcount_internal(cluster_offset, value, backend, cache)
    }

    /// Free a cluster (set refcount to 0).
    ///
    /// In [`AllocationMode::Scanning`], the freed cluster may be reused by
    /// a subsequent [`allocate_cluster`](Self::allocate_cluster) call.
    pub fn free_cluster(
        &mut self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        self.set_refcount(cluster_offset, 0, backend, cache)?;
        self.hint_freed_cluster(cluster_offset);
        Ok(())
    }

    /// Increment the refcount for a cluster. Returns the new refcount value.
    ///
    /// Errors with [`Error::RefcountOverflow`] if incrementing would exceed
    /// the maximum representable value for the configured refcount width.
    pub fn increment_refcount(
        &mut self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<u64> {
        let current = self.get_refcount(cluster_offset, backend, cache)?;
        let max = self.max_refcount();
        if current >= max {
            return Err(Error::RefcountOverflow {
                cluster_offset,
                current,
                max,
            });
        }
        let new_val = current + 1;
        self.set_refcount(cluster_offset, new_val, backend, cache)?;
        Ok(new_val)
    }

    /// Decrement the refcount for a cluster. Returns the new refcount value.
    ///
    /// If the refcount reaches 0, the cluster is logically freed and may be
    /// reused by subsequent allocations in [`AllocationMode::Scanning`].
    ///
    /// Panics in debug mode if the current refcount is already 0.
    pub fn decrement_refcount(
        &mut self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<u64> {
        let current = self.get_refcount(cluster_offset, backend, cache)?;
        debug_assert!(
            current > 0,
            "decrement of zero refcount at cluster offset 0x{cluster_offset:x}"
        );
        let new_val = current.saturating_sub(1);
        self.set_refcount(cluster_offset, new_val, backend, cache)?;
        if new_val == 0 {
            self.hint_freed_cluster(cluster_offset);
        }
        Ok(new_val)
    }

    /// Maximum representable refcount value for the configured refcount order.
    pub fn max_refcount(&self) -> u64 {
        let bits = 1u64 << self.state.refcount_order;
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    /// Access the internal state (for diagnostics and allocation strategies).
    pub fn state(&self) -> &RefcountManagerState {
        &self.state
    }

    // ---- Internal helpers ----

    /// Scan refcount blocks for a cluster with refcount 0, starting from
    /// the saved scan cursor. Returns the host offset if found, or `None`
    /// if all clusters up to `next_cluster_offset` are in use.
    fn scan_for_free_cluster(
        &mut self,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<Option<u64>> {
        let cluster_size = 1u64 << self.state.cluster_bits;
        let total_clusters = self.state.next_cluster_offset / cluster_size;

        for cluster_index in self.next_scan_index..total_clusters {
            let offset = cluster_index * cluster_size;
            let rc = self.get_refcount(offset, backend, cache)?;
            if rc == 0 {
                self.next_scan_index = cluster_index + 1;
                return Ok(Some(offset));
            }
        }

        // No free cluster found in the scanned range.
        self.next_scan_index = total_clusters;
        Ok(None)
    }

    /// Move the scan cursor back if the freed cluster is before it,
    /// so the scanner will find it on the next allocation.
    fn hint_freed_cluster(&mut self, cluster_offset: u64) {
        if self.mode == AllocationMode::Scanning {
            let cluster_size = 1u64 << self.state.cluster_bits;
            let freed_index = cluster_offset / cluster_size;
            if freed_index < self.next_scan_index {
                self.next_scan_index = freed_index;
            }
        }
    }

    /// Map a host cluster offset to (refcount_table_index, block_entry_index).
    fn cluster_to_refcount_index(&self, cluster_offset: u64) -> (usize, u32) {
        let cluster_size = 1u64 << self.state.cluster_bits;
        let cluster_index = cluster_offset / cluster_size;
        let refcount_bits = 1u32 << self.state.refcount_order;
        let entries_per_block = (cluster_size as u32 * 8) / refcount_bits;

        let table_index = (cluster_index / entries_per_block as u64) as usize;
        let block_index = (cluster_index % entries_per_block as u64) as u32;

        (table_index, block_index)
    }

    /// Load a refcount block from disk and insert into the cache.
    fn load_refcount_block_into_cache(
        &self,
        offset: ClusterOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let cluster_size = 1usize << self.state.cluster_bits;
        let mut buf = vec![0u8; cluster_size];
        backend.read_exact_at(&mut buf, offset.0)?;
        let block = RefcountBlock::read_from(&buf, self.state.refcount_order)?;
        cache.insert_refcount_block(offset, block, false);
        Ok(())
    }

    /// Write a refcount block back to disk and evict from cache.
    fn write_refcount_block(
        &self,
        offset: ClusterOffset,
        block: &RefcountBlock,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let cluster_size = 1usize << self.state.cluster_bits;
        let mut buf = vec![0u8; cluster_size];
        block.write_to(&mut buf)?;
        backend.write_all_at(&buf, offset.0)?;
        cache.evict_refcount_block(offset);
        Ok(())
    }

    /// Internal set_refcount that assumes coverage already exists.
    ///
    /// In WriteBack mode, modifies the refcount block in-place in the cache
    /// and marks it dirty. In WriteThrough mode, writes to disk immediately.
    fn set_refcount_internal(
        &self,
        cluster_offset: u64,
        value: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let (table_index, block_index) = self.cluster_to_refcount_index(cluster_offset);

        let block_offset = self.state.refcount_table.get(table_index)
            .and_then(|e| e.block_offset())
            .ok_or(Error::WriteFailed {
                guest_offset: cluster_offset,
                message: format!(
                    "refcount table entry {} has no block allocated",
                    table_index
                ),
            })?;

        // WriteBack: modify in cache if possible
        if let Some(entry) = cache.get_refcount_entry_mut(block_offset) {
            entry.value.set(block_index, value)?;
            entry.dirty = true;
            return Ok(());
        }

        // Load from disk into cache if not present
        if cache.get_refcount_block(block_offset).is_none() {
            self.load_refcount_block_into_cache(block_offset, backend, cache)?;
        }

        if cache.is_write_back() {
            // Modify in-place in cache (now guaranteed present)
            let entry = cache.get_refcount_entry_mut(block_offset)
                .ok_or(Error::CacheInconsistency { offset: block_offset.0 })?;
            entry.value.set(block_index, value)?;
            entry.dirty = true;
            // Handle pending evictions
            self.flush_pending_refcount_evictions(backend, cache)?;
        } else {
            // WriteThrough: clone, modify, write to disk
            let mut block = cache.get_refcount_block(block_offset)
                .ok_or(Error::CacheInconsistency { offset: block_offset.0 })?.clone();
            block.set(block_index, value)?;
            self.write_refcount_block(block_offset, &block, backend, cache)?;
        }

        Ok(())
    }

    /// Write any pending dirty refcount blocks that were evicted by LRU pressure.
    fn flush_pending_refcount_evictions(
        &self,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let pending = cache.take_pending_refcount_evictions();
        let cluster_size = 1usize << self.state.cluster_bits;
        for (offset, block) in &pending {
            let mut buf = vec![0u8; cluster_size];
            block.write_to(&mut buf)?;
            backend.write_all_at(&buf, *offset)?;
        }
        Ok(())
    }

    /// Ensure that refcount table and block coverage exists for the given offset.
    ///
    /// If the refcount table entry for this cluster is unallocated, allocates
    /// a new refcount block at the end of the file.
    fn ensure_refcount_coverage(
        &mut self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let (table_index, _block_index) = self.cluster_to_refcount_index(cluster_offset);

        // Grow table in memory if needed
        while table_index >= self.state.refcount_table.len() {
            self.state
                .refcount_table
                .push(RefcountTableEntry::unallocated());
        }

        // Already has a block?
        if !self.state.refcount_table[table_index].is_unallocated() {
            return Ok(());
        }

        // Allocate a new refcount block at end of file
        let cluster_size = 1u64 << self.state.cluster_bits;
        let block_offset = self.state.next_cluster_offset;
        self.state.next_cluster_offset += cluster_size;

        // Update the refcount table entry in memory
        self.state.refcount_table[table_index] =
            RefcountTableEntry::with_block_offset(ClusterOffset(block_offset));

        // Write the updated refcount table entry to disk
        let entry_disk_offset = self.state.refcount_table_offset.0
            + (table_index as u64 * REFCOUNT_TABLE_ENTRY_SIZE as u64);
        let mut entry_buf = [0u8; REFCOUNT_TABLE_ENTRY_SIZE];
        write_refcount_table(
            &[self.state.refcount_table[table_index]],
            &mut entry_buf,
        )?;
        backend.write_all_at(&entry_buf, entry_disk_offset)?;

        // Create the block in memory with its own refcount set to 1
        let mut block = RefcountBlock::new_empty(
            cluster_size as usize,
            self.state.refcount_order,
        );
        let (self_table_index, self_block_index) =
            self.cluster_to_refcount_index(block_offset);
        if self_table_index == table_index {
            block.set(self_block_index, 1)?;
        }

        if cache.is_write_back() {
            // WriteBack: insert dirty into cache, skip disk write of zeroed block
            cache.insert_refcount_block(ClusterOffset(block_offset), block, true);
            self.flush_pending_refcount_evictions(backend, cache)?;
        } else {
            // WriteThrough: write to disk immediately
            self.write_refcount_block(
                ClusterOffset(block_offset),
                &block,
                backend,
                cache,
            )?;
        }

        Ok(())
    }
}
