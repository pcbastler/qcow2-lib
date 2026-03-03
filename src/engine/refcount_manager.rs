//! Cluster allocation and refcount management.
//!
//! The [`RefcountManager`] tracks reference counts for every cluster in the
//! image and allocates new clusters for the write path. It uses a pluggable
//! [`AllocationStrategy`] to find free clusters.
//!
//! Phase 2 ships with [`AppendAllocator`], which always allocates at the end
//! of the file. This is simple, correct, and avoids fragmentation during
//! sequential writes. A future `ScanningAllocator` can reuse freed clusters.
//! Use `qemu-img convert` for offline compaction in the meantime.

use crate::engine::cache::MetadataCache;
use crate::error::{Error, Result};
use crate::format::constants::REFCOUNT_TABLE_ENTRY_SIZE;
use crate::format::header::Header;
use crate::format::refcount::{
    read_refcount_table, write_refcount_table, RefcountBlock, RefcountTableEntry,
};
use crate::format::types::ClusterOffset;
use crate::io::IoBackend;

/// Strategy for finding the next cluster to allocate.
///
/// Phase 2 ships with [`AppendAllocator`] (always appends at end of file).
/// Future phases can add a `ScanningAllocator` that reuses freed clusters.
pub trait AllocationStrategy: std::fmt::Debug + Send + Sync {
    /// Find a free cluster offset. Returns `None` if no space is available.
    fn find_free_cluster(&mut self, state: &RefcountManagerState) -> Option<u64>;
}

/// Append-only allocator: always allocates at the end of the file.
///
/// Simple, fast, no fragmentation during sequential writes.
/// Limitation: does not reuse freed clusters — the file only grows.
/// Use `qemu-img convert` for offline compaction.
#[derive(Debug)]
pub struct AppendAllocator;

impl AllocationStrategy for AppendAllocator {
    fn find_free_cluster(&mut self, state: &RefcountManagerState) -> Option<u64> {
        Some(state.next_cluster_offset)
    }
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
pub struct RefcountManager {
    state: RefcountManagerState,
    allocator: Box<dyn AllocationStrategy>,
}

impl std::fmt::Debug for RefcountManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefcountManager")
            .field("state", &self.state)
            .field("allocator", &self.allocator)
            .finish()
    }
}

impl RefcountManager {
    /// Load the refcount manager from an image header, using the default
    /// [`AppendAllocator`].
    pub fn load(backend: &dyn IoBackend, header: &Header) -> Result<Self> {
        Self::load_with_allocator(backend, header, Box::new(AppendAllocator))
    }

    /// Load the refcount manager with a custom allocation strategy.
    pub fn load_with_allocator(
        backend: &dyn IoBackend,
        header: &Header,
        allocator: Box<dyn AllocationStrategy>,
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
            allocator,
        })
    }

    /// Allocate a new cluster: find free space, set refcount to 1, return offset.
    pub fn allocate_cluster(
        &mut self,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<ClusterOffset> {
        let offset = self
            .allocator
            .find_free_cluster(&self.state)
            .ok_or(Error::RefcountTableFull)?;

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

    /// Get the refcount for a cluster at the given host offset.
    pub fn get_refcount(
        &self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<u64> {
        let (table_index, block_index) = self.cluster_to_refcount_index(cluster_offset);

        if table_index >= self.state.refcount_table.len() {
            return Ok(0);
        }

        let block_offset = match self.state.refcount_table[table_index].block_offset() {
            Some(offset) => offset,
            None => return Ok(0),
        };

        let block = self.load_refcount_block(block_offset, backend, cache)?;
        block.get(block_index)
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
    pub fn free_cluster(
        &mut self,
        cluster_offset: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        self.set_refcount(cluster_offset, 0, backend, cache)
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
    /// If the refcount reaches 0, the cluster is logically freed but not
    /// reclaimed (the append allocator does not reuse freed clusters).
    /// Use `qemu-img convert` for offline compaction.
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

    /// Load a refcount block from disk or cache.
    fn load_refcount_block(
        &self,
        offset: ClusterOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<RefcountBlock> {
        if let Some(block) = cache.get_refcount_block(offset) {
            return Ok(block.clone());
        }

        let cluster_size = 1usize << self.state.cluster_bits;
        let mut buf = vec![0u8; cluster_size];
        backend.read_exact_at(&mut buf, offset.0)?;
        let block = RefcountBlock::read_from(&buf, self.state.refcount_order)?;

        cache.insert_refcount_block(offset, block.clone());
        Ok(block)
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
    fn set_refcount_internal(
        &self,
        cluster_offset: u64,
        value: u64,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<()> {
        let (table_index, block_index) = self.cluster_to_refcount_index(cluster_offset);

        let block_offset = self.state.refcount_table[table_index]
            .block_offset()
            .ok_or(Error::WriteFailed {
                guest_offset: cluster_offset,
                message: format!(
                    "refcount table entry {} has no block allocated",
                    table_index
                ),
            })?;

        let mut block = self.load_refcount_block(block_offset, backend, cache)?;
        block.set(block_index, value)?;
        self.write_refcount_block(block_offset, &block, backend, cache)?;

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

        // Write a zeroed block to disk
        let zeroed_block = vec![0u8; cluster_size as usize];
        backend.write_all_at(&zeroed_block, block_offset)?;

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

        // Now set refcount=1 for the block itself (it's a used cluster)
        // This block covers itself — find its index and set it
        let (self_table_index, self_block_index) =
            self.cluster_to_refcount_index(block_offset);
        if self_table_index == table_index {
            // The new block covers itself — load it, set refcount, write back
            let mut block = RefcountBlock::new_empty(
                cluster_size as usize,
                self.state.refcount_order,
            );
            block.set(self_block_index, 1)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cache::CacheConfig;
    use crate::format::constants::REFCOUNT_TABLE_ENTRY_SIZE;
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;
    const REFCOUNT_ORDER: u32 = 4; // 16-bit refcounts

    /// Build a minimal header for RefcountManager tests.
    fn make_header(refcount_table_clusters: u32) -> Header {
        Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30, // 1 GiB
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
            refcount_table_offset: ClusterOffset(2 * CLUSTER_SIZE as u64),
            refcount_table_clusters,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: REFCOUNT_ORDER,
            header_length: 104,
            compression_type: 0,
        }
    }

    /// Build a MemoryBackend with a valid refcount table at cluster 2.
    /// refcount_block_offset: if Some, cluster 3 has a refcount block.
    fn make_backend(
        refcount_table_clusters: u32,
        refcount_entries: &[(usize, u64)],
    ) -> MemoryBackend {
        let rt_offset = 2 * CLUSTER_SIZE;
        let total_size = (4 + refcount_table_clusters as usize) * CLUSTER_SIZE;
        let mut data = vec![0u8; total_size];

        // Write refcount table entries
        for &(index, raw) in refcount_entries {
            let offset = rt_offset + index * REFCOUNT_TABLE_ENTRY_SIZE;
            BigEndian::write_u64(&mut data[offset..], raw);
        }

        MemoryBackend::new(data)
    }

    #[test]
    fn load_empty_refcount_table() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);

        let mgr = RefcountManager::load(&backend, &header).unwrap();
        let entries_per_cluster = CLUSTER_SIZE / REFCOUNT_TABLE_ENTRY_SIZE;
        assert_eq!(mgr.state().refcount_table.len(), entries_per_cluster);
    }

    #[test]
    fn get_refcount_unallocated_returns_zero() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        let rc = mgr.get_refcount(5 * CLUSTER_SIZE as u64, &backend, &mut cache).unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    fn get_refcount_beyond_table_returns_zero() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Way beyond what the table covers
        let rc = mgr
            .get_refcount(u64::MAX & !0xFFFF, &backend, &mut cache)
            .unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    fn set_and_get_refcount() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Cluster 0 maps to refcount table index 0, block index 0
        mgr.set_refcount(0, 42, &backend, &mut cache).unwrap();
        let rc = mgr.get_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(rc, 42);
    }

    #[test]
    fn allocate_cluster_returns_sequential_offsets() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        // Pre-populate refcount block covering the first clusters
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        let initial_end = mgr.state().next_cluster_offset;
        let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
        assert_eq!(c1.0, initial_end);

        let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
        assert_eq!(c2.0, initial_end + CLUSTER_SIZE as u64);
    }

    #[test]
    fn allocate_cluster_sets_refcount_to_one() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        let c = mgr.allocate_cluster(&backend, &mut cache).unwrap();
        let rc = mgr.get_refcount(c.0, &backend, &mut cache).unwrap();
        assert_eq!(rc, 1);
    }

    #[test]
    fn free_cluster_sets_refcount_to_zero() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Set refcount to 1 first
        mgr.set_refcount(0, 1, &backend, &mut cache).unwrap();
        assert_eq!(mgr.get_refcount(0, &backend, &mut cache).unwrap(), 1);

        mgr.free_cluster(0, &backend, &mut cache).unwrap();
        assert_eq!(mgr.get_refcount(0, &backend, &mut cache).unwrap(), 0);
    }

    #[test]
    fn cluster_to_refcount_index_calculation() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();

        // Cluster 0 → table[0], block[0]
        assert_eq!(mgr.cluster_to_refcount_index(0), (0, 0));

        // Cluster 1 (offset=0x10000) → table[0], block[1]
        assert_eq!(mgr.cluster_to_refcount_index(CLUSTER_SIZE as u64), (0, 1));

        // 16-bit refcounts in 64KB cluster = 32768 entries per block
        // So cluster 32768 → table[1], block[0]
        let entries_per_block = CLUSTER_SIZE * 8 / 16; // 32768
        assert_eq!(
            mgr.cluster_to_refcount_index(entries_per_block as u64 * CLUSTER_SIZE as u64),
            (1, 0)
        );
    }

    #[test]
    fn ensure_coverage_allocates_new_block() {
        let header = make_header(1);
        // No refcount blocks pre-allocated
        let backend = make_backend(1, &[]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Setting refcount on cluster 0 should trigger block allocation
        mgr.set_refcount(0, 1, &backend, &mut cache).unwrap();

        // Table entry 0 should now point to the new block
        assert!(!mgr.state().refcount_table[0].is_unallocated());

        // Should be able to read back the value
        let rc = mgr.get_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(rc, 1);
    }

    #[test]
    fn write_through_persists_to_backend() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.set_refcount(0, 99, &backend, &mut cache).unwrap();

        // Read the refcount block directly from the backend to verify persistence
        let mut buf = vec![0u8; CLUSTER_SIZE];
        backend.read_exact_at(&mut buf, block_offset).unwrap();
        let block = RefcountBlock::read_from(&buf, REFCOUNT_ORDER).unwrap();
        assert_eq!(block.get(0).unwrap(), 99);
    }

    #[test]
    fn evicts_cache_after_write() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Prime the cache
        let _ = mgr.get_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(cache.stats().refcount_misses, 1);

        // Write should evict
        mgr.set_refcount(0, 5, &backend, &mut cache).unwrap();

        // Next read should be a miss (re-loaded from disk)
        let rc = mgr.get_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(rc, 5);
        assert!(cache.stats().refcount_misses >= 2);
    }

    #[test]
    fn custom_allocator() {
        /// Allocates sequentially from a starting offset.
        #[derive(Debug)]
        struct SequentialAllocator(u64);

        impl AllocationStrategy for SequentialAllocator {
            fn find_free_cluster(&mut self, _state: &RefcountManagerState) -> Option<u64> {
                let offset = self.0;
                self.0 += CLUSTER_SIZE as u64;
                Some(offset)
            }
        }

        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let start_offset = 5 * CLUSTER_SIZE as u64;
        let mut mgr = RefcountManager::load_with_allocator(
            &backend,
            &header,
            Box::new(SequentialAllocator(start_offset)),
        )
        .unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
        assert_eq!(c1.0, start_offset);

        // Second allocation must return a different cluster
        let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
        assert_ne!(c1, c2, "allocator must not return the same cluster twice");
        assert_eq!(c2.0, start_offset + CLUSTER_SIZE as u64);
    }

    #[test]
    fn debug_format() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();
        let debug_str = format!("{mgr:?}");
        assert!(debug_str.contains("RefcountManager"));
        assert!(debug_str.contains("AppendAllocator"));
    }

    #[test]
    fn next_cluster_offset_is_cluster_aligned() {
        let header = make_header(1);
        // Make backend with size not perfectly cluster-aligned
        let data = vec![0u8; 4 * CLUSTER_SIZE + 100];
        let backend = MemoryBackend::new(data);
        // Need a valid refcount table at offset 2*CLUSTER_SIZE
        // It's all zeros which is fine (all entries unallocated)

        let mgr = RefcountManager::load(&backend, &header).unwrap();
        assert_eq!(
            mgr.state().next_cluster_offset,
            5 * CLUSTER_SIZE as u64,
            "should round up to next cluster boundary"
        );
    }

    // ---- increment_refcount / decrement_refcount tests ----

    #[test]
    fn increment_from_zero_returns_one() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        let new_val = mgr.increment_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(new_val, 1);
        assert_eq!(mgr.get_refcount(0, &backend, &mut cache).unwrap(), 1);
    }

    #[test]
    fn increment_from_one_returns_two() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.set_refcount(0, 1, &backend, &mut cache).unwrap();
        let new_val = mgr.increment_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(new_val, 2);
    }

    #[test]
    fn decrement_from_two_returns_one() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.set_refcount(0, 2, &backend, &mut cache).unwrap();
        let new_val = mgr.decrement_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(new_val, 1);
    }

    #[test]
    fn decrement_from_one_returns_zero() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.set_refcount(0, 1, &backend, &mut cache).unwrap();
        let new_val = mgr.decrement_refcount(0, &backend, &mut cache).unwrap();
        assert_eq!(new_val, 0);
    }

    #[test]
    fn increment_at_max_returns_overflow_error() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        // 16-bit refcount max = 65535
        mgr.set_refcount(0, 65535, &backend, &mut cache).unwrap();
        let result = mgr.increment_refcount(0, &backend, &mut cache);
        assert!(
            matches!(result, Err(Error::RefcountOverflow { .. })),
            "should error on overflow: {result:?}"
        );
    }

    #[test]
    fn increment_then_decrement_round_trip() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.increment_refcount(0, &backend, &mut cache).unwrap();
        mgr.increment_refcount(0, &backend, &mut cache).unwrap();
        mgr.decrement_refcount(0, &backend, &mut cache).unwrap();

        assert_eq!(mgr.get_refcount(0, &backend, &mut cache).unwrap(), 1);
    }

    #[test]
    fn increment_persists_to_backend() {
        let block_offset = 3 * CLUSTER_SIZE as u64;
        let header = make_header(1);
        let backend = make_backend(1, &[(0, block_offset)]);
        let mut mgr = RefcountManager::load(&backend, &header).unwrap();
        let mut cache = MetadataCache::new(CacheConfig::default());

        mgr.increment_refcount(0, &backend, &mut cache).unwrap();

        // Read block directly from backend
        let mut buf = vec![0u8; CLUSTER_SIZE];
        backend.read_exact_at(&mut buf, block_offset).unwrap();
        let block = RefcountBlock::read_from(&buf, REFCOUNT_ORDER).unwrap();
        assert_eq!(block.get(0).unwrap(), 1);
    }

    #[test]
    fn max_refcount_16bit() {
        let header = make_header(1);
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();
        assert_eq!(mgr.max_refcount(), 65535);
    }

    #[test]
    fn max_refcount_64bit() {
        let mut header = make_header(1);
        header.refcount_order = 6; // 64-bit refcounts
        // load() works because the refcount table has no block entries to parse.
        let backend = make_backend(1, &[]);
        let mgr = RefcountManager::load(&backend, &header).unwrap();
        assert_eq!(mgr.state().refcount_order, 6);
        assert_eq!(mgr.max_refcount(), u64::MAX);
    }
}
