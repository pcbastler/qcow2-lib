//! LRU metadata cache for L2 tables and refcount blocks.
//!
//! Caches frequently accessed metadata tables in memory to avoid
//! repeated I/O. Keyed by the host file offset where each table
//! was loaded from.
//!
//! Supports two modes via [`CacheMode`]:
//! - **WriteBack**: modified entries stay in cache as dirty, flushed on
//!   `flush()`, LRU eviction, or `close()`. Higher throughput.
//! - **WriteThrough**: every modification is written to disk immediately
//!   (legacy behavior). Lower throughput but all metadata always on disk.

extern crate alloc;

use alloc::vec::Vec;

use crate::format::l2::L2Table;
use crate::format::refcount::RefcountBlock;
use crate::format::types::ClusterOffset;
use crate::lru::LruCache;

/// Controls how metadata modifications are persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Modifications stay in cache, flushed on flush()/eviction.
    /// Higher throughput, dirty entries lost on crash (recovered via DIRTY flag).
    WriteBack,
    /// Every modification written to disk immediately (legacy behavior).
    WriteThrough,
}

impl Default for CacheMode {
    fn default() -> Self {
        CacheMode::WriteBack
    }
}

/// A cached metadata entry with dirty tracking.
pub struct CacheEntry<T> {
    pub value: T,
    pub dirty: bool,
}

/// Configuration for cache capacities.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of L2 tables to cache.
    pub l2_table_capacity: usize,
    /// Maximum number of refcount blocks to cache.
    pub refcount_block_capacity: usize,
    /// Maximum number of bitmap data clusters to cache.
    pub bitmap_data_capacity: usize,
    /// Maximum number of hash data clusters to cache.
    pub hash_data_capacity: usize,
    /// Cache write mode.
    pub mode: CacheMode,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l2_table_capacity: 32,
            refcount_block_capacity: 16,
            bitmap_data_capacity: 8,
            hash_data_capacity: 16,
            mode: CacheMode::default(),
        }
    }
}

/// LRU cache for frequently accessed QCOW2 metadata.
///
/// Maintains separate caches for L2 tables and refcount blocks because
/// their access patterns and sizes may differ. Keyed by [`ClusterOffset`]
/// (the host file offset where the metadata was read from).
///
/// In [`CacheMode::WriteBack`], dirty entries evicted by LRU pressure
/// are placed into pending eviction buffers. The caller must drain them
/// via [`take_pending_l2_evictions`] / [`take_pending_refcount_evictions`]
/// and write them to disk.
pub struct MetadataCache {
    mode: CacheMode,
    l2_tables: LruCache<u64, CacheEntry<L2Table>>,
    refcount_blocks: LruCache<u64, CacheEntry<RefcountBlock>>,
    pending_l2_evictions: Vec<(u64, L2Table)>,
    pending_refcount_evictions: Vec<(u64, RefcountBlock)>,
    bitmap_data: LruCache<u64, Vec<u8>>,
    hash_data: LruCache<u64, Vec<u8>>,
    stats: CacheStats,
}

/// Cache hit/miss statistics for diagnostics and tuning.
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    /// Number of L2 table cache hits.
    pub l2_hits: u64,
    /// Number of L2 table cache misses.
    pub l2_misses: u64,
    /// Number of refcount block cache hits.
    pub refcount_hits: u64,
    /// Number of refcount block cache misses.
    pub refcount_misses: u64,
    /// Number of bitmap data cluster cache hits.
    pub bitmap_hits: u64,
    /// Number of bitmap data cluster cache misses.
    pub bitmap_misses: u64,
    /// Number of hash data cluster cache hits.
    pub hash_hits: u64,
    /// Number of hash data cluster cache misses.
    pub hash_misses: u64,
    /// Number of dirty L2 tables written back (on flush or eviction).
    pub l2_writebacks: u64,
    /// Number of dirty refcount blocks written back.
    pub refcount_writebacks: u64,
}

impl MetadataCache {
    /// Create a new metadata cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            mode: config.mode,
            l2_tables: LruCache::new(config.l2_table_capacity),
            refcount_blocks: LruCache::new(config.refcount_block_capacity),
            pending_l2_evictions: Vec::new(),
            pending_refcount_evictions: Vec::new(),
            bitmap_data: LruCache::new(config.bitmap_data_capacity),
            hash_data: LruCache::new(config.hash_data_capacity),
            stats: CacheStats::default(),
        }
    }

    /// The current cache mode.
    pub fn mode(&self) -> CacheMode {
        self.mode
    }

    /// Whether the cache is in write-back mode.
    pub fn is_write_back(&self) -> bool {
        self.mode == CacheMode::WriteBack
    }

    /// Change the cache mode. Caller should flush dirty entries first
    /// when switching from WriteBack to WriteThrough.
    pub fn set_mode(&mut self, mode: CacheMode) {
        self.mode = mode;
    }

    // ---- L2 tables ----

    /// Look up a cached L2 table by host offset (read-only).
    pub fn get_l2_table(&mut self, offset: ClusterOffset) -> Option<&L2Table> {
        let result = self.l2_tables.get(&offset.0);
        if let Some(entry) = result {
            self.stats.l2_hits += 1;
            Some(&entry.value)
        } else {
            self.stats.l2_misses += 1;
            None
        }
    }

    /// Look up a cached L2 table mutably for in-place modification.
    ///
    /// Returns `None` on cache miss. In [`CacheMode::WriteThrough`],
    /// always returns `None` so the caller falls through to the
    /// write-to-disk path.
    pub fn get_l2_entry_mut(&mut self, offset: ClusterOffset) -> Option<&mut CacheEntry<L2Table>> {
        if self.mode == CacheMode::WriteThrough {
            return None;
        }
        self.l2_tables.get_mut(&offset.0)
    }

    /// Insert an L2 table into the cache.
    ///
    /// If `dirty` is true and the cache is in WriteBack mode, the entry
    /// is marked dirty. In WriteThrough mode, `dirty` is ignored.
    ///
    /// If a dirty entry is evicted by LRU pressure, it is placed into
    /// the pending eviction buffer.
    pub fn insert_l2_table(&mut self, offset: ClusterOffset, table: L2Table, dirty: bool) {
        let dirty = dirty && self.mode == CacheMode::WriteBack;
        let entry = CacheEntry { value: table, dirty };
        if let Some((evicted_key, evicted_entry)) = self.l2_tables.put_with_evict(offset.0, entry) {
            if evicted_entry.dirty {
                self.pending_l2_evictions.push((evicted_key, evicted_entry.value));
            }
        }
    }

    /// Take all dirty L2 tables that were evicted by LRU pressure.
    ///
    /// The caller must write these to disk before they are lost.
    pub fn take_pending_l2_evictions(&mut self) -> Vec<(u64, L2Table)> {
        core::mem::take(&mut self.pending_l2_evictions)
    }

    /// Evict a specific L2 table from the cache.
    ///
    /// If the evicted entry is dirty, it is returned so the caller can
    /// write it to disk. Returns `None` if not present or clean.
    pub fn evict_l2_table(&mut self, offset: ClusterOffset) -> Option<L2Table> {
        if let Some(entry) = self.l2_tables.pop(&offset.0) {
            if entry.dirty {
                return Some(entry.value);
            }
        }
        None
    }

    /// Flush a single dirty L2 table at `offset` to disk via the callback.
    ///
    /// The entry remains in cache but is marked clean. No-op if the entry
    /// is not present or not dirty.
    pub fn flush_single_l2<F>(&mut self, offset: ClusterOffset, mut writer: F) -> bool
    where
        F: FnMut(u64, &L2Table),
    {
        if let Some(entry) = self.l2_tables.get_mut(&offset.0) {
            if entry.dirty {
                writer(offset.0, &entry.value);
                entry.dirty = false;
                self.stats.l2_writebacks += 1;
                return true;
            }
        }
        false
    }

    /// Flush all dirty L2 tables via the callback. Entries remain cached but clean.
    pub fn flush_l2_tables<F, E>(&mut self, mut writer: F) -> Result<(), E>
    where
        F: FnMut(u64, &L2Table) -> Result<(), E>,
    {
        for (key, entry) in self.l2_tables.iter_mut() {
            if entry.dirty {
                writer(*key, &entry.value)?;
                entry.dirty = false;
                self.stats.l2_writebacks += 1;
            }
        }
        Ok(())
    }

    // ---- Refcount blocks ----

    /// Look up a cached refcount block by host offset (read-only).
    pub fn get_refcount_block(&mut self, offset: ClusterOffset) -> Option<&RefcountBlock> {
        let result = self.refcount_blocks.get(&offset.0);
        if let Some(entry) = result {
            self.stats.refcount_hits += 1;
            Some(&entry.value)
        } else {
            self.stats.refcount_misses += 1;
            None
        }
    }

    /// Look up a cached refcount block mutably for in-place modification.
    ///
    /// Returns `None` in WriteThrough mode.
    pub fn get_refcount_entry_mut(
        &mut self,
        offset: ClusterOffset,
    ) -> Option<&mut CacheEntry<RefcountBlock>> {
        if self.mode == CacheMode::WriteThrough {
            return None;
        }
        self.refcount_blocks.get_mut(&offset.0)
    }

    /// Insert a refcount block into the cache.
    pub fn insert_refcount_block(
        &mut self,
        offset: ClusterOffset,
        block: RefcountBlock,
        dirty: bool,
    ) {
        let dirty = dirty && self.mode == CacheMode::WriteBack;
        let entry = CacheEntry { value: block, dirty };
        if let Some((evicted_key, evicted_entry)) =
            self.refcount_blocks.put_with_evict(offset.0, entry)
        {
            if evicted_entry.dirty {
                self.pending_refcount_evictions
                    .push((evicted_key, evicted_entry.value));
            }
        }
    }

    /// Take all dirty refcount blocks that were evicted by LRU pressure.
    pub fn take_pending_refcount_evictions(&mut self) -> Vec<(u64, RefcountBlock)> {
        core::mem::take(&mut self.pending_refcount_evictions)
    }

    /// Evict a specific refcount block from the cache.
    ///
    /// Returns the block if it was dirty.
    pub fn evict_refcount_block(&mut self, offset: ClusterOffset) -> Option<RefcountBlock> {
        if let Some(entry) = self.refcount_blocks.pop(&offset.0) {
            if entry.dirty {
                return Some(entry.value);
            }
        }
        None
    }

    /// Flush all dirty refcount blocks via the callback.
    pub fn flush_refcount_blocks<F, E>(&mut self, mut writer: F) -> Result<(), E>
    where
        F: FnMut(u64, &RefcountBlock) -> Result<(), E>,
    {
        for (key, entry) in self.refcount_blocks.iter_mut() {
            if entry.dirty {
                writer(*key, &entry.value)?;
                entry.dirty = false;
                self.stats.refcount_writebacks += 1;
            }
        }
        Ok(())
    }

    /// Whether there are any pending dirty evictions that need writing.
    pub fn has_pending_evictions(&self) -> bool {
        !self.pending_l2_evictions.is_empty() || !self.pending_refcount_evictions.is_empty()
    }

    /// Drain all entries (for close/drop). Returns dirty L2 and refcount entries.
    pub fn drain_dirty(&mut self) -> (Vec<(u64, L2Table)>, Vec<(u64, RefcountBlock)>) {
        let mut dirty_l2 = core::mem::take(&mut self.pending_l2_evictions);
        for (key, entry) in self.l2_tables.drain() {
            if entry.dirty {
                dirty_l2.push((key, entry.value));
            }
        }
        let mut dirty_rc = core::mem::take(&mut self.pending_refcount_evictions);
        for (key, entry) in self.refcount_blocks.drain() {
            if entry.dirty {
                dirty_rc.push((key, entry.value));
            }
        }
        (dirty_l2, dirty_rc)
    }

    // ---- Bitmap data (unchanged, no dirty tracking) ----

    /// Look up a cached bitmap data cluster by host offset.
    pub fn get_bitmap_data(&mut self, offset: ClusterOffset) -> Option<&Vec<u8>> {
        let result = self.bitmap_data.get(&offset.0);
        if result.is_some() {
            self.stats.bitmap_hits += 1;
        } else {
            self.stats.bitmap_misses += 1;
        }
        result
    }

    /// Insert a bitmap data cluster into the cache.
    pub fn insert_bitmap_data(&mut self, offset: ClusterOffset, data: Vec<u8>) {
        self.bitmap_data.put(offset.0, data);
    }

    /// Evict a specific bitmap data cluster from the cache.
    pub fn evict_bitmap_data(&mut self, offset: ClusterOffset) {
        self.bitmap_data.pop(&offset.0);
    }

    // ---- Hash data (unchanged, no dirty tracking) ----

    /// Look up a cached hash data cluster by host offset.
    pub fn get_hash_data(&mut self, offset: ClusterOffset) -> Option<&Vec<u8>> {
        let result = self.hash_data.get(&offset.0);
        if result.is_some() {
            self.stats.hash_hits += 1;
        } else {
            self.stats.hash_misses += 1;
        }
        result
    }

    /// Insert a hash data cluster into the cache.
    pub fn insert_hash_data(&mut self, offset: ClusterOffset, data: Vec<u8>) {
        self.hash_data.put(offset.0, data);
    }

    /// Evict a specific hash data cluster from the cache.
    pub fn evict_hash_data(&mut self, offset: ClusterOffset) {
        self.hash_data.pop(&offset.0);
    }

    // ---- General ----

    /// Clear all cached entries. Dirty entries are silently dropped.
    ///
    /// Caller should flush before clearing if dirty entries need persisting.
    pub fn clear(&mut self) {
        self.l2_tables.clear();
        self.refcount_blocks.clear();
        self.pending_l2_evictions.clear();
        self.pending_refcount_evictions.clear();
        self.bitmap_data.clear();
        self.hash_data.clear();
    }

    /// Get cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::format::l2::L2Table;
    use crate::format::types::ClusterGeometry;

    fn make_l2_table(cluster_bits: u32) -> L2Table {
        let cluster_size = 1usize << cluster_bits;
        let buf = vec![0u8; cluster_size];
        L2Table::read_from(&buf, ClusterGeometry { cluster_bits, extended_l2: false }).unwrap()
    }

    fn default_config() -> CacheConfig {
        CacheConfig::default()
    }

    fn write_through_config() -> CacheConfig {
        CacheConfig {
            mode: CacheMode::WriteThrough,
            ..Default::default()
        }
    }

    #[test]
    fn insert_and_get_l2_table() {
        let mut cache = MetadataCache::new(default_config());
        let table = make_l2_table(16);
        let offset = ClusterOffset(0x10000);

        cache.insert_l2_table(offset, table.clone(), false);
        let cached = cache.get_l2_table(offset);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), table.len());
    }

    #[test]
    fn cache_miss_returns_none() {
        let mut cache = MetadataCache::new(default_config());
        assert!(cache.get_l2_table(ClusterOffset(0x99999)).is_none());
    }

    #[test]
    fn lru_eviction() {
        let config = CacheConfig {
            l2_table_capacity: 2,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), false);
        cache.insert_l2_table(ClusterOffset(0x30000), make_l2_table(16), false);

        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_l2_table(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_l2_table(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn stats_tracking() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);

        cache.get_l2_table(ClusterOffset(0x10000)); // hit
        cache.get_l2_table(ClusterOffset(0x20000)); // miss
        cache.get_l2_table(ClusterOffset(0x10000)); // hit

        assert_eq!(cache.stats().l2_hits, 2);
        assert_eq!(cache.stats().l2_misses, 1);
    }

    #[test]
    fn clear_empties_cache() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        cache.clear();
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
    }

    #[test]
    fn capacity_one_evicts_on_every_insert() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_some());

        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), false);
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_l2_table(ClusterOffset(0x20000)).is_some());
    }

    #[test]
    fn refcount_block_cache() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(default_config());

        let data = vec![0u8; 64];
        let block = RefcountBlock::read_from(&data, 4).unwrap();

        cache.insert_refcount_block(ClusterOffset(0x30000), block.clone(), false);
        let cached = cache.get_refcount_block(ClusterOffset(0x30000));
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), block.len());

        assert_eq!(cache.stats().refcount_hits, 1);
        assert_eq!(cache.stats().refcount_misses, 0);

        cache.get_refcount_block(ClusterOffset(0x99999));
        assert_eq!(cache.stats().refcount_misses, 1);
    }

    #[test]
    fn refcount_block_eviction() {
        use crate::format::refcount::RefcountBlock;

        let config = CacheConfig {
            l2_table_capacity: 8,
            refcount_block_capacity: 2,
            bitmap_data_capacity: 1,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        let make_block = || {
            let data = vec![0u8; 32];
            RefcountBlock::read_from(&data, 4).unwrap()
        };

        cache.insert_refcount_block(ClusterOffset(0x10000), make_block(), false);
        cache.insert_refcount_block(ClusterOffset(0x20000), make_block(), false);
        cache.insert_refcount_block(ClusterOffset(0x30000), make_block(), false);

        assert!(cache.get_refcount_block(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_refcount_block(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_refcount_block(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn mixed_l2_and_refcount_stats() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(default_config());

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        let block_data = vec![0u8; 32];
        let block = RefcountBlock::read_from(&block_data, 4).unwrap();
        cache.insert_refcount_block(ClusterOffset(0x20000), block, false);

        cache.get_l2_table(ClusterOffset(0x10000));
        cache.get_l2_table(ClusterOffset(0x99999));
        cache.get_refcount_block(ClusterOffset(0x20000));
        cache.get_refcount_block(ClusterOffset(0x88888));

        assert_eq!(cache.stats().l2_hits, 1);
        assert_eq!(cache.stats().l2_misses, 1);
        assert_eq!(cache.stats().refcount_hits, 1);
        assert_eq!(cache.stats().refcount_misses, 1);
    }

    #[test]
    fn evict_l2_table_removes_entry() {
        let mut cache = MetadataCache::new(default_config());
        let offset = ClusterOffset(0x10000);
        cache.insert_l2_table(offset, make_l2_table(16), false);
        assert!(cache.get_l2_table(offset).is_some());

        cache.evict_l2_table(offset);
        assert!(cache.get_l2_table(offset).is_none());
    }

    #[test]
    fn evict_refcount_block_removes_entry() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(default_config());
        let offset = ClusterOffset(0x20000);
        let block = RefcountBlock::read_from(&[0u8; 64], 4).unwrap();
        cache.insert_refcount_block(offset, block, false);
        assert!(cache.get_refcount_block(offset).is_some());

        cache.evict_refcount_block(offset);
        assert!(cache.get_refcount_block(offset).is_none());
    }

    // ---- Dirty tracking ----

    #[test]
    fn dirty_l2_eviction_captured_in_pending() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            mode: CacheMode::WriteBack,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), true);
        // This evicts the dirty entry at 0x10000
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), false);

        let pending = cache.take_pending_l2_evictions();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 0x10000);
    }

    #[test]
    fn clean_eviction_not_captured() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            mode: CacheMode::WriteBack,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), false);

        let pending = cache.take_pending_l2_evictions();
        assert!(pending.is_empty());
    }

    #[test]
    fn get_l2_entry_mut_returns_none_in_writethrough() {
        let mut cache = MetadataCache::new(write_through_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        assert!(cache.get_l2_entry_mut(ClusterOffset(0x10000)).is_none());
    }

    #[test]
    fn get_l2_entry_mut_returns_some_in_writeback() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        let entry = cache.get_l2_entry_mut(ClusterOffset(0x10000));
        assert!(entry.is_some());
        assert!(!entry.unwrap().dirty);
    }

    #[test]
    fn dirty_flag_ignored_in_writethrough() {
        let mut cache = MetadataCache::new(write_through_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), true);
        // Even though dirty=true was passed, it should not be captured
        let (dirty_l2, _) = cache.drain_dirty();
        assert!(dirty_l2.is_empty());
    }

    #[test]
    fn flush_l2_tables_clears_dirty() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), true);
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), true);

        let mut flushed = Vec::new();
        cache
            .flush_l2_tables(|offset, _table| -> Result<(), ()> {
                flushed.push(offset);
                Ok(())
            })
            .unwrap();

        assert_eq!(flushed.len(), 2);

        // After flush, drain_dirty should be empty
        let (dirty_l2, _) = cache.drain_dirty();
        assert!(dirty_l2.is_empty());
    }

    #[test]
    fn evict_dirty_l2_returns_table() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), true);
        let evicted = cache.evict_l2_table(ClusterOffset(0x10000));
        assert!(evicted.is_some());
    }

    #[test]
    fn evict_clean_l2_returns_none() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        let evicted = cache.evict_l2_table(ClusterOffset(0x10000));
        assert!(evicted.is_none());
    }

    // ---- Bitmap data cache (unchanged) ----

    #[test]
    fn bitmap_data_insert_and_get() {
        let mut cache = MetadataCache::new(default_config());
        let offset = ClusterOffset(0x50000);
        let data = vec![0xAA; 4096];

        cache.insert_bitmap_data(offset, data.clone());
        let cached = cache.get_bitmap_data(offset);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), &data);

        assert_eq!(cache.stats().bitmap_hits, 1);
        assert_eq!(cache.stats().bitmap_misses, 0);
    }

    #[test]
    fn bitmap_data_miss() {
        let mut cache = MetadataCache::new(default_config());
        assert!(cache.get_bitmap_data(ClusterOffset(0x99999)).is_none());
        assert_eq!(cache.stats().bitmap_misses, 1);
    }

    #[test]
    fn bitmap_data_eviction() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 2,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_bitmap_data(ClusterOffset(0x10000), vec![1; 64]);
        cache.insert_bitmap_data(ClusterOffset(0x20000), vec![2; 64]);
        cache.insert_bitmap_data(ClusterOffset(0x30000), vec![3; 64]);

        assert!(cache.get_bitmap_data(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_bitmap_data(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_bitmap_data(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn bitmap_data_evict_specific() {
        let mut cache = MetadataCache::new(default_config());
        let offset = ClusterOffset(0x40000);
        cache.insert_bitmap_data(offset, vec![0xFF; 128]);
        assert!(cache.get_bitmap_data(offset).is_some());

        cache.evict_bitmap_data(offset);
        assert!(cache.get_bitmap_data(offset).is_none());
    }

    #[test]
    fn bitmap_data_stats_tracking() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_bitmap_data(ClusterOffset(0x10000), vec![0; 64]);

        cache.get_bitmap_data(ClusterOffset(0x10000)); // hit
        cache.get_bitmap_data(ClusterOffset(0x20000)); // miss
        cache.get_bitmap_data(ClusterOffset(0x10000)); // hit
        cache.get_bitmap_data(ClusterOffset(0x30000)); // miss

        assert_eq!(cache.stats().bitmap_hits, 2);
        assert_eq!(cache.stats().bitmap_misses, 2);
    }

    #[test]
    fn clear_also_clears_bitmap_data() {
        let mut cache = MetadataCache::new(default_config());
        cache.insert_bitmap_data(ClusterOffset(0x10000), vec![1; 64]);
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16), false);

        cache.clear();

        assert!(cache.get_bitmap_data(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_l2_table(ClusterOffset(0x20000)).is_none());
    }

    #[test]
    fn bitmap_data_capacity_one() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_bitmap_data(ClusterOffset(0x10000), vec![1; 64]);
        assert!(cache.get_bitmap_data(ClusterOffset(0x10000)).is_some());

        cache.insert_bitmap_data(ClusterOffset(0x20000), vec![2; 64]);
        assert!(cache.get_bitmap_data(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_bitmap_data(ClusterOffset(0x20000)).is_some());
    }

    #[test]
    fn mixed_all_three_cache_types() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(default_config());

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16), false);
        let block = RefcountBlock::read_from(&[0u8; 64], 4).unwrap();
        cache.insert_refcount_block(ClusterOffset(0x20000), block, false);
        cache.insert_bitmap_data(ClusterOffset(0x30000), vec![0xBB; 256]);

        cache.get_l2_table(ClusterOffset(0x10000));
        cache.get_refcount_block(ClusterOffset(0x20000));
        cache.get_bitmap_data(ClusterOffset(0x30000));
        cache.get_bitmap_data(ClusterOffset(0x99999));

        assert_eq!(cache.stats().l2_hits, 1);
        assert_eq!(cache.stats().refcount_hits, 1);
        assert_eq!(cache.stats().bitmap_hits, 1);
        assert_eq!(cache.stats().bitmap_misses, 1);
    }
}
