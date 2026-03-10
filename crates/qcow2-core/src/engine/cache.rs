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
    /// The cached value (L2Table or RefcountBlock).
    pub value: T,
    /// Whether this entry has been modified since last flush.
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

// ---- Generic dirty LRU cache ----

/// LRU cache with dirty tracking and pending eviction buffer.
///
/// When a dirty entry is evicted by LRU pressure, it is placed into
/// a pending eviction buffer. The caller must drain it via
/// [`take_pending_evictions`] and write the entries to disk.
struct DirtyLruCache<T> {
    entries: LruCache<u64, CacheEntry<T>>,
    pending_evictions: Vec<(u64, T)>,
}

impl<T> DirtyLruCache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            entries: LruCache::new(capacity),
            pending_evictions: Vec::new(),
        }
    }

    /// Look up a cached entry by key (read-only reference to the value).
    fn get(&mut self, key: u64) -> Option<&T> {
        self.entries.get(&key).map(|entry| &entry.value)
    }

    /// Look up a cached entry mutably for in-place modification.
    fn get_entry_mut(&mut self, key: u64) -> Option<&mut CacheEntry<T>> {
        self.entries.get_mut(&key)
    }

    /// Insert an entry into the cache.
    ///
    /// If `dirty` is true, the entry is marked dirty. If a dirty entry
    /// is evicted by LRU pressure, it is placed into the pending buffer.
    fn insert(&mut self, key: u64, value: T, dirty: bool) {
        let entry = CacheEntry { value, dirty };
        if let Some((evicted_key, evicted_entry)) = self.entries.put_with_evict(key, entry) {
            if evicted_entry.dirty {
                self.pending_evictions.push((evicted_key, evicted_entry.value));
            }
        }
    }

    /// Take all dirty entries that were evicted by LRU pressure.
    fn take_pending_evictions(&mut self) -> Vec<(u64, T)> {
        core::mem::take(&mut self.pending_evictions)
    }

    /// Evict a specific entry from the cache.
    ///
    /// Returns the value if the evicted entry was dirty; `None` otherwise.
    fn evict(&mut self, key: u64) -> Option<T> {
        if let Some(entry) = self.entries.pop(&key) {
            if entry.dirty {
                return Some(entry.value);
            }
        }
        None
    }

    /// Flush a single dirty entry at `key` via the callback.
    ///
    /// The entry remains in cache but is marked clean. Returns the number
    /// of writebacks performed (0 or 1).
    fn flush_single<F>(&mut self, key: u64, mut writer: F) -> u64
    where
        F: FnMut(u64, &T),
    {
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.dirty {
                writer(key, &entry.value);
                entry.dirty = false;
                return 1;
            }
        }
        0
    }

    /// Flush all dirty entries via the callback. Entries remain cached but clean.
    /// Returns the number of writebacks performed.
    fn flush_all<F, E>(&mut self, mut writer: F) -> Result<u64, E>
    where
        F: FnMut(u64, &T) -> Result<(), E>,
    {
        let mut writebacks = 0u64;
        for (key, entry) in self.entries.iter_mut() {
            if entry.dirty {
                writer(*key, &entry.value)?;
                entry.dirty = false;
                writebacks += 1;
            }
        }
        Ok(writebacks)
    }

    /// Drain all entries. Returns dirty ones (pending + in-cache).
    fn drain_dirty(&mut self) -> Vec<(u64, T)> {
        let mut dirty = core::mem::take(&mut self.pending_evictions);
        for (key, entry) in self.entries.drain() {
            if entry.dirty {
                dirty.push((key, entry.value));
            }
        }
        dirty
    }

    /// Clear all cached entries. Dirty entries are silently dropped.
    fn clear(&mut self) {
        self.entries.clear();
        self.pending_evictions.clear();
    }
}

// ---- MetadataCache: typed facade with stats and cache mode ----

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
    l2_tables: DirtyLruCache<L2Table>,
    refcount_blocks: DirtyLruCache<RefcountBlock>,
    bitmap_data: LruCache<u64, Vec<u8>>,
    hash_data: LruCache<u64, Vec<u8>>,
    stats: CacheStats,
}

impl MetadataCache {
    /// Create a new metadata cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            mode: config.mode,
            l2_tables: DirtyLruCache::new(config.l2_table_capacity),
            refcount_blocks: DirtyLruCache::new(config.refcount_block_capacity),
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
        let result = self.l2_tables.get(offset.0);
        if result.is_some() {
            self.stats.l2_hits += 1;
        } else {
            self.stats.l2_misses += 1;
        }
        result
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
        self.l2_tables.get_entry_mut(offset.0)
    }

    /// Insert an L2 table into the cache.
    ///
    /// If `dirty` is true and the cache is in WriteBack mode, the entry
    /// is marked dirty. In WriteThrough mode, `dirty` is ignored.
    ///
    /// If a dirty entry is evicted by LRU pressure, it is placed into
    /// the pending eviction buffer.
    pub fn insert_l2_table(&mut self, offset: ClusterOffset, table: L2Table, dirty: bool) {
        let effective_dirty = dirty && self.mode == CacheMode::WriteBack;
        self.l2_tables.insert(offset.0, table, effective_dirty);
    }

    /// Take all dirty L2 tables that were evicted by LRU pressure.
    ///
    /// The caller must write these to disk before they are lost.
    pub fn take_pending_l2_evictions(&mut self) -> Vec<(u64, L2Table)> {
        self.l2_tables.take_pending_evictions()
    }

    /// Evict a specific L2 table from the cache.
    ///
    /// If the evicted entry is dirty, it is returned so the caller can
    /// write it to disk. Returns `None` if not present or clean.
    pub fn evict_l2_table(&mut self, offset: ClusterOffset) -> Option<L2Table> {
        self.l2_tables.evict(offset.0)
    }

    /// Flush a single dirty L2 table at `offset` to disk via the callback.
    ///
    /// The entry remains in cache but is marked clean. No-op if the entry
    /// is not present or not dirty.
    pub fn flush_single_l2<F>(&mut self, offset: ClusterOffset, writer: F) -> bool
    where
        F: FnMut(u64, &L2Table),
    {
        let writebacks = self.l2_tables.flush_single(offset.0, writer);
        self.stats.l2_writebacks += writebacks;
        writebacks > 0
    }

    /// Flush all dirty L2 tables via the callback. Entries remain cached but clean.
    pub fn flush_l2_tables<F, E>(&mut self, writer: F) -> Result<(), E>
    where
        F: FnMut(u64, &L2Table) -> Result<(), E>,
    {
        let writebacks = self.l2_tables.flush_all(writer)?;
        self.stats.l2_writebacks += writebacks;
        Ok(())
    }

    // ---- Refcount blocks ----

    /// Look up a cached refcount block by host offset (read-only).
    pub fn get_refcount_block(&mut self, offset: ClusterOffset) -> Option<&RefcountBlock> {
        let result = self.refcount_blocks.get(offset.0);
        if result.is_some() {
            self.stats.refcount_hits += 1;
        } else {
            self.stats.refcount_misses += 1;
        }
        result
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
        self.refcount_blocks.get_entry_mut(offset.0)
    }

    /// Insert a refcount block into the cache.
    pub fn insert_refcount_block(
        &mut self,
        offset: ClusterOffset,
        block: RefcountBlock,
        dirty: bool,
    ) {
        let effective_dirty = dirty && self.mode == CacheMode::WriteBack;
        self.refcount_blocks.insert(offset.0, block, effective_dirty);
    }

    /// Take all dirty refcount blocks that were evicted by LRU pressure.
    pub fn take_pending_refcount_evictions(&mut self) -> Vec<(u64, RefcountBlock)> {
        self.refcount_blocks.take_pending_evictions()
    }

    /// Evict a specific refcount block from the cache.
    ///
    /// Returns the block if it was dirty.
    pub fn evict_refcount_block(&mut self, offset: ClusterOffset) -> Option<RefcountBlock> {
        self.refcount_blocks.evict(offset.0)
    }

    /// Flush all dirty refcount blocks via the callback.
    pub fn flush_refcount_blocks<F, E>(&mut self, writer: F) -> Result<(), E>
    where
        F: FnMut(u64, &RefcountBlock) -> Result<(), E>,
    {
        let writebacks = self.refcount_blocks.flush_all(writer)?;
        self.stats.refcount_writebacks += writebacks;
        Ok(())
    }

    /// Whether there are any pending dirty evictions that need writing.
    pub fn has_pending_evictions(&self) -> bool {
        !self.l2_tables.pending_evictions.is_empty()
            || !self.refcount_blocks.pending_evictions.is_empty()
    }

    /// Drain all entries (for close/drop). Returns dirty L2 and refcount entries.
    pub fn drain_dirty(&mut self) -> (Vec<(u64, L2Table)>, Vec<(u64, RefcountBlock)>) {
        (self.l2_tables.drain_dirty(), self.refcount_blocks.drain_dirty())
    }

    // ---- Bitmap data (simple, no dirty tracking) ----

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

    // ---- Hash data (simple, no dirty tracking) ----

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
