//! LRU metadata cache for L2 tables and refcount blocks.
//!
//! Caches frequently accessed metadata tables in memory to avoid
//! repeated I/O. Keyed by the host file offset where each table
//! was loaded from.

extern crate alloc;

use alloc::vec::Vec;

use crate::format::l2::L2Table;
use crate::format::refcount::RefcountBlock;
use crate::format::types::ClusterOffset;
use crate::lru::LruCache;

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
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l2_table_capacity: 32,
            refcount_block_capacity: 16,
            bitmap_data_capacity: 8,
            hash_data_capacity: 16,
        }
    }
}

/// LRU cache for frequently accessed QCOW2 metadata.
///
/// Maintains separate caches for L2 tables and refcount blocks because
/// their access patterns and sizes may differ. Keyed by [`ClusterOffset`]
/// (the host file offset where the metadata was read from).
pub struct MetadataCache {
    l2_tables: LruCache<u64, L2Table>,
    refcount_blocks: LruCache<u64, RefcountBlock>,
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
}

impl MetadataCache {
    /// Create a new metadata cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            l2_tables: LruCache::new(config.l2_table_capacity),
            refcount_blocks: LruCache::new(config.refcount_block_capacity),
            bitmap_data: LruCache::new(config.bitmap_data_capacity),
            hash_data: LruCache::new(config.hash_data_capacity),
            stats: CacheStats::default(),
        }
    }

    /// Look up a cached L2 table by host offset.
    pub fn get_l2_table(&mut self, offset: ClusterOffset) -> Option<&L2Table> {
        let result = self.l2_tables.get(&offset.0);
        if result.is_some() {
            self.stats.l2_hits += 1;
        } else {
            self.stats.l2_misses += 1;
        }
        result
    }

    /// Insert an L2 table into the cache.
    pub fn insert_l2_table(&mut self, offset: ClusterOffset, table: L2Table) {
        self.l2_tables.put(offset.0, table);
    }

    /// Look up a cached refcount block by host offset.
    pub fn get_refcount_block(&mut self, offset: ClusterOffset) -> Option<&RefcountBlock> {
        let result = self.refcount_blocks.get(&offset.0);
        if result.is_some() {
            self.stats.refcount_hits += 1;
        } else {
            self.stats.refcount_misses += 1;
        }
        result
    }

    /// Insert a refcount block into the cache.
    pub fn insert_refcount_block(&mut self, offset: ClusterOffset, block: RefcountBlock) {
        self.refcount_blocks.put(offset.0, block);
    }

    /// Evict a specific L2 table from the cache.
    ///
    /// Used by the write path after modifying an L2 table on disk,
    /// so that subsequent reads reload the updated version.
    pub fn evict_l2_table(&mut self, offset: ClusterOffset) {
        self.l2_tables.pop(&offset.0);
    }

    /// Evict a specific refcount block from the cache.
    ///
    /// Used by the write path after modifying a refcount block on disk.
    pub fn evict_refcount_block(&mut self, offset: ClusterOffset) {
        self.refcount_blocks.pop(&offset.0);
    }

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

    /// Clear all cached entries.
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

    #[test]
    fn insert_and_get_l2_table() {
        let mut cache = MetadataCache::new(CacheConfig::default());
        let table = make_l2_table(16);
        let offset = ClusterOffset(0x10000);

        cache.insert_l2_table(offset, table.clone());
        let cached = cache.get_l2_table(offset);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), table.len());
    }

    #[test]
    fn cache_miss_returns_none() {
        let mut cache = MetadataCache::new(CacheConfig::default());
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

        // Insert 3 tables into a capacity-2 cache
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16));
        cache.insert_l2_table(ClusterOffset(0x30000), make_l2_table(16));

        // First entry should have been evicted
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
        // Other two should still be present
        assert!(cache.get_l2_table(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_l2_table(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn stats_tracking() {
        let mut cache = MetadataCache::new(CacheConfig::default());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));

        cache.get_l2_table(ClusterOffset(0x10000)); // hit
        cache.get_l2_table(ClusterOffset(0x20000)); // miss
        cache.get_l2_table(ClusterOffset(0x10000)); // hit

        assert_eq!(cache.stats().l2_hits, 2);
        assert_eq!(cache.stats().l2_misses, 1);
    }

    #[test]
    fn clear_empties_cache() {
        let mut cache = MetadataCache::new(CacheConfig::default());
        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));
        cache.clear();
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
    }

    // ---- Edge cases ----

    #[test]
    fn capacity_one_evicts_on_every_insert() {
        let config = CacheConfig {
            l2_table_capacity: 1,
            refcount_block_capacity: 1,
            bitmap_data_capacity: 1,
            ..Default::default()
        };
        let mut cache = MetadataCache::new(config);

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_some());

        // Second insert evicts the first
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16));
        assert!(cache.get_l2_table(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_l2_table(ClusterOffset(0x20000)).is_some());
    }

    #[test]
    fn refcount_block_cache() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(CacheConfig::default());

        let data = vec![0u8; 64];
        let block = RefcountBlock::read_from(&data, 4).unwrap(); // 16-bit

        cache.insert_refcount_block(ClusterOffset(0x30000), block.clone());
        let cached = cache.get_refcount_block(ClusterOffset(0x30000));
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), block.len());

        assert_eq!(cache.stats().refcount_hits, 1);
        assert_eq!(cache.stats().refcount_misses, 0);

        // Miss
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

        cache.insert_refcount_block(ClusterOffset(0x10000), make_block());
        cache.insert_refcount_block(ClusterOffset(0x20000), make_block());
        cache.insert_refcount_block(ClusterOffset(0x30000), make_block());

        // First entry evicted
        assert!(cache.get_refcount_block(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_refcount_block(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_refcount_block(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn mixed_l2_and_refcount_stats() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(CacheConfig::default());

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));
        let block_data = vec![0u8; 32];
        let block = RefcountBlock::read_from(&block_data, 4).unwrap();
        cache.insert_refcount_block(ClusterOffset(0x20000), block);

        cache.get_l2_table(ClusterOffset(0x10000));     // L2 hit
        cache.get_l2_table(ClusterOffset(0x99999));     // L2 miss
        cache.get_refcount_block(ClusterOffset(0x20000)); // refcount hit
        cache.get_refcount_block(ClusterOffset(0x88888)); // refcount miss

        assert_eq!(cache.stats().l2_hits, 1);
        assert_eq!(cache.stats().l2_misses, 1);
        assert_eq!(cache.stats().refcount_hits, 1);
        assert_eq!(cache.stats().refcount_misses, 1);
    }

    #[test]
    fn evict_l2_table_removes_entry() {
        let mut cache = MetadataCache::new(CacheConfig::default());
        let offset = ClusterOffset(0x10000);
        cache.insert_l2_table(offset, make_l2_table(16));
        assert!(cache.get_l2_table(offset).is_some());

        cache.evict_l2_table(offset);
        assert!(cache.get_l2_table(offset).is_none());
    }

    #[test]
    fn evict_refcount_block_removes_entry() {
        use crate::format::refcount::RefcountBlock;

        let mut cache = MetadataCache::new(CacheConfig::default());
        let offset = ClusterOffset(0x20000);
        let block = RefcountBlock::read_from(&[0u8; 64], 4).unwrap();
        cache.insert_refcount_block(offset, block);
        assert!(cache.get_refcount_block(offset).is_some());

        cache.evict_refcount_block(offset);
        assert!(cache.get_refcount_block(offset).is_none());
    }

    // ---- Bitmap data cache ----

    #[test]
    fn bitmap_data_insert_and_get() {
        let mut cache = MetadataCache::new(CacheConfig::default());
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
        let mut cache = MetadataCache::new(CacheConfig::default());
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

        // First entry evicted
        assert!(cache.get_bitmap_data(ClusterOffset(0x10000)).is_none());
        assert!(cache.get_bitmap_data(ClusterOffset(0x20000)).is_some());
        assert!(cache.get_bitmap_data(ClusterOffset(0x30000)).is_some());
    }

    #[test]
    fn bitmap_data_evict_specific() {
        let mut cache = MetadataCache::new(CacheConfig::default());
        let offset = ClusterOffset(0x40000);
        cache.insert_bitmap_data(offset, vec![0xFF; 128]);
        assert!(cache.get_bitmap_data(offset).is_some());

        cache.evict_bitmap_data(offset);
        assert!(cache.get_bitmap_data(offset).is_none());
    }

    #[test]
    fn bitmap_data_stats_tracking() {
        let mut cache = MetadataCache::new(CacheConfig::default());
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
        let mut cache = MetadataCache::new(CacheConfig::default());
        cache.insert_bitmap_data(ClusterOffset(0x10000), vec![1; 64]);
        cache.insert_l2_table(ClusterOffset(0x20000), make_l2_table(16));

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

        let mut cache = MetadataCache::new(CacheConfig::default());

        cache.insert_l2_table(ClusterOffset(0x10000), make_l2_table(16));
        let block = RefcountBlock::read_from(&[0u8; 64], 4).unwrap();
        cache.insert_refcount_block(ClusterOffset(0x20000), block);
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
