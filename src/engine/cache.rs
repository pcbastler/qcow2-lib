//! LRU metadata cache for L2 tables and refcount blocks.
//!
//! Caches frequently accessed metadata tables in memory to avoid
//! repeated I/O. Keyed by the host file offset where each table
//! was loaded from.

use std::num::NonZeroUsize;

use lru::LruCache;

use crate::format::l2::L2Table;
use crate::format::refcount::RefcountBlock;
use crate::format::types::ClusterOffset;

/// Configuration for cache capacities.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of L2 tables to cache.
    pub l2_table_capacity: usize,
    /// Maximum number of refcount blocks to cache.
    pub refcount_block_capacity: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l2_table_capacity: 32,
            refcount_block_capacity: 16,
        }
    }
}

/// LRU cache for frequently accessed QCOW2 metadata.
///
/// Maintains separate caches for L2 tables and refcount blocks because
/// their access patterns and sizes may differ. Keyed by [`ClusterOffset`]
/// (the host file offset where the metadata was read from).
///
/// In Phase 1 (read-only), entries are never dirty and can be freely evicted.
pub struct MetadataCache {
    l2_tables: LruCache<u64, L2Table>,
    refcount_blocks: LruCache<u64, RefcountBlock>,
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
}

impl MetadataCache {
    /// Create a new metadata cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            l2_tables: LruCache::new(
                NonZeroUsize::new(config.l2_table_capacity).unwrap_or(NonZeroUsize::new(1).unwrap()),
            ),
            refcount_blocks: LruCache::new(
                NonZeroUsize::new(config.refcount_block_capacity)
                    .unwrap_or(NonZeroUsize::new(1).unwrap()),
            ),
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

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.l2_tables.clear();
        self.refcount_blocks.clear();
    }

    /// Get cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::l2::L2Table;

    fn make_l2_table(cluster_bits: u32) -> L2Table {
        let cluster_size = 1usize << cluster_bits;
        let buf = vec![0u8; cluster_size];
        L2Table::read_from(&buf, cluster_bits).unwrap()
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
}
