//! Tests for refcount_manager (originally in engine/refcount_manager.rs)

use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::refcount_manager::{AllocationMode, RefcountManager};
use crate::error::Error;
use crate::format::constants::REFCOUNT_TABLE_ENTRY_SIZE;
use crate::format::header::Header;
use crate::format::refcount::RefcountBlock;
use crate::format::types::ClusterOffset;
use crate::io::MemoryBackend;
use crate::IoBackend;
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
fn append_mode_returns_sequential_offsets() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr =
        RefcountManager::load_with_mode(&backend, &header, AllocationMode::Append).unwrap();
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

// cluster_to_refcount_index_calculation: removed (accesses private method across crate boundary)

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
fn load_with_append_mode() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr =
        RefcountManager::load_with_mode(&backend, &header, AllocationMode::Append).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    assert_eq!(mgr.allocation_mode(), AllocationMode::Append);

    let initial_end = mgr.state().next_cluster_offset;
    let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_eq!(c1.0, initial_end);

    let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_ne!(c1, c2, "allocator must not return the same cluster twice");
    assert_eq!(c2.0, initial_end + CLUSTER_SIZE as u64);
}

#[test]
fn debug_format() {
    let header = make_header(1);
    let backend = make_backend(1, &[]);
    let mgr = RefcountManager::load(&backend, &header).unwrap();
    let debug_str = format!("{mgr:?}");
    assert!(debug_str.contains("RefcountManager"));
    assert!(debug_str.contains("Scanning"));
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

// ---- ScanningAllocator tests ----

#[test]
fn default_mode_is_scanning() {
    let header = make_header(1);
    let backend = make_backend(1, &[]);
    let mgr = RefcountManager::load(&backend, &header).unwrap();
    assert_eq!(mgr.allocation_mode(), AllocationMode::Scanning);
}

#[test]
fn scanning_reuses_freed_cluster() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Allocate a cluster, then free it
    let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    mgr.free_cluster(c1.0, &backend, &mut cache).unwrap();

    // Next allocation should reuse the freed cluster
    let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_eq!(c2.0, c1.0, "scanning allocator should reuse freed cluster");
}

#[test]
fn scanning_falls_back_to_append() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Mark all clusters in the existing range as used so the scanner
    // finds nothing free and falls back to append.
    let cluster_count = mgr.state().next_cluster_offset / CLUSTER_SIZE as u64;
    for i in 0..cluster_count {
        mgr.set_refcount(i * CLUSTER_SIZE as u64, 1, &backend, &mut cache)
            .unwrap();
    }

    let initial_end = mgr.state().next_cluster_offset;
    let c = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_eq!(c.0, initial_end, "should append at end when no free clusters");
}

#[test]
fn scanning_hint_moves_cursor_back() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Set several clusters as used
    mgr.set_refcount(0, 1, &backend, &mut cache).unwrap();
    mgr.set_refcount(CLUSTER_SIZE as u64, 1, &backend, &mut cache)
        .unwrap();
    mgr.set_refcount(2 * CLUSTER_SIZE as u64, 1, &backend, &mut cache)
        .unwrap();

    // Allocate once to advance the scan cursor past all used clusters
    let _ = mgr.allocate_cluster(&backend, &mut cache).unwrap();

    // Free cluster 1 -- hint should move cursor back
    mgr.free_cluster(CLUSTER_SIZE as u64, &backend, &mut cache)
        .unwrap();

    // Next allocation should find the freed cluster
    let c = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_eq!(
        c.0,
        CLUSTER_SIZE as u64,
        "should allocate the freed cluster"
    );
}

#[test]
fn append_mode_ignores_free_clusters() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr =
        RefcountManager::load_with_mode(&backend, &header, AllocationMode::Append).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Allocate, free, then allocate again
    let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    mgr.free_cluster(c1.0, &backend, &mut cache).unwrap();

    // In append mode, the freed cluster should NOT be reused
    let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    assert_ne!(
        c2.0, c1.0,
        "append mode should not reuse freed clusters"
    );
    assert!(c2.0 > c1.0, "append mode should allocate at end");
}

#[test]
fn decrement_to_zero_hints_scanner() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Set cluster 1 refcount to 2, advance scan cursor past it
    let offset = CLUSTER_SIZE as u64;
    mgr.set_refcount(offset, 2, &backend, &mut cache).unwrap();
    // Allocate to advance cursor
    let _ = mgr.allocate_cluster(&backend, &mut cache).unwrap();

    // Decrement from 2->1: no hint (still in use)
    mgr.decrement_refcount(offset, &backend, &mut cache)
        .unwrap();

    // Decrement from 1->0: should hint scanner to find it
    mgr.decrement_refcount(offset, &backend, &mut cache)
        .unwrap();

    // Verify the cluster is now free (refcount == 0)
    let rc = mgr.get_refcount(offset, &backend, &mut cache).unwrap();
    assert_eq!(rc, 0);
}

#[test]
fn scanning_after_multiple_frees() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Allocate 3 clusters
    let c1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    let c2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    let c3 = mgr.allocate_cluster(&backend, &mut cache).unwrap();

    // Free them (c1 first, then c3, then c2)
    mgr.free_cluster(c1.0, &backend, &mut cache).unwrap();
    mgr.free_cluster(c3.0, &backend, &mut cache).unwrap();
    mgr.free_cluster(c2.0, &backend, &mut cache).unwrap();

    // Allocate again -- should reuse freed clusters
    let r1 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    let r2 = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    let r3 = mgr.allocate_cluster(&backend, &mut cache).unwrap();

    let mut reused: Vec<u64> = vec![r1.0, r2.0, r3.0];
    reused.sort();
    let mut original: Vec<u64> = vec![c1.0, c2.0, c3.0];
    original.sort();
    assert_eq!(
        reused, original,
        "all freed clusters should be reused"
    );
}

// ---- allocate_contiguous_clusters tests ----

#[test]
fn allocate_contiguous_returns_sequential() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    let initial_end = mgr.state().next_cluster_offset;
    let first = mgr
        .allocate_contiguous_clusters(3, &backend, &mut cache)
        .unwrap();

    assert_eq!(first.0, initial_end);

    // Verify all 3 clusters have refcount 1
    for i in 0..3 {
        let offset = first.0 + i * CLUSTER_SIZE as u64;
        let rc = mgr.get_refcount(offset, &backend, &mut cache).unwrap();
        assert_eq!(rc, 1, "cluster {i} should have refcount 1");
    }

    // next_cluster_offset should be past all 3
    assert_eq!(
        mgr.state().next_cluster_offset,
        initial_end + 3 * CLUSTER_SIZE as u64
    );
}

#[test]
fn allocate_contiguous_skips_free_gaps() {
    let block_offset = 3 * CLUSTER_SIZE as u64;
    let header = make_header(1);
    let backend = make_backend(1, &[(0, block_offset)]);
    let mut mgr = RefcountManager::load(&backend, &header).unwrap();
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Allocate a cluster, then free it to create a gap
    let gap = mgr.allocate_cluster(&backend, &mut cache).unwrap();
    mgr.free_cluster(gap.0, &backend, &mut cache).unwrap();

    // allocate_contiguous should ignore the gap and append at end
    let end_before = mgr.state().next_cluster_offset;
    let first = mgr
        .allocate_contiguous_clusters(2, &backend, &mut cache)
        .unwrap();

    assert_eq!(
        first.0, end_before,
        "contiguous allocation should append at end, ignoring gaps"
    );
}
