//! Tests for cluster_mapping (originally in engine/cluster_mapping.rs)

use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::cluster_mapping::{ClusterMapper, ClusterResolution};
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::constants::*;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::l2::SubclusterBitmap;
use crate::format::types::*;
use crate::io::MemoryBackend;
use byteorder::{BigEndian, ByteOrder};

const CLUSTER_BITS: u32 = 16;
const CLUSTER_SIZE: usize = 1 << 16; // 65536
const IMAGE_SIZE: u64 = 10 * CLUSTER_SIZE as u64;

/// Build a minimal QCOW2 image in memory with specific L1/L2 entries.
fn build_test_image(l2_entries: &[(u32, u64)]) -> (MemoryBackend, L1Table) {
    // Layout:
    // Cluster 0: header (unused in this test)
    // Cluster 1: L1 table
    // Cluster 2: L2 table
    // Cluster 3+: data clusters

    let l1_offset = CLUSTER_SIZE; // cluster 1
    let l2_offset = 2 * CLUSTER_SIZE; // cluster 2

    // Build L1 table with one entry pointing to L2 at cluster 2
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    // Build L2 table
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    for &(index, raw_entry) in l2_entries {
        let offset = index as usize * L2_ENTRY_SIZE;
        BigEndian::write_u64(&mut l2_buf[offset..], raw_entry);
    }

    // Assemble image
    let image_size = 10 * CLUSTER_SIZE;
    let mut image_data = vec![0u8; image_size];
    image_data[l1_offset..l1_offset + l1_buf.len()].copy_from_slice(&l1_buf);
    image_data[l2_offset..l2_offset + CLUSTER_SIZE].copy_from_slice(&l2_buf);

    (MemoryBackend::new(image_data), l1_table)
}

#[test]
fn resolve_unallocated_l1() {
    // L1 entry is zero (unallocated)
    let l1_buf = vec![0u8; L1_ENTRY_SIZE];
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(CLUSTER_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper
        .resolve(GuestOffset(0), &backend, &mut cache)
        .unwrap();
    assert_eq!(result, ClusterResolution::Unallocated);
}

#[test]
fn resolve_standard_allocated() {
    let data_cluster_offset = 3 * CLUSTER_SIZE as u64;
    let l2_raw = data_cluster_offset | L2_COPIED_FLAG;
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper
        .resolve(GuestOffset(42), &backend, &mut cache)
        .unwrap();
    assert_eq!(
        result,
        ClusterResolution::Allocated {
            host_offset: ClusterOffset(data_cluster_offset),
            intra_cluster_offset: IntraClusterOffset(42),
            subclusters: SubclusterBitmap::all_allocated(),
        }
    );
}

#[test]
fn resolve_zero_cluster() {
    let l2_raw = L2_ZERO_FLAG;
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper
        .resolve(GuestOffset(100), &backend, &mut cache)
        .unwrap();
    assert_eq!(result, ClusterResolution::Zero {
        bitmap: SubclusterBitmap::all_zero(),
        intra_cluster_offset: IntraClusterOffset(100),
    });
}

#[test]
fn resolve_unallocated_l2() {
    let (backend, l1_table) = build_test_image(&[]); // All L2 entries are 0
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper
        .resolve(GuestOffset(0), &backend, &mut cache)
        .unwrap();
    assert_eq!(result, ClusterResolution::Unallocated);
}

#[test]
fn resolve_compressed_cluster() {
    let desc = CompressedClusterDescriptor {
        host_offset: 0x5000,
        compressed_size: 2 * 512,
    };
    let l2_raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper
        .resolve(GuestOffset(256), &backend, &mut cache)
        .unwrap();
    assert_eq!(
        result,
        ClusterResolution::Compressed {
            descriptor: desc,
            intra_cluster_offset: IntraClusterOffset(256),
        }
    );
}

#[test]
fn l2_table_is_cached() {
    let data_offset = 3 * CLUSTER_SIZE as u64;
    let l2_raw = data_offset | L2_COPIED_FLAG;
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    // First resolve: cache miss
    mapper
        .resolve(GuestOffset(0), &backend, &mut cache)
        .unwrap();
    assert_eq!(cache.stats().l2_misses, 1);
    assert_eq!(cache.stats().l2_hits, 0);

    // Second resolve: cache hit
    mapper
        .resolve(GuestOffset(0), &backend, &mut cache)
        .unwrap();
    assert_eq!(cache.stats().l2_hits, 1);
}

// ---- Edge cases ----

#[test]
fn l1_index_out_of_bounds() {
    // L1 table has only 1 entry. A guest offset that maps to L1 index >= 1
    // should fail.
    let l1_buf = vec![0u8; L1_ENTRY_SIZE];
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(10 * CLUSTER_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    // cluster_bits=16 -> l2_entries=8192 -> L1 boundary at 8192 * 65536 = 0x2000_0000
    let beyond_l1 = 8192u64 * 65536;
    let result = mapper.resolve(GuestOffset(beyond_l1), &backend, &mut cache);
    assert!(result.is_err(), "should fail for L1 index out of bounds");
}

#[test]
fn same_offset_resolves_identically_twice() {
    // Verify that resolving the same offset twice (cache hit path)
    // returns the same result.
    let data_offset = 3 * CLUSTER_SIZE as u64;
    let l2_raw = data_offset | L2_COPIED_FLAG;
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result1 = mapper
        .resolve(GuestOffset(42), &backend, &mut cache)
        .unwrap();
    let result2 = mapper
        .resolve(GuestOffset(42), &backend, &mut cache)
        .unwrap();
    assert_eq!(result1, result2);
    assert_eq!(cache.stats().l2_misses, 1);
    assert_eq!(cache.stats().l2_hits, 1);
}

#[test]
fn intra_cluster_offset_propagated_correctly() {
    let data_offset = 3 * CLUSTER_SIZE as u64;
    let l2_raw = data_offset | L2_COPIED_FLAG;
    let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Guest offset 12345 -> intra = 12345 (within first cluster)
    let result = mapper
        .resolve(GuestOffset(12345), &backend, &mut cache)
        .unwrap();
    assert_eq!(
        result,
        ClusterResolution::Allocated {
            host_offset: ClusterOffset(data_offset),
            intra_cluster_offset: IntraClusterOffset(12345),
            subclusters: SubclusterBitmap::all_allocated(),
        }
    );
}

// ---- L2 bounds-checking tests ----

#[test]
fn reject_l2_table_beyond_file() {
    // L1 points to an L2 table whose offset exceeds the file size.
    let fake_l2_offset = 20 * CLUSTER_SIZE as u64; // well beyond IMAGE_SIZE
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(fake_l2_offset), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
    assert!(result.is_err(), "should reject L2 table beyond file");
    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::error::Error::Format(crate::error::FormatError::MetadataOffsetBeyondEof { .. })),
        "expected MetadataOffsetBeyondEof, got {err:?}"
    );
}

#[test]
fn reject_l2_table_offset_beyond_eof() {
    // L1 points to an L2 offset beyond the file (L1_OFFSET_MASK caps at 0x00ff_ffff_ffff_fe00,
    // so arithmetic overflow is unreachable -- but MetadataOffsetBeyondEof must catch it).
    let huge_offset = u64::MAX - 100; // masked to L1_OFFSET_MASK by with_l2_offset
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(huge_offset), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
    assert!(
        matches!(result, Err(crate::error::Error::Format(crate::error::FormatError::MetadataOffsetBeyondEof { .. }))),
        "should reject L2 offset beyond file, got {result:?}"
    );
}

// ---- Write-support methods ----

#[test]
fn l1_entry_read() {
    let entry = L1Entry::with_l2_offset(ClusterOffset(0x20000), true);
    let mut l1_buf = vec![0u8; 2 * L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf[L1_ENTRY_SIZE..], entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 2).unwrap();
    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);

    assert!(mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());
    assert_eq!(mapper.l1_entry(L1Index(1)).unwrap(), entry);
}

#[test]
fn set_l1_entry_updates_table() {
    let l1_table = L1Table::new_empty(4);
    let mut mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);

    let entry = L1Entry::with_l2_offset(ClusterOffset(0x30000), true);
    mapper.set_l1_entry(L1Index(2), entry).unwrap();
    assert_eq!(mapper.l1_entry(L1Index(2)).unwrap(), entry);
}

#[test]
fn set_file_size_extends_boundary() {
    let l2_offset = 12 * CLUSTER_SIZE as u64; // beyond original IMAGE_SIZE
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let mut mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(20 * CLUSTER_SIZE);
    let mut cache = MetadataCache::new(CacheConfig::default());

    // Should fail with original file size
    assert!(mapper.resolve(GuestOffset(0), &backend, &mut cache).is_err());

    // After extending file size, should succeed
    mapper.set_file_size(20 * CLUSTER_SIZE as u64);
    let result = mapper.resolve(GuestOffset(0), &backend, &mut cache).unwrap();
    assert_eq!(result, ClusterResolution::Unallocated);
}

#[test]
fn valid_l2_table_at_file_boundary_ok() {
    // L2 table starts exactly at the last valid position: file_size - cluster_size.
    // This should succeed.
    let l2_offset = IMAGE_SIZE - CLUSTER_SIZE as u64; // cluster 9
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);
    let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
    let mut cache = MetadataCache::new(CacheConfig::default());

    // All L2 entries are zero -> Unallocated
    let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
    assert_eq!(result.unwrap(), ClusterResolution::Unallocated);
}

#[test]
fn replace_l1_table_updates_mapping() {
    let l1_table = L1Table::new_empty(1);
    let mut mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);

    // Start with empty table
    assert!(mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());

    // Replace with a table that has an entry
    let mut new_table = L1Table::new_empty(2);
    let entry = L1Entry::with_l2_offset(ClusterOffset(0x20000), true);
    new_table.set(L1Index(1), entry).unwrap();
    mapper.replace_l1_table(new_table);

    assert_eq!(mapper.l1_table().len(), 2);
    assert_eq!(mapper.l1_entry(L1Index(1)).unwrap(), entry);
}

#[test]
fn l1_table_mut_allows_in_place_grow() {
    let l1_table = L1Table::new_empty(2);
    let mut mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false }, IMAGE_SIZE);

    mapper.l1_table_mut().grow(4);
    assert_eq!(mapper.l1_table().len(), 4);
    assert!(mapper.l1_entry(L1Index(3)).unwrap().is_unallocated());
}
