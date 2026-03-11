//! Tests for writer (originally in engine/writer.rs)

use crate::engine::cache::{CacheConfig, CacheMode, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::refcount_manager::RefcountManager;
use crate::engine::writer::Qcow2Writer;
use crate::error::Error;
use crate::format::constants::*;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap, SubclusterState};
use crate::format::types::*;
use crate::io::MemoryBackend;
use crate::engine::compression::StdCompressor;
use crate::IoBackend;
use byteorder::{BigEndian, ByteOrder};

const CLUSTER_BITS: u32 = 16;
const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;
const GEO_STD: ClusterGeometry = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false };
const VIRTUAL_SIZE: u64 = 1 << 30; // 1 GiB

/// Standard test image layout:
/// - Cluster 0: Header
/// - Cluster 1: L1 table (1 entry)
/// - Cluster 2: Refcount table (1 cluster)
/// - Cluster 3: Refcount block 0
/// - Cluster 4+: Free
struct TestSetup {
    backend: MemoryBackend,
    mapper: ClusterMapper,
    cache: MetadataCache,
    refcount_manager: RefcountManager,
    l1_table_offset: ClusterOffset,
}

fn make_header() -> crate::format::header::Header {
    crate::format::header::Header {
        version: 3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits: CLUSTER_BITS,
        virtual_size: VIRTUAL_SIZE,
        crypt_method: 0,
        l1_table_entries: 1,
        l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
        refcount_table_offset: ClusterOffset(2 * CLUSTER_SIZE as u64),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
        compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
        autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
        refcount_order: 4,
        header_length: 104,
        compression_type: 0,
    }
}

fn setup() -> TestSetup {
    setup_with_l2(None)
}

/// Setup with an optional pre-populated L2 table.
/// If l2_entries is Some, an L2 table is placed at cluster 4,
/// and the L1 entry points to it.
fn setup_with_l2(l2_entries: Option<&[(u32, L2Entry)]>) -> TestSetup {
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;

    let initial_clusters = if l2_entries.is_some() { 5 } else { 4 };
    let mut data = vec![0u8; initial_clusters * CLUSTER_SIZE];

    // Refcount table: entry 0 -> block at cluster 3
    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    // Refcount block: set refcounts for clusters 0-3 (or 0-4) to 1
    for i in 0..initial_clusters {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }

    // L1 table
    let l1_entry = if l2_entries.is_some() {
        L1Entry::with_l2_offset(ClusterOffset(4 * CLUSTER_SIZE as u64), true)
    } else {
        L1Entry::unallocated()
    };
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table at cluster 4 (if requested)
    if let Some(entries) = l2_entries {
        let l2_base = 4 * CLUSTER_SIZE;
        for &(index, entry) in entries {
            let offset = l2_base + index as usize * L2_ENTRY_SIZE;
            BigEndian::write_u64(&mut data[offset..], entry.encode(GEO_STD));
        }
    }

    let backend = MemoryBackend::new(data);

    // Build L1 table
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_STD, file_size);

    let header = make_header();
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    }
}

fn make_writer<'a>(s: &'a mut TestSetup) -> Qcow2Writer<'a> {
    Qcow2Writer::new(
        &mut s.mapper,
        s.l1_table_offset,
        &s.backend,
        &s.backend,
        &mut s.cache,
        &mut s.refcount_manager,
        CLUSTER_BITS,
        VIRTUAL_SIZE,
        COMPRESSION_DEFLATE,
        false,
        None,
        None,
        &StdCompressor,
    )
}

// ---- Basic write tests ----

#[test]
fn write_to_unallocated_allocates_cluster() {
    let mut s = setup();
    let data = vec![0xAB; 512];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // L1 should now point to an L2 table
    assert!(!s.mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());

    // Read back via backend to verify data
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();

    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let l2_entry = l2_table.get(L2Index(0)).unwrap();

    if let L2Entry::Standard { host_offset, copied, .. } = l2_entry {
        assert!(copied);
        let mut read_back = vec![0u8; 512];
        s.backend
            .read_exact_at(&mut read_back, host_offset.0)
            .unwrap();
        assert_eq!(read_back, data);
    } else {
        panic!("expected Standard L2 entry, got {l2_entry:?}");
    }
}

#[test]
fn write_full_cluster() {
    let mut s = setup();
    let data = vec![0xCD; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // Verify round-trip
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut read_back = vec![0u8; CLUSTER_SIZE];
        s.backend
            .read_exact_at(&mut read_back, host_offset.0)
            .unwrap();
        assert_eq!(read_back, data);
    } else {
        panic!("expected Standard L2 entry");
    }
}

#[test]
fn write_in_place_to_standard_copied() {
    let data_cluster = 5 * CLUSTER_SIZE as u64;
    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_cluster),
        copied: true,
        subclusters: SubclusterBitmap::all_allocated(),
    };
    let mut s = setup_with_l2(Some(&[(0, l2_entry)]));

    // Write initial data at the data cluster location
    let initial = vec![0xFF; CLUSTER_SIZE];
    s.backend.write_all_at(&initial, data_cluster).unwrap();

    // Set refcount for cluster 5 to 1 (consistent with L2 pointing here)
    s.refcount_manager
        .set_refcount(data_cluster, 1, &s.backend, &mut s.cache)
        .unwrap();

    // Partial write at offset 100 within the first guest cluster
    let patch = vec![0x42; 64];
    make_writer(&mut s).write_at(&patch, 100).unwrap();

    // Verify in-place write
    let mut read_back = vec![0u8; CLUSTER_SIZE];
    s.backend
        .read_exact_at(&mut read_back, data_cluster)
        .unwrap();
    assert_eq!(&read_back[100..164], &patch[..]);
    assert_eq!(read_back[0], 0xFF); // Unchanged
    assert_eq!(read_back[164], 0xFF); // Unchanged
}

#[test]
fn write_to_zero_cluster_allocates_new() {
    let l2_entry = L2Entry::Zero {
        preallocated_offset: None,
        subclusters: SubclusterBitmap::all_zero(),
    };
    let mut s = setup_with_l2(Some(&[(0, l2_entry)]));

    let data = vec![0xBB; 256];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // The L2 entry should now be Standard
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, .. } => {
            assert!(copied);
            let mut read_back = vec![0u8; CLUSTER_SIZE];
            s.backend
                .read_exact_at(&mut read_back, host_offset.0)
                .unwrap();
            assert_eq!(&read_back[..256], &data[..]);
            // Rest should be zeros (from zero-fill)
            assert!(read_back[256..].iter().all(|&b| b == 0));
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

/// Build a custom setup with a pre-existing data cluster for COW tests.
///
/// Layout: 0=header, 1=L1, 2=reftable, 3=refblock, 4=L2, 5=data cluster.
/// The data cluster at 5 has refcount=2 (shared) and L2 entry has copied=false.
fn setup_with_shared_data(pattern: u8) -> TestSetup {
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;
    let l2_offset = 4 * CLUSTER_SIZE;
    let data_offset = 5 * CLUSTER_SIZE;

    let mut data = vec![0u8; 6 * CLUSTER_SIZE];

    // Refcount table: entry 0 -> block at cluster 3
    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    // Refcount block: clusters 0-4 refcount=1, cluster 5 refcount=2
    for i in 0..5 {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }
    BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

    // Data cluster: fill with pattern
    data[data_offset..data_offset + CLUSTER_SIZE].fill(pattern);

    // L1 table: entry 0 -> L2 at cluster 4, copied=true
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table: entry 0 -> data at cluster 5, copied=false (shared)
    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_offset as u64),
        copied: false,
        subclusters: SubclusterBitmap::all_allocated(),
    };
    BigEndian::write_u64(
        &mut data[l2_offset..],
        l2_entry.encode(GEO_STD),
    );

    let backend = MemoryBackend::new(data);

    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_STD, file_size);

    let header = make_header();
    let refcount_manager =
        RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    }
}

#[test]
fn cow_shared_data_cluster_allocates_new() {
    let mut s = setup_with_shared_data(0xAA);

    let data_offset = 5 * CLUSTER_SIZE as u64;

    // Verify initial refcount is 2
    let rc = s
        .refcount_manager
        .get_refcount(data_offset, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(rc, 2, "shared cluster should start with refcount 2");

    // Write a small amount of data -- should trigger COW
    let write_data = vec![0x11; 64];
    make_writer(&mut s).write_at(&write_data, 0).unwrap();

    // Old cluster refcount should have been decremented from 2 to 1
    let old_rc = s
        .refcount_manager
        .get_refcount(data_offset, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(old_rc, 1, "old cluster refcount should be decremented");
}

#[test]
fn write_beyond_virtual_size_rejected() {
    let mut s = setup();
    let data = vec![0x00; 64];
    let result = make_writer(&mut s).write_at(&data, VIRTUAL_SIZE);
    assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
}

#[test]
fn write_spanning_beyond_virtual_size_rejected() {
    let mut s = setup();
    let data = vec![0x00; 128];
    let result = make_writer(&mut s).write_at(&data, VIRTUAL_SIZE - 64);
    assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
}

#[test]
fn write_spanning_two_clusters() {
    let mut s = setup();
    // Write starting near end of cluster 0, spanning into cluster 1
    let offset = CLUSTER_SIZE as u64 - 100; // virtual offset
    // This maps to L1[0], L2[0] (last 100 bytes) + L1[0], L2[1] (first 156 bytes)
    let data = vec![0xEE; 256];
    make_writer(&mut s).write_at(&data, offset).unwrap();

    // Both L2 entries [0] and [1] should now be allocated
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    let host0 = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied: true, .. } => host_offset,
        other => panic!("expected Standard+copied for cluster 0, got {other:?}"),
    };
    let host1 = match l2_table.get(L2Index(1)).unwrap() {
        L2Entry::Standard { host_offset, copied: true, .. } => host_offset,
        other => panic!("expected Standard+copied for cluster 1, got {other:?}"),
    };

    // Verify data in cluster 0: last 100 bytes should be 0xEE
    let mut tail = vec![0u8; 100];
    s.backend
        .read_exact_at(&mut tail, host0.0 + CLUSTER_SIZE as u64 - 100)
        .unwrap();
    assert!(tail.iter().all(|&b| b == 0xEE), "cluster 0 tail should be 0xEE");

    // Verify data in cluster 1: first 156 bytes should be 0xEE
    let mut head = vec![0u8; 156];
    s.backend.read_exact_at(&mut head, host1.0).unwrap();
    assert!(head.iter().all(|&b| b == 0xEE), "cluster 1 head should be 0xEE");
}

#[test]
fn write_empty_buffer_is_noop() {
    let mut s = setup();
    make_writer(&mut s).write_at(&[], 0).unwrap();
    // L1 should still be unallocated
    assert!(s.mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());
}

#[test]
fn partial_write_to_unallocated_zero_fills_rest() {
    let mut s = setup();
    let data = vec![0xAA; 100];
    make_writer(&mut s).write_at(&data, 200).unwrap();

    // Read the full cluster and verify zero-fill
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut cluster_data = vec![0u8; CLUSTER_SIZE];
        s.backend
            .read_exact_at(&mut cluster_data, host_offset.0)
            .unwrap();
        assert!(cluster_data[..200].iter().all(|&b| b == 0));
        assert_eq!(&cluster_data[200..300], &data[..]);
        assert!(cluster_data[300..].iter().all(|&b| b == 0));
    } else {
        panic!("expected Standard L2 entry");
    }
}

#[test]
fn write_allocates_refcounted_clusters() {
    let mut s = setup();
    let data = vec![0x55; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // The newly allocated L2 table and data cluster should have refcount 1
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();

    let rc = s
        .refcount_manager
        .get_refcount(l2_offset.0, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(rc, 1, "L2 table should have refcount 1");
}

#[test]
fn write_through_l1_persisted_to_disk() {
    let mut s = setup();
    let data = vec![0x77; 64];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // Read L1 entry directly from the backend
    let mut l1_buf = [0u8; 8];
    s.backend
        .read_exact_at(&mut l1_buf, CLUSTER_SIZE as u64)
        .unwrap();
    let raw = BigEndian::read_u64(&l1_buf);
    let l1_entry = L1Entry::from_raw(raw);
    assert!(!l1_entry.is_unallocated());
}

#[test]
fn write_through_l2_persisted_to_disk() {
    let mut s = setup();
    let data = vec![0x88; 64];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // Get L2 table offset from L1
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();

    // Read L2 entry 0 directly from backend
    let mut l2_entry_buf = [0u8; 8];
    s.backend
        .read_exact_at(&mut l2_entry_buf, l2_offset.0)
        .unwrap();
    let raw = BigEndian::read_u64(&l2_entry_buf);
    let l2_entry = L2Entry::decode(raw, CLUSTER_BITS);
    assert!(matches!(
        l2_entry,
        L2Entry::Standard { copied: true, .. }
    ));
}

#[test]
fn multiple_writes_to_same_cluster_reuse_allocation() {
    let mut s = setup();

    // First write
    let data1 = vec![0xAA; 100];
    make_writer(&mut s).write_at(&data1, 0).unwrap();

    // Get the allocated data cluster offset
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let first_host_offset = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, .. } => host_offset,
        other => panic!("expected Standard, got {other:?}"),
    };

    // Second write to same cluster should reuse (in-place write)
    let data2 = vec![0xBB; 100];
    make_writer(&mut s).write_at(&data2, 200).unwrap();

    // Verify same data cluster offset
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let second_host_offset = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, .. } => host_offset,
        other => panic!("expected Standard, got {other:?}"),
    };
    assert_eq!(first_host_offset, second_host_offset);

    // Verify both writes present
    let mut cluster_data = vec![0u8; CLUSTER_SIZE];
    s.backend
        .read_exact_at(&mut cluster_data, first_host_offset.0)
        .unwrap();
    assert_eq!(&cluster_data[..100], &data1[..]);
    assert_eq!(&cluster_data[200..300], &data2[..]);
}

// ---- COW tests ----

#[test]
fn cow_preserves_existing_data_on_partial_write() {
    let mut s = setup_with_shared_data(0xAA);

    // Write 64 bytes at offset 100 within the cluster
    let write_data = vec![0x11; 64];
    make_writer(&mut s).write_at(&write_data, 100).unwrap();

    // Find the new data cluster from the L2 table
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    let new_host = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, .. } => host_offset,
        other => panic!("expected Standard, got {other:?}"),
    };

    // New cluster should NOT be at the old data offset (cluster 5)
    assert_ne!(new_host.0, 5 * CLUSTER_SIZE as u64);

    // Read the new cluster and verify contents
    let mut cluster_data = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut cluster_data, new_host.0).unwrap();

    // Bytes 0-99 should be preserved from old cluster (0xAA)
    assert!(cluster_data[..100].iter().all(|&b| b == 0xAA));
    // Bytes 100-163 should be our write (0x11)
    assert_eq!(&cluster_data[100..164], &write_data[..]);
    // Bytes 164+ should be preserved from old cluster (0xAA)
    assert!(cluster_data[164..CLUSTER_SIZE].iter().all(|&b| b == 0xAA));
}

#[test]
fn cow_sets_copied_flag_on_new_entry() {
    let mut s = setup_with_shared_data(0xBB);

    make_writer(&mut s).write_at(&[0x22; 16], 0).unwrap();

    // Read L2 entry from disk
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { copied: true, .. } => {}
        other => panic!("expected Standard{{copied:true}}, got {other:?}"),
    }
}

#[test]
fn cow_full_cluster_write() {
    let mut s = setup_with_shared_data(0xCC);
    let data_offset = 5 * CLUSTER_SIZE as u64;

    // Full cluster write should still COW (allocate new, decrement old)
    let write_data = vec![0x33; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&write_data, 0).unwrap();

    let old_rc = s
        .refcount_manager
        .get_refcount(data_offset, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(old_rc, 1, "old cluster refcount should be decremented");

    // Verify new cluster has the written data
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut cluster_data = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut cluster_data, host_offset.0).unwrap();
        assert!(cluster_data.iter().all(|&b| b == 0x33));
    }
}

#[test]
fn cow_second_write_is_in_place() {
    let mut s = setup_with_shared_data(0xDD);

    // First write triggers COW
    make_writer(&mut s).write_at(&[0x44; 64], 0).unwrap();

    // Get the new cluster offset
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let first_host = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, .. } => {
            assert!(copied, "should be copied after COW");
            host_offset
        }
        other => panic!("expected Standard, got {other:?}"),
    };

    // Second write should be in-place (same host offset)
    make_writer(&mut s).write_at(&[0x55; 64], 100).unwrap();

    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let second_host = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, .. } => host_offset,
        other => panic!("expected Standard, got {other:?}"),
    };
    assert_eq!(first_host, second_host, "second write should reuse cluster");
}

#[test]
fn cow_l2_table_when_l1_not_copied() {
    // Create a setup where L1 entry has copied=false (shared L2 table)
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;
    let l2_offset = 4 * CLUSTER_SIZE;

    let mut data = vec![0u8; 5 * CLUSTER_SIZE];

    // Refcount table: entry 0 -> block at cluster 3
    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    // Refcount block: clusters 0-3 refcount=1, cluster 4 (L2 table) refcount=2
    for i in 0..4 {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }
    BigEndian::write_u16(&mut data[rb_offset + 4 * 2..], 2);

    // L1 entry: points to L2 table, copied=FALSE (shared with snapshot)
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), false);
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table: entry 0 unallocated (for simplicity)
    // (We'll write to a new cluster)

    let backend = MemoryBackend::new(data);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_STD, file_size);
    let header = make_header();
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    let mut s = TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    };

    // Write should trigger L2 table COW first, then allocate data cluster
    make_writer(&mut s).write_at(&[0x77; 64], 0).unwrap();

    // L1 entry should now be copied=true and point to a new L2 table
    let new_l1 = s.mapper.l1_entry(L1Index(0)).unwrap();
    assert!(new_l1.is_copied(), "L1 should be copied after L2 COW");
    assert_ne!(
        new_l1.l2_table_offset().unwrap().0,
        l2_offset as u64,
        "L1 should point to new L2 table"
    );

    // Old L2 table refcount should have been decremented from 2 to 1
    let old_l2_rc = s
        .refcount_manager
        .get_refcount(l2_offset as u64, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(old_l2_rc, 1, "old L2 table refcount should be decremented");
}

#[test]
fn cow_l2_table_preserves_existing_entries() {
    // Setup: L2 table at cluster 4 with existing entry, L1 copied=false
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;
    let l2_offset_val = 4 * CLUSTER_SIZE;
    let data_offset = 5 * CLUSTER_SIZE;

    let mut data = vec![0u8; 6 * CLUSTER_SIZE];

    // Refcount table
    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    // Refcount block: clusters 0-3 ref=1, cluster 4 (L2) ref=2, cluster 5 (data) ref=2
    for i in 0..4 {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }
    BigEndian::write_u16(&mut data[rb_offset + 4 * 2..], 2);
    BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

    // L1: copied=false (shared with snapshot)
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset_val as u64), false);
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table: entry 1 -> data at cluster 5, copied=false
    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_offset as u64),
        copied: false,
        subclusters: SubclusterBitmap::all_allocated(),
    };
    BigEndian::write_u64(
        &mut data[l2_offset_val + 8..], // entry 1
        l2_entry.encode(GEO_STD),
    );

    // Data cluster: fill with pattern
    data[data_offset..data_offset + CLUSTER_SIZE].fill(0xEE);

    let backend = MemoryBackend::new(data);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_STD, file_size);
    let header = make_header();
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    let mut s = TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    };

    // Write to virtual cluster 1 (L2 index 1) -- should COW the L2 table,
    // then COW the data cluster
    let write_data = vec![0xFF; 64];
    make_writer(&mut s)
        .write_at(&write_data, CLUSTER_SIZE as u64)
        .unwrap();

    // The new L2 table should exist at a new offset
    let new_l1 = s.mapper.l1_entry(L1Index(0)).unwrap();
    let new_l2_offset = new_l1.l2_table_offset().unwrap();
    assert_ne!(new_l2_offset.0, l2_offset_val as u64);

    // Read the new L2 table -- entry 0 should still be unallocated
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, new_l2_offset.0).unwrap();
    let new_l2 = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    assert!(matches!(new_l2.get(L2Index(0)).unwrap(), L2Entry::Unallocated));

    // Entry 1 should point to a NEW data cluster (COW'd), with copied=true
    match new_l2.get(L2Index(1)).unwrap() {
        L2Entry::Standard { host_offset, copied, .. } => {
            assert!(copied, "COW'd entry should be copied");
            assert_ne!(host_offset.0, data_offset as u64, "should be a new cluster");
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

// ---- Overflow and compressed write tests ----

#[test]
fn write_u64_overflow_rejected() {
    let mut s = setup();
    // guest_offset near u64::MAX + buf.len() would overflow
    let buf = vec![0xAA; 100];
    let result = make_writer(&mut s).write_at(&buf, u64::MAX - 10);
    assert!(result.is_err(), "should reject write that overflows u64");
}

#[test]
fn write_to_compressed_cluster_decompresses_and_reallocates() {
    use crate::engine::compression;
    use crate::format::compressed::CompressedClusterDescriptor;

    // Create setup with an L2 table (at cluster 4)
    let mut s = setup();

    // First, write a full cluster so we get an L2 table allocated
    let original_data = vec![0xAA; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&original_data, 0).unwrap();

    // Now find where the data cluster landed
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();

    // Compress the original data
    let compressed =
        compression::compress_cluster(&original_data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
            .unwrap()
            .expect("all-0xAA should compress");

    // Allocate a cluster for the compressed data
    let comp_host = s
        .refcount_manager
        .allocate_cluster(&s.backend, &mut s.cache)
        .unwrap();
    let file_size = s.backend.file_size().unwrap();
    s.mapper.set_file_size(file_size);

    // Write compressed data to backend, padded to sector alignment
    let sector_aligned = ((compressed.len() + 511) & !511).max(512);
    let mut padded = vec![0u8; sector_aligned];
    padded[..compressed.len()].copy_from_slice(&compressed);
    s.backend.write_all_at(&padded, comp_host.0).unwrap();

    // Patch L2 entry 0 to be Compressed
    let descriptor = CompressedClusterDescriptor {
        host_offset: comp_host.0,
        compressed_size: sector_aligned as u64,
    };
    let comp_entry = L2Entry::Compressed(descriptor);
    let encoded = comp_entry.encode(GEO_STD);
    let entry_offset = l2_offset.0; // entry index 0
    let mut entry_buf = [0u8; 8];
    BigEndian::write_u64(&mut entry_buf, encoded);
    s.backend.write_all_at(&entry_buf, entry_offset).unwrap();
    s.cache.evict_l2_table(l2_offset);

    // Now write 64 bytes of 0xBB at offset 100 within that compressed cluster
    let write_data = vec![0xBB; 64];
    make_writer(&mut s).write_at(&write_data, 100).unwrap();

    // The L2 entry should now be Standard (decompressed + reallocated)
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_off = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_off.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, .. } => {
            assert!(copied);
            // Read back the full cluster
            let mut readback = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
            // Bytes 0..100 should be 0xAA (original)
            assert!(readback[..100].iter().all(|&b| b == 0xAA));
            // Bytes 100..164 should be 0xBB (our write)
            assert!(readback[100..164].iter().all(|&b| b == 0xBB));
            // Bytes 164.. should be 0xAA (original)
            assert!(readback[164..].iter().all(|&b| b == 0xAA));
        }
        other => panic!("expected Standard after write to compressed, got {other:?}"),
    }
}

// ---- Extended L2 / subcluster tests ----

const GEO_EXT: ClusterGeometry = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: true };

/// Setup with extended L2 entries.
/// Similar to setup_with_l2 but uses 16-byte L2 entries.
fn setup_with_l2_extended(l2_entries: Option<&[(u32, L2Entry)]>) -> TestSetup {
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;

    let used_clusters = if l2_entries.is_some() { 5 } else { 4 };
    // Reserve extra clusters for writer allocations (L2 tables, data clusters)
    let total_clusters = used_clusters + 4;
    let mut data = vec![0u8; total_clusters * CLUSTER_SIZE];

    // Refcount table: entry 0 -> block at cluster 3
    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    // Refcount block: set refcounts for used clusters to 1
    for i in 0..used_clusters {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }

    // L1 table
    let l1_entry = if l2_entries.is_some() {
        L1Entry::with_l2_offset(ClusterOffset(4 * CLUSTER_SIZE as u64), true)
    } else {
        L1Entry::unallocated()
    };
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table at cluster 4 (if requested) — 16-byte entries for extended L2
    if let Some(entries) = l2_entries {
        let l2_base = 4 * CLUSTER_SIZE;
        for &(index, entry) in entries {
            let offset = l2_base + index as usize * L2_ENTRY_SIZE_EXTENDED;
            BigEndian::write_u64(&mut data[offset..], entry.encode(GEO_EXT));
            BigEndian::write_u64(&mut data[offset + 8..], entry.encode_bitmap());
        }
    }

    let backend = MemoryBackend::new(data);

    // Build L1 table
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_EXT, file_size);

    let mut header = make_header();
    header.incompatible_features |=
        crate::format::feature_flags::IncompatibleFeatures::EXTENDED_L2;
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    }
}

/// Setup with shared data cluster and extended L2 entries.
/// Cluster 5 = data, refcount=2, copied=false.
fn setup_with_shared_data_extended(pattern: u8, bitmap: SubclusterBitmap) -> TestSetup {
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;
    let l2_offset = 4 * CLUSTER_SIZE;
    let data_offset = 5 * CLUSTER_SIZE;

    // Reserve extra clusters for writer allocations
    let mut data = vec![0u8; 10 * CLUSTER_SIZE];

    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

    for i in 0..5 {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }
    BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

    // Data cluster: fill with pattern
    data[data_offset..data_offset + CLUSTER_SIZE].fill(pattern);

    // L1 table: entry 0 -> L2 at cluster 4, copied=true
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    // L2 table: entry 0 -> data at cluster 5, copied=false (shared), custom bitmap
    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_offset as u64),
        copied: false,
        subclusters: bitmap,
    };
    BigEndian::write_u64(&mut data[l2_offset..], l2_entry.encode(GEO_EXT));
    BigEndian::write_u64(&mut data[l2_offset + 8..], l2_entry.encode_bitmap());

    let backend = MemoryBackend::new(data);

    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_EXT, file_size);

    let mut header = make_header();
    header.incompatible_features |=
        crate::format::feature_flags::IncompatibleFeatures::EXTENDED_L2;
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    }
}

/// Create a writer with raw_external=true (for error path tests).
fn make_writer_raw_external<'a>(s: &'a mut TestSetup) -> Qcow2Writer<'a> {
    Qcow2Writer::new(
        &mut s.mapper,
        s.l1_table_offset,
        &s.backend,
        &s.backend,
        &mut s.cache,
        &mut s.refcount_manager,
        CLUSTER_BITS,
        VIRTUAL_SIZE,
        COMPRESSION_DEFLATE,
        true,
        None,
        None,
        &StdCompressor,
    )
}

/// Create a writer with extended L2 geometry (standard mode, not raw_external).
fn make_writer_ext<'a>(s: &'a mut TestSetup) -> Qcow2Writer<'a> {
    Qcow2Writer::new(
        &mut s.mapper,
        s.l1_table_offset,
        &s.backend,
        &s.backend,
        &mut s.cache,
        &mut s.refcount_manager,
        CLUSTER_BITS,
        VIRTUAL_SIZE,
        COMPRESSION_DEFLATE,
        false,
        None,
        None,
        &StdCompressor,
    )
}

// ---- Path 5: write_in_place with partial subclusters that are Zero/Unallocated ----

#[test]
fn write_in_place_partial_subcluster_zero_fill() {
    // Setup: extended L2, data cluster at cluster 5, copied=true
    // Bitmap: subcluster 0 = Allocated, subcluster 1 = Zero, rest = Unallocated
    let data_cluster = 5 * CLUSTER_SIZE as u64;
    let sc_size = CLUSTER_SIZE / 32; // 2048 bytes per subcluster with 64K clusters

    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Allocated);
    bitmap.set(1, SubclusterState::Zero);

    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_cluster),
        copied: true,
        subclusters: bitmap,
    };
    let mut s = setup_with_l2_extended(Some(&[(0, l2_entry)]));

    // Fill data cluster with existing data
    let initial = vec![0xAA; CLUSTER_SIZE];
    s.backend.write_all_at(&initial, data_cluster).unwrap();
    s.refcount_manager
        .set_refcount(data_cluster, 1, &s.backend, &mut s.cache)
        .unwrap();

    // Write 100 bytes at offset sc_size + 500 (within subcluster 1 which is Zero)
    // This is a partial write within a Zero subcluster — should zero-fill the rest
    let write_offset = sc_size as u64 + 500;
    let patch = vec![0xBB; 100];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    // Read back the full subcluster 1
    let mut sc1_data = vec![0u8; sc_size];
    s.backend.read_exact_at(&mut sc1_data, data_cluster + sc_size as u64).unwrap();

    // The first 500 bytes of SC 1 should be zeros (zero-fill for Zero subcluster)
    assert!(sc1_data[..500].iter().all(|&b| b == 0),
        "zero-fill portion before write should be zeros");
    // The 100 bytes we wrote
    assert_eq!(&sc1_data[500..600], &patch[..],
        "written data should match");
    // The rest of SC 1 (after the write) should also be zeros
    assert!(sc1_data[600..].iter().all(|&b| b == 0),
        "zero-fill portion after write should be zeros");

    // Verify the L2 entry now has subcluster 1 as Allocated
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { subclusters, .. } => {
            assert_eq!(subclusters.get(0), SubclusterState::Allocated);
            assert_eq!(subclusters.get(1), SubclusterState::Allocated,
                "written subcluster should be Allocated now");
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

#[test]
fn write_in_place_partial_subcluster_unallocated_fill() {
    // Similar to above but the partially-covered subcluster is Unallocated (not Zero)
    let data_cluster = 5 * CLUSTER_SIZE as u64;
    let sc_size = CLUSTER_SIZE / 32;

    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Allocated);
    // subcluster 1 is Unallocated

    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_cluster),
        copied: true,
        subclusters: bitmap,
    };
    let mut s = setup_with_l2_extended(Some(&[(0, l2_entry)]));

    let initial = vec![0xCC; CLUSTER_SIZE];
    s.backend.write_all_at(&initial, data_cluster).unwrap();
    s.refcount_manager
        .set_refcount(data_cluster, 1, &s.backend, &mut s.cache)
        .unwrap();

    // Write partially into subcluster 1
    let write_offset = sc_size as u64 + 100;
    let patch = vec![0xDD; 50];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    // SC 1 should be zero-filled except for our write
    let mut sc1_data = vec![0u8; sc_size];
    s.backend.read_exact_at(&mut sc1_data, data_cluster + sc_size as u64).unwrap();

    assert!(sc1_data[..100].iter().all(|&b| b == 0),
        "zero-fill before write in unallocated subcluster");
    assert_eq!(&sc1_data[100..150], &patch[..]);
    assert!(sc1_data[150..].iter().all(|&b| b == 0),
        "zero-fill after write in unallocated subcluster");
}

#[test]
fn write_in_place_fully_covered_subcluster_no_zero_fill() {
    // When a write fully covers a Zero subcluster, no zero-fill is needed
    let data_cluster = 5 * CLUSTER_SIZE as u64;
    let sc_size = CLUSTER_SIZE / 32;

    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Allocated);
    bitmap.set(1, SubclusterState::Zero);

    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_cluster),
        copied: true,
        subclusters: bitmap,
    };
    let mut s = setup_with_l2_extended(Some(&[(0, l2_entry)]));

    let initial = vec![0xEE; CLUSTER_SIZE];
    s.backend.write_all_at(&initial, data_cluster).unwrap();
    s.refcount_manager
        .set_refcount(data_cluster, 1, &s.backend, &mut s.cache)
        .unwrap();

    // Write exactly one full subcluster (SC 1)
    let write_offset = sc_size as u64;
    let patch = vec![0xFF; sc_size];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    // SC 1 should be entirely our written data (no zero-fill path triggered)
    let mut sc1_data = vec![0u8; sc_size];
    s.backend.read_exact_at(&mut sc1_data, data_cluster + sc_size as u64).unwrap();
    assert!(sc1_data.iter().all(|&b| b == 0xFF));
}

// ---- Path 11: compressed cluster error paths ----

#[test]
fn write_to_compressed_cluster_with_raw_external_rejected() {
    use crate::engine::compression;
    use crate::format::compressed::CompressedClusterDescriptor;

    // First build a setup with a compressed L2 entry using standard (non-external) setup
    let mut s = setup();

    // Write data to get an L2 table, then set up a compressed entry
    let original_data = vec![0xAA; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&original_data, 0).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();

    let compressed =
        compression::compress_cluster(&original_data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
            .unwrap()
            .expect("should compress");

    let comp_host = s
        .refcount_manager
        .allocate_cluster(&s.backend, &mut s.cache)
        .unwrap();
    let file_size = s.backend.file_size().unwrap();
    s.mapper.set_file_size(file_size);

    let sector_aligned = ((compressed.len() + 511) & !511).max(512);
    let mut padded = vec![0u8; sector_aligned];
    padded[..compressed.len()].copy_from_slice(&compressed);
    s.backend.write_all_at(&padded, comp_host.0).unwrap();

    let descriptor = CompressedClusterDescriptor {
        host_offset: comp_host.0,
        compressed_size: sector_aligned as u64,
    };
    let comp_entry = L2Entry::Compressed(descriptor);
    let encoded = comp_entry.encode(GEO_STD);
    let mut entry_buf = [0u8; 8];
    BigEndian::write_u64(&mut entry_buf, encoded);
    s.backend.write_all_at(&entry_buf, l2_offset.0).unwrap();
    s.cache.evict_l2_table(l2_offset);

    // Try to write with raw_external=true — should get CompressedWithExternalData error
    let write_data = vec![0xBB; 64];
    let result = make_writer_raw_external(&mut s).write_at(&write_data, 100);
    assert!(
        matches!(result, Err(Error::CompressedWithExternalData)),
        "expected CompressedWithExternalData, got {result:?}"
    );
}

// ---- Path 1: write_to_new_cluster with non-trivial subcluster bitmap ----

#[test]
fn write_to_new_cluster_with_mixed_zero_bitmap() {
    // Setup: extended L2, a Standard entry with copied=true and mixed subcluster states.
    // Some subclusters are Zero, some are Allocated, some Unallocated.
    // When we create a NEW cluster from this state (e.g., by having it be
    // a Zero entry with mixed bitmap), the subcluster-aware path is triggered.
    //
    // A Zero entry with partial zero subclusters (NOT all_zero, NOT all_unallocated)
    // triggers the write_subclusters path in write_to_new_cluster.
    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Zero);
    bitmap.set(1, SubclusterState::Zero);
    // rest: Unallocated

    // This bitmap is NOT all_zero and NOT all_unallocated → triggers line 70-73
    let l2_entry = L2Entry::Zero {
        preallocated_offset: None,
        subclusters: bitmap,
    };
    let mut s = setup_with_l2_extended(Some(&[(0, l2_entry)]));

    let sc_size = CLUSTER_SIZE / 32;

    // Write 100 bytes at subcluster 1 (partially covering it)
    let write_offset = sc_size as u64 + 200;
    let patch = vec![0x42; 100];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    // Read the new L2 entry
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, subclusters } => {
            assert!(copied);
            // Subcluster 1 should now be Allocated (we wrote to it)
            assert_eq!(subclusters.get(1), SubclusterState::Allocated);
            // Subcluster 0 should still be Zero (preserved from old bitmap)
            assert_eq!(subclusters.get(0), SubclusterState::Zero);
            // Subclusters 2+ should still be Unallocated
            assert_eq!(subclusters.get(2), SubclusterState::Unallocated);

            // Verify data: the 100 bytes we wrote should be at the correct offset
            let mut readback = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
            assert_eq!(&readback[sc_size + 200..sc_size + 300], &patch[..]);
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

#[test]
fn write_to_new_cluster_all_zero_bitmap_fast_path() {
    // All-zero bitmap should use the fast path (no subcluster logic)
    let l2_entry = L2Entry::Zero {
        preallocated_offset: None,
        subclusters: SubclusterBitmap::all_zero(),
    };
    let mut s = setup_with_l2_extended(Some(&[(0, l2_entry)]));

    let patch = vec![0x55; 200];
    make_writer_ext(&mut s).write_at(&patch, 100).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, subclusters, .. } => {
            // Fast path produces all_allocated bitmap
            assert!(subclusters.is_all_allocated());

            let mut readback = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
            // Before the write: zeros
            assert!(readback[..100].iter().all(|&b| b == 0));
            // The write
            assert_eq!(&readback[100..300], &patch[..]);
            // After: zeros
            assert!(readback[300..].iter().all(|&b| b == 0));
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

// ---- Path 6 + 10: COW with mixed subcluster bitmap ----

#[test]
fn cow_mixed_subclusters_copies_allocated_preserves_zero() {
    // Setup: shared data cluster with mixed bitmap
    // SC 0 = Allocated, SC 1 = Zero, SC 2 = Unallocated
    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Allocated);
    bitmap.set(1, SubclusterState::Zero);
    // SC 2+ = Unallocated

    let mut s = setup_with_shared_data_extended(0xAA, bitmap);
    let sc_size = CLUSTER_SIZE / 32;

    // Write 64 bytes into subcluster 2 — triggers COW with mixed bitmap
    let write_offset = 2 * sc_size as u64 + 100;
    let patch = vec![0x77; 64];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    // Verify the new L2 entry
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, subclusters } => {
            assert!(copied, "COW result should have copied flag");
            // SC 0 should still be Allocated (copied from old)
            assert_eq!(subclusters.get(0), SubclusterState::Allocated);
            // SC 1 should still be Zero (preserved)
            assert_eq!(subclusters.get(1), SubclusterState::Zero);
            // SC 2 should be Allocated (we wrote to it)
            assert_eq!(subclusters.get(2), SubclusterState::Allocated);
            // SC 3+ should be Unallocated
            assert_eq!(subclusters.get(3), SubclusterState::Unallocated);

            // Verify SC 0 was actually copied (data should be 0xAA)
            let mut sc0 = vec![0u8; sc_size];
            s.backend.read_exact_at(&mut sc0, host_offset.0).unwrap();
            assert!(sc0.iter().all(|&b| b == 0xAA),
                "SC 0 should be copied from old cluster");

            // Verify our write in SC 2
            let mut sc2 = vec![0u8; sc_size];
            s.backend.read_exact_at(&mut sc2, host_offset.0 + 2 * sc_size as u64).unwrap();
            assert_eq!(&sc2[100..164], &patch[..]);
        }
        other => panic!("expected Standard, got {other:?}"),
    }

    // Old cluster refcount should be decremented
    let old_rc = s
        .refcount_manager
        .get_refcount(5 * CLUSTER_SIZE as u64, &s.backend, &mut s.cache)
        .unwrap();
    assert_eq!(old_rc, 1, "old cluster refcount should be decremented from 2 to 1");
}

#[test]
fn cow_mixed_subclusters_full_write_to_unallocated_sc() {
    // COW with mixed bitmap where write fully covers an unallocated subcluster
    let mut bitmap = SubclusterBitmap::all_unallocated();
    bitmap.set(0, SubclusterState::Allocated);
    bitmap.set(3, SubclusterState::Zero);

    let mut s = setup_with_shared_data_extended(0xCC, bitmap);
    let sc_size = CLUSTER_SIZE / 32;

    // Write exactly one full subcluster (SC 1, which is Unallocated)
    let write_offset = sc_size as u64;
    let patch = vec![0x99; sc_size];
    make_writer_ext(&mut s).write_at(&patch, write_offset).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, subclusters, .. } => {
            assert_eq!(subclusters.get(0), SubclusterState::Allocated);
            assert_eq!(subclusters.get(1), SubclusterState::Allocated);
            assert_eq!(subclusters.get(2), SubclusterState::Unallocated);
            assert_eq!(subclusters.get(3), SubclusterState::Zero);

            // SC 1 should have our data
            let mut sc1 = vec![0u8; sc_size];
            s.backend.read_exact_at(&mut sc1, host_offset.0 + sc_size as u64).unwrap();
            assert!(sc1.iter().all(|&b| b == 0x99));
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

#[test]
fn cow_all_allocated_uses_full_cluster_fast_path() {
    // COW with all_allocated bitmap should use cow_full_cluster (bulk copy)
    let mut s = setup_with_shared_data(0xDD);

    // Write a small amount — should trigger full-cluster COW
    let patch = vec![0x11; 128];
    make_writer(&mut s).write_at(&patch, 500).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, subclusters } => {
            assert!(copied);
            assert!(subclusters.is_all_allocated());

            let mut readback = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
            // Preserved from old cluster
            assert!(readback[..500].iter().all(|&b| b == 0xDD));
            // Our write
            assert_eq!(&readback[500..628], &patch[..]);
            // Preserved
            assert!(readback[628..].iter().all(|&b| b == 0xDD));
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

// ---- Path 8: cow_allocate_new with raw_external (reuses offset) ----

#[test]
fn cow_full_cluster_raw_external_reuses_offset() {
    // Setup: shared data cluster, then use raw_external writer
    // cow_allocate_new with raw_external returns the same offset
    let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
    let rt_offset = 2 * CLUSTER_SIZE;
    let rb_offset = 3 * CLUSTER_SIZE;
    let l2_offset_val = 4 * CLUSTER_SIZE;
    let data_offset = 5 * CLUSTER_SIZE;

    let mut data = vec![0u8; 6 * CLUSTER_SIZE];

    BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);
    for i in 0..5 {
        BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
    }
    BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

    data[data_offset..data_offset + CLUSTER_SIZE].fill(0xBB);

    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset_val as u64), true);
    BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

    let l2_entry = L2Entry::Standard {
        host_offset: ClusterOffset(data_offset as u64),
        copied: false,
        subclusters: SubclusterBitmap::all_allocated(),
    };
    BigEndian::write_u64(&mut data[l2_offset_val..], l2_entry.encode(GEO_STD));

    let backend = MemoryBackend::new(data);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let file_size = backend.file_size().unwrap();
    let mapper = ClusterMapper::new(l1_table, GEO_STD, file_size);
    let header = make_header();
    let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
    let cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteThrough,
        ..CacheConfig::default()
    });

    let mut s = TestSetup {
        backend,
        mapper,
        cache,
        refcount_manager,
        l1_table_offset: l1_offset,
    };

    // Write with raw_external=true — COW should reuse the old offset
    let patch = vec![0x22; 64];
    make_writer_raw_external(&mut s).write_at(&patch, 100).unwrap();

    // L2 entry should now point to the SAME data_offset (raw_external reuses)
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_off = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_off.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { host_offset, copied, .. } => {
            assert!(copied);
            // raw_external: cow_allocate_new returns old_host_offset
            assert_eq!(host_offset.0, data_offset as u64,
                "raw_external should reuse the same host offset");

            // Verify write was applied
            let mut readback = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
            assert_eq!(&readback[100..164], &patch[..]);
            assert_eq!(readback[0], 0xBB); // preserved
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

// ---- Extended L2 basic write tests ----

#[test]
fn ext_l2_write_to_unallocated_produces_all_allocated() {
    // With extended L2, writing a full cluster should set all subclusters to Allocated
    let mut s = setup_with_l2_extended(None);
    let data = vec![0xAB; CLUSTER_SIZE];
    make_writer_ext(&mut s).write_at(&data, 0).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { subclusters, copied, .. } => {
            assert!(copied);
            assert!(subclusters.is_all_allocated(),
                "full cluster write should set all subclusters to Allocated");
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

#[test]
fn ext_l2_partial_write_to_unallocated_produces_all_allocated_fast_path() {
    // Partial write to Unallocated (all_unallocated bitmap) uses fast path
    // → still produces all_allocated because it's the fast path
    let mut s = setup_with_l2_extended(None);
    let data = vec![0xAB; 512];
    make_writer_ext(&mut s).write_at(&data, 100).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_EXT).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Standard { subclusters, .. } => {
            assert!(subclusters.is_all_allocated());
        }
        other => panic!("expected Standard, got {other:?}"),
    }
}

#[test]
fn write_compressed_at_packs_cluster() {
    use crate::engine::compression;

    let mut s = setup();

    // Compress a full cluster of 0xAA data
    let data = vec![0xAA; CLUSTER_SIZE];
    let compressed =
        compression::compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
            .unwrap()
            .expect("all-0xAA should compress");

    // Write compressed data at guest offset 0
    make_writer(&mut s)
        .write_compressed_at(&compressed, 0)
        .unwrap();

    // Verify L2 entry is Compressed
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Compressed(desc) => {
            // Read the actual compressed bytes (deflate is self-terminating,
            // so we only need the raw bytes, not the sector-aligned size)
            let mut comp_buf = vec![0u8; compressed.len()];
            s.backend.read_exact_at(&mut comp_buf, desc.host_offset).unwrap();
            let decompressed =
                compression::decompress_cluster(&comp_buf, CLUSTER_SIZE, 0, COMPRESSION_DEFLATE)
                    .unwrap();
            assert_eq!(decompressed, data, "decompressed data should match original");
        }
        other => panic!("expected Compressed L2 entry, got {other:?}"),
    }
}

#[test]
fn write_compressed_two_entries_pack_into_same_cluster() {
    use crate::engine::compression;

    let mut s = setup();

    // Compress two different clusters — both small enough to share one host cluster
    let data1 = vec![0xAA; CLUSTER_SIZE];
    let data2 = vec![0xBB; CLUSTER_SIZE];
    let comp1 = compression::compress_cluster(&data1, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");
    let comp2 = compression::compress_cluster(&data2, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");

    // Both compressed results should be small (repetitive data)
    assert!(comp1.len() + comp2.len() < CLUSTER_SIZE, "both should fit in one cluster");

    {
        let mut writer = make_writer(&mut s);
        writer.write_compressed_at(&comp1, 0).unwrap();
        // Second write should pack into the same host cluster
        writer.write_compressed_at(&comp2, CLUSTER_SIZE as u64).unwrap();
    }

    // Read L2 entries for both guest clusters
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    let desc0 = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Compressed(d) => d,
        other => panic!("expected Compressed for entry 0, got {other:?}"),
    };
    let desc1 = match l2_table.get(L2Index(1)).unwrap() {
        L2Entry::Compressed(d) => d,
        other => panic!("expected Compressed for entry 1, got {other:?}"),
    };

    // Both should reference the same host cluster (packing)
    let host_cluster_0 = desc0.host_offset & !(CLUSTER_SIZE as u64 - 1);
    let host_cluster_1 = desc1.host_offset & !(CLUSTER_SIZE as u64 - 1);
    assert_eq!(host_cluster_0, host_cluster_1, "should pack into same host cluster");
    // But at different offsets within that cluster
    assert_ne!(desc0.host_offset, desc1.host_offset, "should be at different offsets");
}

#[test]
fn write_compressed_overflow_allocates_new_cluster() {
    use crate::engine::compression;

    let mut s = setup();

    // We need data that compresses to a large size to fill the cluster quickly.
    // Use random-ish data that doesn't compress well.
    let mut data = vec![0u8; CLUSTER_SIZE];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i.wrapping_mul(137).wrapping_add(i >> 3)) as u8;
    }

    // Try compressing — if it doesn't compress well, use synthetic large compressed data
    let comp = compression::compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap();

    // If it compresses, great; if not, use a synthetic test
    if let Some(comp_data) = comp {
        if comp_data.len() > CLUSTER_SIZE / 2 {
            // Large compressed data — two writes should need separate host clusters
            let mut writer = make_writer(&mut s);
            writer.write_compressed_at(&comp_data, 0).unwrap();
            writer.write_compressed_at(&comp_data, CLUSTER_SIZE as u64).unwrap();

            let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
            let l2_offset = l1_entry.l2_table_offset().unwrap();
            let mut l2_buf = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
            let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

            let desc0 = match l2_table.get(L2Index(0)).unwrap() {
                L2Entry::Compressed(d) => d,
                other => panic!("got {other:?}"),
            };
            let desc1 = match l2_table.get(L2Index(1)).unwrap() {
                L2Entry::Compressed(d) => d,
                other => panic!("got {other:?}"),
            };

            let host0 = desc0.host_offset & !(CLUSTER_SIZE as u64 - 1);
            let host1 = desc1.host_offset & !(CLUSTER_SIZE as u64 - 1);
            assert_ne!(host0, host1, "large compressed data should use different host clusters");
        }
    }
}

#[test]
fn write_compressed_overwrites_standard_l2_entry() {
    use crate::engine::compression;

    // First write a normal (uncompressed) cluster, then overwrite with compressed
    let mut s = setup();
    let data = vec![0xCD; CLUSTER_SIZE];
    make_writer(&mut s).write_at(&data, 0).unwrap();

    // Verify it's Standard first
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    assert!(matches!(l2_table.get(L2Index(0)).unwrap(), L2Entry::Standard { .. }));

    // Now overwrite with compressed data
    let comp = compression::compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");
    make_writer(&mut s).write_compressed_at(&comp, 0).unwrap();

    // Verify it's now Compressed
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    assert!(matches!(l2_table.get(L2Index(0)).unwrap(), L2Entry::Compressed(_)));
}

#[test]
fn write_compressed_overwrites_compressed_l2_entry() {
    use crate::engine::compression;

    let mut s = setup();
    let data1 = vec![0xAA; CLUSTER_SIZE];
    let data2 = vec![0xBB; CLUSTER_SIZE];
    let comp1 = compression::compress_cluster(&data1, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");
    let comp2 = compression::compress_cluster(&data2, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");

    // Write first compressed entry
    make_writer(&mut s).write_compressed_at(&comp1, 0).unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let old_desc = match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Compressed(d) => d,
        other => panic!("got {other:?}"),
    };
    let _old_offset = old_desc.host_offset;

    // Overwrite with different compressed data
    make_writer(&mut s).write_compressed_at(&comp2, 0).unwrap();

    // Verify it's still Compressed but with new data
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    match l2_table.get(L2Index(0)).unwrap() {
        L2Entry::Compressed(new_desc) => {
            // The new descriptor should exist (may or may not be at same offset
            // depending on cursor state, but it should be valid)
            let mut comp_buf = vec![0u8; comp2.len()];
            s.backend.read_exact_at(&mut comp_buf, new_desc.host_offset).unwrap();
            let decompressed =
                compression::decompress_cluster(&comp_buf, CLUSTER_SIZE, 0, COMPRESSION_DEFLATE)
                    .unwrap();
            assert_eq!(decompressed, data2, "should read back the second write's data");
        }
        other => panic!("expected Compressed, got {other:?}"),
    }
}

// ---- Backing image tests ----

/// Simple backing image that returns a fixed byte pattern.
struct MockBacking {
    data: Vec<u8>,
    virtual_size: u64,
}

impl MockBacking {
    fn new(size: u64, fill: u8) -> Self {
        Self {
            data: vec![fill; size as usize],
            virtual_size: size,
        }
    }
}

impl crate::io::BackingImage for MockBacking {
    fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> crate::error::Result<()> {
        let start = guest_offset as usize;
        let end = start + buf.len();
        if end <= self.data.len() {
            buf.copy_from_slice(&self.data[start..end]);
        } else if start < self.data.len() {
            let avail = self.data.len() - start;
            buf[..avail].copy_from_slice(&self.data[start..]);
            // rest stays as-is (caller initialized to zero)
        }
        Ok(())
    }
}

fn make_writer_with_backing<'a>(
    s: &'a mut TestSetup,
    backing: &'a mut dyn crate::io::BackingImage,
) -> Qcow2Writer<'a> {
    Qcow2Writer::new(
        &mut s.mapper,
        s.l1_table_offset,
        &s.backend,
        &s.backend,
        &mut s.cache,
        &mut s.refcount_manager,
        CLUSTER_BITS,
        VIRTUAL_SIZE,
        COMPRESSION_DEFLATE,
        false,
        Some(backing),
        None,
        &StdCompressor,
    )
}

#[test]
fn partial_write_reads_backing_data() {
    let mut s = setup();
    let mut backing = MockBacking::new(VIRTUAL_SIZE, 0xBB);

    // Write 512 bytes at offset 256 within cluster 0
    let write_data = vec![0xCC; 512];
    make_writer_with_backing(&mut s, &mut backing)
        .write_at(&write_data, 256)
        .unwrap();

    // Read back the entire cluster
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();
    let entry = l2_table.get(L2Index(0)).unwrap();

    if let L2Entry::Standard { host_offset, .. } = entry {
        let mut cluster = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut cluster, host_offset.0).unwrap();

        // Bytes 0..256 should come from backing (0xBB)
        assert!(cluster[..256].iter().all(|&b| b == 0xBB), "pre-write area should be backing data");
        // Bytes 256..768 should be our write (0xCC)
        assert!(cluster[256..768].iter().all(|&b| b == 0xCC), "write area should be our data");
        // Bytes 768..cluster_size should be backing data (0xBB)
        assert!(cluster[768..].iter().all(|&b| b == 0xBB), "post-write area should be backing data");
    } else {
        panic!("expected Standard entry, got {entry:?}");
    }
}

#[test]
fn partial_write_beyond_backing_size_zeros_rest() {
    let mut s = setup();
    // Backing is only 128 bytes — smaller than a cluster
    let mut backing = MockBacking::new(128, 0xDD);

    let write_data = vec![0xEE; 64];
    make_writer_with_backing(&mut s, &mut backing)
        .write_at(&write_data, 64)
        .unwrap();

    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut cluster = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut cluster, host_offset.0).unwrap();

        // Bytes 0..64: from backing (0xDD)
        assert!(cluster[..64].iter().all(|&b| b == 0xDD), "should read from backing");
        // Bytes 64..128: our write (0xEE)
        assert!(cluster[64..128].iter().all(|&b| b == 0xEE), "should be our write");
        // Bytes 128+: zero (beyond backing)
        assert!(cluster[128..256].iter().all(|&b| b == 0), "beyond backing should be zero");
    } else {
        panic!("expected Standard entry");
    }
}

// ---- Encrypted write tests ----

fn make_writer_encrypted<'a>(
    s: &'a mut TestSetup,
    crypt: &'a crate::engine::encryption::CryptContext,
) -> Qcow2Writer<'a> {
    Qcow2Writer::new(
        &mut s.mapper,
        s.l1_table_offset,
        &s.backend,
        &s.backend,
        &mut s.cache,
        &mut s.refcount_manager,
        CLUSTER_BITS,
        VIRTUAL_SIZE,
        COMPRESSION_DEFLATE,
        false,
        None,
        Some(crypt),
        &StdCompressor,
    )
}

#[test]
fn encrypted_full_cluster_write_roundtrip() {
    use crate::engine::encryption::{CryptContext, CipherMode};

    let mut s = setup();
    let key = vec![0x42u8; 64]; // 64 bytes for AES-256-XTS
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    let plaintext = vec![0xAB; CLUSTER_SIZE];
    make_writer_encrypted(&mut s, &crypt)
        .write_at(&plaintext, 0)
        .unwrap();

    // Read back the raw on-disk data — it should NOT be plaintext
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut raw = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut raw, host_offset.0).unwrap();
        assert_ne!(raw, plaintext, "on-disk data should be encrypted");

        // Decrypt and verify roundtrip
        crypt.decrypt_cluster(host_offset.0, &mut raw).unwrap();
        assert_eq!(raw, plaintext, "decrypted data should match original");
    } else {
        panic!("expected Standard entry");
    }
}

#[test]
fn encrypted_partial_write_in_place() {
    use crate::engine::encryption::{CryptContext, CipherMode};

    let mut s = setup();
    let key = vec![0x42u8; 64];
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    // First: full cluster write to allocate
    let initial = vec![0xAA; CLUSTER_SIZE];
    make_writer_encrypted(&mut s, &crypt)
        .write_at(&initial, 0)
        .unwrap();

    // Second: partial write (in-place update since copied=true, refcount=1)
    let patch = vec![0xBB; 512];
    make_writer_encrypted(&mut s, &crypt)
        .write_at(&patch, 256)
        .unwrap();

    // Read back and decrypt
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut raw = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut raw, host_offset.0).unwrap();
        crypt.decrypt_cluster(host_offset.0, &mut raw).unwrap();

        // Verify: 0..256 = 0xAA, 256..768 = 0xBB, 768.. = 0xAA
        assert!(raw[..256].iter().all(|&b| b == 0xAA));
        assert!(raw[256..768].iter().all(|&b| b == 0xBB));
        assert!(raw[768..].iter().all(|&b| b == 0xAA));
    } else {
        panic!("expected Standard entry");
    }
}

#[test]
fn encrypted_write_to_unallocated_partial() {
    use crate::engine::encryption::{CryptContext, CipherMode};

    let mut s = setup();
    let key = vec![0x42u8; 64];
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    // Partial write to an unallocated cluster
    let data = vec![0xCC; 1024];
    make_writer_encrypted(&mut s, &crypt)
        .write_at(&data, 512)
        .unwrap();

    // Decrypt and verify
    let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
    let l2_offset = l1_entry.l2_table_offset().unwrap();
    let mut l2_buf = vec![0u8; CLUSTER_SIZE];
    s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
    let l2_table = L2Table::read_from(&l2_buf, GEO_STD).unwrap();

    if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
        let mut raw = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut raw, host_offset.0).unwrap();
        crypt.decrypt_cluster(host_offset.0, &mut raw).unwrap();

        assert!(raw[..512].iter().all(|&b| b == 0), "pre-write should be zero");
        assert!(raw[512..1536].iter().all(|&b| b == 0xCC), "write area should match");
        assert!(raw[1536..].iter().all(|&b| b == 0), "post-write should be zero");
    } else {
        panic!("expected Standard entry");
    }
}

#[test]
fn write_to_compressed_cluster_with_encryption_returns_error() {
    use crate::engine::compression;
    use crate::engine::encryption::{CryptContext, CipherMode};

    let mut s = setup();
    let key = vec![0x42u8; 64];
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    // First write a compressed cluster (without encryption to set it up)
    let comp_data = vec![0xAA; CLUSTER_SIZE];
    let compressed = compression::compress_cluster(&comp_data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("should compress");
    make_writer(&mut s).write_compressed_at(&compressed, 0).unwrap();

    // Now try to write to it with encryption enabled — should get EncryptionWithCompression
    let patch = vec![0xBB; 512];
    let result = make_writer_encrypted(&mut s, &crypt).write_at(&patch, 0);
    assert!(
        matches!(result, Err(Error::EncryptionWithCompression)),
        "expected EncryptionWithCompression error, got {result:?}"
    );
}
