//! Tests for writer (originally in engine/writer.rs)

use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::refcount_manager::RefcountManager;
use crate::engine::writer::Qcow2Writer;
use crate::error::Error;
use crate::format::constants::*;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap};
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
    let cache = MetadataCache::new(CacheConfig::default());

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
    let cache = MetadataCache::new(CacheConfig::default());

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
    let cache = MetadataCache::new(CacheConfig::default());

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
    let cache = MetadataCache::new(CacheConfig::default());

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
