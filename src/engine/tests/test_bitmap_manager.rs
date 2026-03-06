//! Tests for bitmap_manager (originally in engine/bitmap_manager.rs)

use crate::engine::bitmap_manager::BitmapManager;
use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::refcount_manager::RefcountManager;
use crate::error::Error;
use crate::format::constants::*;
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::types::ClusterOffset;
use crate::io::MemoryBackend;
use crate::IoBackend;
use byteorder::{BigEndian, ByteOrder};

/// Build a minimal writable QCOW2 image in memory for testing.
fn build_test_image(virtual_size: u64) -> (Box<dyn IoBackend>, Header, Vec<HeaderExtension>) {
    let cluster_bits = 16u32;
    let cluster_size = 1u64 << cluster_bits;
    let refcount_order = 4u32;

    let l2_entries = cluster_size / 8;
    let bytes_per_l1 = l2_entries * cluster_size;
    let l1_entries = ((virtual_size + bytes_per_l1 - 1) / bytes_per_l1) as u32;

    // Layout: header(0), L1(1), reftable(2), refblock(3), [free from 4..]
    let l1_offset = cluster_size;
    let rt_offset = 2 * cluster_size;
    let rb_offset = 3 * cluster_size;

    let header = Header {
        version: 3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits,
        virtual_size,
        crypt_method: 0,
        l1_table_entries: l1_entries,
        l1_table_offset: ClusterOffset(l1_offset),
        refcount_table_offset: ClusterOffset(rt_offset),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
        compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
        autoclear_features: AutoclearFeatures::empty(),
        refcount_order,
        header_length: HEADER_V3_MIN_LENGTH as u32,
        compression_type: 0,
    };

    // Create image buffer
    let image_size = 64 * cluster_size; // plenty of space
    let mut buf = vec![0u8; image_size as usize];

    // Write header
    header.write_to(&mut buf).unwrap();

    // Write end-of-extensions marker
    // (8 zero bytes at header_length = 104, already zero)

    // Write L1 table (all zeros = unallocated)
    // Already zero.

    // Write refcount table: entry 0 points to refblock at rb_offset
    BigEndian::write_u64(&mut buf[rt_offset as usize..], rb_offset);

    // Write refblock: mark clusters 0-3 as used (refcount=1)
    let refcount_bits = 1u32 << refcount_order; // 16-bit
    let bytes_per_entry = refcount_bits / 8;
    for i in 0..4u64 {
        let off = rb_offset as usize + i as usize * bytes_per_entry as usize;
        BigEndian::write_u16(&mut buf[off..], 1); // refcount = 1
    }

    let backend = Box::new(MemoryBackend::new(buf));
    (backend, header, Vec::new())
}

#[test]
fn create_and_list_bitmap() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // Initially no bitmaps
    assert!(mgr.list_bitmaps().unwrap().is_empty());

    // Create a bitmap
    mgr.create_bitmap("dirty-0", 16, false).unwrap();

    let bitmaps = mgr.list_bitmaps().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "dirty-0");
    assert_eq!(bitmaps[0].granularity_bits, 16);
    assert_eq!(bitmaps[0].granularity, 65536);
    assert!(!bitmaps[0].auto);
    assert!(!bitmaps[0].in_use);
}

#[test]
fn create_bitmap_with_auto() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("track", 16, true).unwrap();
    let bitmaps = mgr.list_bitmaps().unwrap();
    assert!(bitmaps[0].auto);
    assert!(mgr.has_auto_bitmaps().unwrap());
}

#[test]
fn create_duplicate_name_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("dup", 16, false).unwrap();
    match mgr.create_bitmap("dup", 16, false) {
        Err(Error::BitmapNameDuplicate { name }) => assert_eq!(name, "dup"),
        other => panic!("expected BitmapNameDuplicate, got {other:?}"),
    }
}

#[test]
fn create_empty_name_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    match mgr.create_bitmap("", 16, false) {
        Err(Error::BitmapNameEmpty) => {}
        other => panic!("expected BitmapNameEmpty, got {other:?}"),
    }
}

#[test]
fn delete_bitmap() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("to-delete", 16, false).unwrap();
    assert_eq!(mgr.list_bitmaps().unwrap().len(), 1);

    mgr.delete_bitmap("to-delete").unwrap();
    assert!(mgr.list_bitmaps().unwrap().is_empty());

    // Extension should be removed
    assert!(!extensions.iter().any(|e| matches!(e, HeaderExtension::Bitmaps(_))));
}

#[test]
fn delete_nonexistent_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    match mgr.delete_bitmap("nope") {
        Err(Error::BitmapNotFound { name }) => assert_eq!(name, "nope"),
        other => panic!("expected BitmapNotFound, got {other:?}"),
    }
}

#[test]
fn set_and_get_dirty() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Initially clean
    assert!(!mgr.get_dirty("test", 0).unwrap());
    assert!(!mgr.get_dirty("test", 65536).unwrap());

    // Mark first granularity block as dirty
    mgr.set_dirty("test", 0, 65536).unwrap();

    assert!(mgr.get_dirty("test", 0).unwrap());
    assert!(!mgr.get_dirty("test", 65536).unwrap());
}

#[test]
fn set_dirty_range() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Mark 3 granularity blocks dirty (0, 64K, 128K)
    mgr.set_dirty("test", 0, 3 * 65536).unwrap();

    assert!(mgr.get_dirty("test", 0).unwrap());
    assert!(mgr.get_dirty("test", 65536).unwrap());
    assert!(mgr.get_dirty("test", 2 * 65536).unwrap());
    assert!(!mgr.get_dirty("test", 3 * 65536).unwrap());
}

#[test]
fn clear_bitmap_resets_all() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();
    mgr.set_dirty("test", 0, 65536).unwrap();
    assert!(mgr.get_dirty("test", 0).unwrap());

    mgr.clear_bitmap("test").unwrap();
    assert!(!mgr.get_dirty("test", 0).unwrap());
}

#[test]
fn enable_disable_tracking() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();
    assert!(!mgr.list_bitmaps().unwrap()[0].auto);

    mgr.enable_tracking("test").unwrap();
    assert!(mgr.list_bitmaps().unwrap()[0].auto);

    mgr.disable_tracking("test").unwrap();
    assert!(!mgr.list_bitmaps().unwrap()[0].auto);
}

#[test]
fn multiple_bitmaps() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("bitmap-a", 16, false).unwrap();
    mgr.create_bitmap("bitmap-b", 20, true).unwrap();

    let bitmaps = mgr.list_bitmaps().unwrap();
    assert_eq!(bitmaps.len(), 2);
    assert_eq!(bitmaps[0].name, "bitmap-a");
    assert_eq!(bitmaps[1].name, "bitmap-b");
    assert_eq!(bitmaps[1].granularity_bits, 20);
}

#[test]
fn delete_one_of_multiple() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("keep", 16, false).unwrap();
    mgr.create_bitmap("remove", 16, false).unwrap();
    assert_eq!(mgr.list_bitmaps().unwrap().len(), 2);

    mgr.delete_bitmap("remove").unwrap();
    let bitmaps = mgr.list_bitmaps().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "keep");

    // Extension should still exist
    assert!(extensions.iter().any(|e| matches!(e, HeaderExtension::Bitmaps(_))));
}

#[test]
fn merge_bitmaps_or_operation() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("src", 16, false).unwrap();
    mgr.create_bitmap("dst", 16, false).unwrap();

    // Set different bits in each
    mgr.set_dirty("src", 0, 65536).unwrap();
    mgr.set_dirty("dst", 65536, 65536).unwrap();

    mgr.merge_bitmaps("src", "dst").unwrap();

    // Destination should have both bits set
    assert!(mgr.get_dirty("dst", 0).unwrap());
    assert!(mgr.get_dirty("dst", 65536).unwrap());

    // Source should be unchanged
    assert!(mgr.get_dirty("src", 0).unwrap());
    assert!(!mgr.get_dirty("src", 65536).unwrap());
}

#[test]
fn track_write_auto_bitmaps() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // Create one auto and one non-auto bitmap
    mgr.create_bitmap("auto-bm", 16, true).unwrap();
    mgr.create_bitmap("manual-bm", 16, false).unwrap();

    // Simulate a write
    mgr.track_write(0, 65536).unwrap();

    // Auto bitmap should be dirty
    assert!(mgr.get_dirty("auto-bm", 0).unwrap());
    // Manual bitmap should be clean
    assert!(!mgr.get_dirty("manual-bm", 0).unwrap());
}

#[test]
fn invalid_granularity_rejected() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // Too small
    assert!(mgr.create_bitmap("bad", 8, false).is_err());
    // Too large
    assert!(mgr.create_bitmap("bad", 32, false).is_err());
}

#[test]
fn autoclear_flag_set_on_create() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    assert!(!header.autoclear_features.contains(AutoclearFeatures::BITMAPS));

    {
        let mut mgr = BitmapManager::new(
            backend.as_ref(),
            &mut cache,
            &mut refcount_manager,
            &mut header,
            &mut extensions,
            16,
            1024 * 1024,
        );
        mgr.create_bitmap("x", 16, false).unwrap();
    }

    assert!(header.autoclear_features.contains(AutoclearFeatures::BITMAPS));
}

#[test]
fn autoclear_flag_cleared_on_last_delete() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    {
        let mut mgr = BitmapManager::new(
            backend.as_ref(),
            &mut cache,
            &mut refcount_manager,
            &mut header,
            &mut extensions,
            16,
            1024 * 1024,
        );
        mgr.create_bitmap("x", 16, false).unwrap();
    }

    assert!(header.autoclear_features.contains(AutoclearFeatures::BITMAPS));

    {
        let mut mgr = BitmapManager::new(
            backend.as_ref(),
            &mut cache,
            &mut refcount_manager,
            &mut header,
            &mut extensions,
            16,
            1024 * 1024,
        );
        mgr.delete_bitmap("x").unwrap();
    }

    assert!(!header.autoclear_features.contains(AutoclearFeatures::BITMAPS));
}

// --- Edge case tests ---

#[test]
fn set_dirty_idempotent() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Set same range twice -- must not error or corrupt
    mgr.set_dirty("test", 0, 65536).unwrap();
    mgr.set_dirty("test", 0, 65536).unwrap();

    assert!(mgr.get_dirty("test", 0).unwrap());
}

#[test]
fn set_dirty_adjacent_blocks() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Set two adjacent but separate blocks
    mgr.set_dirty("test", 0, 65536).unwrap();
    mgr.set_dirty("test", 65536, 65536).unwrap();

    assert!(mgr.get_dirty("test", 0).unwrap());
    assert!(mgr.get_dirty("test", 65536).unwrap());
    assert!(!mgr.get_dirty("test", 131072).unwrap());
}

#[test]
fn set_dirty_partial_overlap() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // First range: blocks 0-1
    mgr.set_dirty("test", 0, 2 * 65536).unwrap();
    // Second range: blocks 1-2 (overlaps block 1)
    mgr.set_dirty("test", 65536, 2 * 65536).unwrap();

    // All three blocks should be dirty
    assert!(mgr.get_dirty("test", 0).unwrap());
    assert!(mgr.get_dirty("test", 65536).unwrap());
    assert!(mgr.get_dirty("test", 131072).unwrap());
    // Block 3 should be clean
    assert!(!mgr.get_dirty("test", 196608).unwrap());
}

#[test]
fn set_dirty_single_byte_within_granule() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Mark only 1 byte in the middle of a granule
    mgr.set_dirty("test", 32768, 1).unwrap();

    // The entire granule should be dirty (granularity=65536)
    assert!(mgr.get_dirty("test", 0).unwrap());
    // Next granule still clean
    assert!(!mgr.get_dirty("test", 65536).unwrap());
}

#[test]
fn get_dirty_nonexistent_bitmap_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    match mgr.get_dirty("nonexistent", 0) {
        Err(Error::BitmapNotFound { name }) => assert_eq!(name, "nonexistent"),
        other => panic!("expected BitmapNotFound, got {other:?}"),
    }
}

#[test]
fn set_dirty_nonexistent_bitmap_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    match mgr.set_dirty("nonexistent", 0, 65536) {
        Err(Error::BitmapNotFound { name }) => assert_eq!(name, "nonexistent"),
        other => panic!("expected BitmapNotFound, got {other:?}"),
    }
}

#[test]
fn clear_nonexistent_bitmap_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    match mgr.clear_bitmap("nonexistent") {
        Err(Error::BitmapNotFound { name }) => assert_eq!(name, "nonexistent"),
        other => panic!("expected BitmapNotFound, got {other:?}"),
    }
}

#[test]
fn merge_nonexistent_source_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("dst", 16, false).unwrap();
    assert!(mgr.merge_bitmaps("nonexistent", "dst").is_err());
}

#[test]
fn merge_nonexistent_destination_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("src", 16, false).unwrap();
    assert!(mgr.merge_bitmaps("src", "nonexistent").is_err());
}

#[test]
fn merge_different_granularity_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("fine", 9, false).unwrap();
    mgr.create_bitmap("coarse", 20, false).unwrap();

    match mgr.merge_bitmaps("fine", "coarse") {
        Err(Error::InvalidBitmapExtension { message }) => {
            assert!(message.contains("granularity"));
        }
        other => panic!("expected granularity mismatch error, got {other:?}"),
    }
}

#[test]
fn merge_empty_source_into_dirty_destination_preserves() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("empty", 16, false).unwrap();
    mgr.create_bitmap("dirty", 16, false).unwrap();
    mgr.set_dirty("dirty", 0, 65536).unwrap();

    // Merge empty -> dirty: dirty should be unchanged
    mgr.merge_bitmaps("empty", "dirty").unwrap();
    assert!(mgr.get_dirty("dirty", 0).unwrap());
}

#[test]
fn merge_dirty_source_into_empty_destination() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("dirty", 16, false).unwrap();
    mgr.create_bitmap("empty", 16, false).unwrap();
    mgr.set_dirty("dirty", 0, 65536).unwrap();

    // Merge dirty -> empty: empty should become dirty
    mgr.merge_bitmaps("dirty", "empty").unwrap();
    assert!(mgr.get_dirty("empty", 0).unwrap());
    // Source unchanged
    assert!(mgr.get_dirty("dirty", 0).unwrap());
}

#[test]
fn merge_both_dirty_same_block() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("src", 16, false).unwrap();
    mgr.create_bitmap("dst", 16, false).unwrap();
    mgr.set_dirty("src", 0, 65536).unwrap();
    mgr.set_dirty("dst", 0, 65536).unwrap();

    // Both dirty on same block -- merge should be fine
    mgr.merge_bitmaps("src", "dst").unwrap();
    assert!(mgr.get_dirty("dst", 0).unwrap());
}

#[test]
fn min_granularity_set_and_get() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // 512-byte granularity (smallest possible)
    mgr.create_bitmap("fine", 9, false).unwrap();
    mgr.set_dirty("fine", 0, 512).unwrap();

    assert!(mgr.get_dirty("fine", 0).unwrap());
    // Next 512-byte block should be clean
    assert!(!mgr.get_dirty("fine", 512).unwrap());
}

#[test]
fn track_write_no_auto_bitmaps_is_noop() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // Only manual bitmaps
    mgr.create_bitmap("manual", 16, false).unwrap();

    // track_write should not error even with no auto bitmaps
    mgr.track_write(0, 65536).unwrap();

    // Manual bitmap should stay clean
    assert!(!mgr.get_dirty("manual", 0).unwrap());
}

#[test]
fn track_write_multiple_auto_bitmaps() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // Two auto bitmaps with different granularities
    mgr.create_bitmap("auto-fine", 9, true).unwrap();
    mgr.create_bitmap("auto-coarse", 16, true).unwrap();

    mgr.track_write(0, 512).unwrap();

    // Both should be dirty
    assert!(mgr.get_dirty("auto-fine", 0).unwrap());
    assert!(mgr.get_dirty("auto-coarse", 0).unwrap());

    // Fine-grained: next 512-byte block still clean
    assert!(!mgr.get_dirty("auto-fine", 512).unwrap());
}

#[test]
fn create_delete_create_same_name() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("recycled", 16, false).unwrap();
    mgr.set_dirty("recycled", 0, 65536).unwrap();
    mgr.delete_bitmap("recycled").unwrap();

    // Re-create with same name -- should start clean
    mgr.create_bitmap("recycled", 16, false).unwrap();
    assert!(!mgr.get_dirty("recycled", 0).unwrap());
}

#[test]
fn clear_already_clean_bitmap_is_noop() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Clear a bitmap that was never dirtied
    mgr.clear_bitmap("test").unwrap();
    assert!(!mgr.get_dirty("test", 0).unwrap());
}

#[test]
fn set_dirty_entire_virtual_size() {
    let vsize = 1024 * 1024; // 1 MiB
    let (backend, mut header, mut extensions) = build_test_image(vsize);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        vsize,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Mark entire virtual size as dirty
    mgr.set_dirty("test", 0, vsize).unwrap();

    // Sample several points
    assert!(mgr.get_dirty("test", 0).unwrap());
    assert!(mgr.get_dirty("test", vsize / 2).unwrap());
    assert!(mgr.get_dirty("test", vsize - 65536).unwrap());
}

#[test]
fn set_dirty_then_clear_then_set_again() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();

    // Set dirty
    mgr.set_dirty("test", 0, 65536).unwrap();
    assert!(mgr.get_dirty("test", 0).unwrap());

    // Clear all
    mgr.clear_bitmap("test").unwrap();
    assert!(!mgr.get_dirty("test", 0).unwrap());

    // Set dirty again at different offset
    mgr.set_dirty("test", 65536, 65536).unwrap();
    assert!(!mgr.get_dirty("test", 0).unwrap());
    assert!(mgr.get_dirty("test", 65536).unwrap());
}

#[test]
fn enable_tracking_nonexistent_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    assert!(mgr.enable_tracking("nonexistent").is_err());
}

#[test]
fn disable_tracking_nonexistent_fails() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    assert!(mgr.disable_tracking("nonexistent").is_err());
}

#[test]
fn enable_already_enabled_is_idempotent() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, true).unwrap();
    // Already auto, enable again
    mgr.enable_tracking("test").unwrap();
    assert!(mgr.list_bitmaps().unwrap()[0].auto);
}

#[test]
fn disable_already_disabled_is_idempotent() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("test", 16, false).unwrap();
    // Already manual, disable again
    mgr.disable_tracking("test").unwrap();
    assert!(!mgr.list_bitmaps().unwrap()[0].auto);
}

#[test]
fn has_auto_bitmaps_mixed() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    // No bitmaps => no auto
    assert!(!mgr.has_auto_bitmaps().unwrap());

    // Manual only => no auto
    mgr.create_bitmap("manual", 16, false).unwrap();
    assert!(!mgr.has_auto_bitmaps().unwrap());

    // Add auto => has auto
    mgr.create_bitmap("auto", 16, true).unwrap();
    assert!(mgr.has_auto_bitmaps().unwrap());

    // Delete auto => no auto again
    mgr.delete_bitmap("auto").unwrap();
    assert!(!mgr.has_auto_bitmaps().unwrap());
}

#[test]
fn delete_middle_of_three_bitmaps() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("first", 16, false).unwrap();
    mgr.create_bitmap("middle", 16, false).unwrap();
    mgr.create_bitmap("last", 16, false).unwrap();

    // Set dirty bits on all three
    mgr.set_dirty("first", 0, 65536).unwrap();
    mgr.set_dirty("middle", 0, 65536).unwrap();
    mgr.set_dirty("last", 0, 65536).unwrap();

    // Delete the middle one
    mgr.delete_bitmap("middle").unwrap();

    let bitmaps = mgr.list_bitmaps().unwrap();
    assert_eq!(bitmaps.len(), 2);
    assert_eq!(bitmaps[0].name, "first");
    assert_eq!(bitmaps[1].name, "last");

    // Remaining bitmaps should still have their dirty bits
    assert!(mgr.get_dirty("first", 0).unwrap());
    assert!(mgr.get_dirty("last", 0).unwrap());
}

#[test]
fn delete_all_bitmaps_removes_extension() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("a", 16, false).unwrap();
    mgr.create_bitmap("b", 16, false).unwrap();
    mgr.delete_bitmap("a").unwrap();
    mgr.delete_bitmap("b").unwrap();

    assert!(mgr.list_bitmaps().unwrap().is_empty());
    drop(mgr);

    // No bitmap extension should remain
    assert!(!extensions.iter().any(|e| matches!(e, HeaderExtension::Bitmaps(_))));
}

#[test]
fn dirty_bits_independent_between_bitmaps() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    mgr.create_bitmap("a", 16, false).unwrap();
    mgr.create_bitmap("b", 16, false).unwrap();

    // Dirty different offsets
    mgr.set_dirty("a", 0, 65536).unwrap();
    mgr.set_dirty("b", 65536, 65536).unwrap();

    // Verify independence
    assert!(mgr.get_dirty("a", 0).unwrap());
    assert!(!mgr.get_dirty("a", 65536).unwrap());
    assert!(!mgr.get_dirty("b", 0).unwrap());
    assert!(mgr.get_dirty("b", 65536).unwrap());

    // Clear only bitmap a
    mgr.clear_bitmap("a").unwrap();
    assert!(!mgr.get_dirty("a", 0).unwrap());
    // Bitmap b still dirty
    assert!(mgr.get_dirty("b", 65536).unwrap());
}

#[test]
fn max_name_length_bitmap() {
    let (backend, mut header, mut extensions) = build_test_image(1024 * 1024);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut refcount_manager =
        RefcountManager::load(backend.as_ref(), &header).unwrap();

    let mut mgr = BitmapManager::new(
        backend.as_ref(),
        &mut cache,
        &mut refcount_manager,
        &mut header,
        &mut extensions,
        16,
        1024 * 1024,
    );

    let name = "x".repeat(1023); // max name length
    mgr.create_bitmap(&name, 16, false).unwrap();

    let bitmaps = mgr.list_bitmaps().unwrap();
    assert_eq!(bitmaps[0].name, name);
}
