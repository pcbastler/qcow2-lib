use std::sync::Arc;
use std::thread;

use crate::engine::image::{CreateOptions, Qcow2Image};
use crate::engine::image_async::Qcow2ImageAsync;
use crate::error::Error;
use crate::io::MemoryBackend;

/// Helper: create an in-memory writable Qcow2Image and convert to Async.
fn create_async_image(virtual_size: u64) -> Qcow2ImageAsync {
    let backend = Box::new(MemoryBackend::new(Vec::new()));
    let opts = CreateOptions {
        virtual_size,
        cluster_bits: Some(16), // 64 KB clusters
        extended_l2: false,
        compression_type: None,
        data_file: None,
        encryption: None,
    };
    let image = Qcow2Image::create_on_backend(backend, opts).unwrap();
    Qcow2ImageAsync::from_image(image).unwrap()
}

#[test]
fn basic_write_read_roundtrip() {
    let img = create_async_image(1 << 20); // 1 MB

    let data = vec![0xABu8; 512];
    img.write_at(&data, 0).unwrap();

    let mut buf = vec![0u8; 512];
    img.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);

    img.flush().unwrap();
}

#[test]
fn read_unwritten_returns_zeros() {
    let img = create_async_image(1 << 20);

    let mut buf = vec![0xFFu8; 4096];
    img.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn write_read_multiple_clusters() {
    let img = create_async_image(1 << 20);
    let cluster_size = 1u64 << 16; // 64 KB

    // Write to two different clusters
    let data1 = vec![0x11u8; cluster_size as usize];
    let data2 = vec![0x22u8; cluster_size as usize];
    img.write_at(&data1, 0).unwrap();
    img.write_at(&data2, cluster_size).unwrap();

    let mut buf1 = vec![0u8; cluster_size as usize];
    let mut buf2 = vec![0u8; cluster_size as usize];
    img.read_at(&mut buf1, 0).unwrap();
    img.read_at(&mut buf2, cluster_size).unwrap();

    assert_eq!(buf1, data1);
    assert_eq!(buf2, data2);
}

#[test]
fn into_image_roundtrip() {
    let img = create_async_image(1 << 20);
    let data = vec![0xCDu8; 1024];
    img.write_at(&data, 4096).unwrap();
    img.flush().unwrap();

    // Convert back to Qcow2Image
    let mut sync_img = img.into_image();
    let mut buf = vec![0u8; 1024];
    sync_img.read_at(&mut buf, 4096).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn multithreaded_writes_different_l2() {
    // 2 GB virtual size: 4 L2 tables at 64K clusters (8192 entries per L2)
    let virtual_size = 2u64 * 1024 * 1024 * 1024;
    let img = Arc::new(create_async_image(virtual_size));
    let cluster_size = 1u64 << 16;
    let l2_range = 8192u64 * cluster_size; // 512 MB per L2

    let num_threads = 4usize;
    let writes_per_thread = 16usize;

    thread::scope(|s| {
        for t in 0..num_threads {
            let img = Arc::clone(&img);
            s.spawn(move || {
                let base = t as u64 * l2_range; // each thread in different L2
                for i in 0..writes_per_thread {
                    let offset = base + i as u64 * cluster_size;
                    let data = vec![(t * 16 + i) as u8; cluster_size as usize];
                    img.write_at(&data, offset).unwrap();
                }
            });
        }
    });

    // Verify all writes
    for t in 0..num_threads {
        let base = t as u64 * l2_range;
        for i in 0..writes_per_thread {
            let offset = base + i as u64 * cluster_size;
            let mut buf = vec![0u8; cluster_size as usize];
            img.read_at(&mut buf, offset).unwrap();
            let expected = vec![(t * 16 + i) as u8; cluster_size as usize];
            assert_eq!(buf, expected, "mismatch at thread={t} write={i}");
        }
    }

    img.flush().unwrap();
}

#[test]
fn multithreaded_readers_and_writers() {
    let virtual_size = 2u64 * 1024 * 1024 * 1024;
    let img = Arc::new(create_async_image(virtual_size));
    let cluster_size = 1u64 << 16;
    let l2_range = 8192u64 * cluster_size;

    // First, write some data
    for t in 0..2u64 {
        let data = vec![(t + 1) as u8; cluster_size as usize];
        img.write_at(&data, t * l2_range).unwrap();
    }

    thread::scope(|s| {
        // 2 readers on L2 range 0
        for _ in 0..2 {
            let img = Arc::clone(&img);
            s.spawn(move || {
                for _ in 0..10 {
                    let mut buf = vec![0u8; cluster_size as usize];
                    img.read_at(&mut buf, 0).unwrap();
                    assert_eq!(buf[0], 1);
                }
            });
        }

        // 2 writers on L2 range 2 and 3 (different from readers)
        for t in 2..4u64 {
            let img = Arc::clone(&img);
            s.spawn(move || {
                for i in 0..10u64 {
                    let data = vec![(t * 10 + i) as u8; cluster_size as usize];
                    img.write_at(&data, t * l2_range + i * cluster_size).unwrap();
                }
            });
        }
    });

    img.flush().unwrap();
}

#[test]
fn concurrent_writes_same_l2_serialized() {
    let img = Arc::new(create_async_image(1 << 20));
    let cluster_size = 1u64 << 16;

    // Multiple threads write to the same L2 range (offset 0)
    let num_threads = 4usize;

    thread::scope(|s| {
        for t in 0..num_threads {
            let img = Arc::clone(&img);
            s.spawn(move || {
                let offset = t as u64 * cluster_size;
                let data = vec![(t + 1) as u8; cluster_size as usize];
                img.write_at(&data, offset).unwrap();
            });
        }
    });

    // Verify each write landed correctly
    for t in 0..num_threads {
        let mut buf = vec![0u8; cluster_size as usize];
        img.read_at(&mut buf, t as u64 * cluster_size).unwrap();
        assert_eq!(buf[0], (t + 1) as u8);
    }
}

#[test]
fn header_accessors() {
    let img = create_async_image(1 << 20);
    assert_eq!(img.virtual_size().unwrap(), 1 << 20);
    assert_eq!(img.cluster_size().unwrap(), 1 << 16);

    let header = img.header().unwrap();
    assert_eq!(header.virtual_size, 1 << 20);
    assert_eq!(header.cluster_bits, 16);
}

#[test]
fn flush_clears_dirty() {
    let img = create_async_image(1 << 20);
    let data = vec![0xABu8; 512];
    img.write_at(&data, 0).unwrap();
    img.flush().unwrap();

    // Convert back and check dirty flag is clear
    let sync_img = img.into_image();
    assert!(!sync_img.is_dirty());
}

/// Helper: create an overlay Qcow2Image with a backing image that has data written.
fn create_overlay_with_backing(
    backing_data: &[u8],
    backing_offset: u64,
    virtual_size: u64,
) -> Qcow2Image {
    let opts = CreateOptions {
        virtual_size,
        cluster_bits: Some(16),
        extended_l2: false,
        compression_type: None,
        data_file: None,
        encryption: None,
    };

    // Create backing image with data
    let backing_backend = Box::new(MemoryBackend::new(Vec::new()));
    let mut backing = Qcow2Image::create_on_backend(backing_backend, opts.clone()).unwrap();
    backing.write_at(backing_data, backing_offset).unwrap();
    backing.flush().unwrap();

    // Create overlay and inject backing via into_parts/from_parts
    let overlay = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::new(Vec::new())),
        opts,
    )
    .unwrap();
    let (meta, be, data_be, bc, _, cc, comp) = overlay.into_parts();
    Qcow2Image::from_parts(meta, be, data_be, bc, Some(Box::new(backing)), cc, comp)
}

#[test]
fn read_with_backing() {
    let backing_data = vec![0xBBu8; 512];
    let overlay = create_overlay_with_backing(&backing_data, 0, 1 << 20);

    let async_img = Qcow2ImageAsync::from_image(overlay).unwrap();

    // Read from unallocated cluster — should fall through to backing
    let mut buf = vec![0u8; 512];
    async_img.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, backing_data, "should read backing data for unallocated cluster");

    // Write to overlay, then read back — should get overlay data
    let overlay_data = vec![0xCCu8; 512];
    async_img.write_at(&overlay_data, 65536).unwrap();
    let mut buf2 = vec![0u8; 512];
    async_img.read_at(&mut buf2, 65536).unwrap();
    assert_eq!(buf2, overlay_data);
}

#[test]
fn write_with_backing_cow() {
    let cluster_size = 1u64 << 16;
    let full_cluster = vec![0xAAu8; cluster_size as usize];
    let overlay = create_overlay_with_backing(&full_cluster, 0, 1 << 20);

    let async_img = Qcow2ImageAsync::from_image(overlay).unwrap();

    // Partial write in the middle of the cluster (COW: rest from backing)
    let partial = vec![0xFFu8; 512];
    async_img.write_at(&partial, 1024).unwrap();

    // Read the full cluster — should be: backing[0..1024] + 0xFF*512 + backing[1536..]
    let mut result = vec![0u8; cluster_size as usize];
    async_img.read_at(&mut result, 0).unwrap();

    assert!(result[..1024].iter().all(|&b| b == 0xAA), "pre-write region should be from backing");
    assert!(result[1024..1536].iter().all(|&b| b == 0xFF), "written region should be overlay data");
    assert!(result[1536..].iter().all(|&b| b == 0xAA), "post-write region should be from backing");
}

/// Helper: create an async image that is read-only.
fn create_readonly_async_image(virtual_size: u64) -> Qcow2ImageAsync {
    // Create a writable image first to get valid on-disk format
    let img = create_async_image(virtual_size);
    img.flush().unwrap();

    // Extract backend bytes and re-open as read-only
    let sync_img = img.into_image();
    let (_, backend, _, _, _, _, _) = sync_img.into_parts();
    let ro_image = Qcow2Image::from_backend(backend).unwrap();
    Qcow2ImageAsync::from_image(ro_image).unwrap()
}

// ---- Snapshot API tests ----

#[test]
fn snapshot_create_and_list() {
    let img = create_async_image(1 << 20);
    img.write_at(&[0xAA; 4096], 0).unwrap();

    img.snapshot_create("snap-1").unwrap();

    let snapshots = img.snapshot_list().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "snap-1");
    assert_eq!(snapshots[0].id, "1");
}

#[test]
fn snapshot_create_multiple() {
    let img = create_async_image(1 << 20);
    img.snapshot_create("first").unwrap();
    img.snapshot_create("second").unwrap();

    let snapshots = img.snapshot_list().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].name, "first");
    assert_eq!(snapshots[1].name, "second");
}

#[test]
fn snapshot_delete() {
    let img = create_async_image(1 << 20);
    img.snapshot_create("to-delete").unwrap();
    assert_eq!(img.snapshot_list().unwrap().len(), 1);

    img.snapshot_delete("to-delete").unwrap();
    assert_eq!(img.snapshot_list().unwrap().len(), 0);
}

#[test]
fn snapshot_apply_reverts_data() {
    let img = create_async_image(1 << 20);
    img.write_at(&[0x11; 256], 0).unwrap();
    img.snapshot_create("snap").unwrap();

    // Overwrite with different data
    img.write_at(&[0x22; 256], 0).unwrap();
    let mut buf = vec![0u8; 256];
    img.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22));

    // Revert to snapshot
    img.snapshot_apply("snap").unwrap();
    img.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11), "data should revert to snapshot state");
}

#[test]
fn snapshot_list_empty() {
    let img = create_async_image(1 << 20);
    let snapshots = img.snapshot_list().unwrap();
    assert!(snapshots.is_empty());
}

// ---- Bitmap API tests ----

#[test]
fn bitmap_create_and_list() {
    let img = create_async_image(1 << 20);
    img.bitmap_create("dirty-0", None, false).unwrap();

    let bitmaps = img.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "dirty-0");
}

#[test]
fn bitmap_set_and_get_dirty() {
    let img = create_async_image(1 << 20);
    let cluster_size = 1u64 << 16;
    img.bitmap_create("test", None, false).unwrap();

    assert!(!img.bitmap_get_dirty("test", 0).unwrap());
    img.bitmap_set_dirty("test", 0, cluster_size).unwrap();
    assert!(img.bitmap_get_dirty("test", 0).unwrap());
    assert!(!img.bitmap_get_dirty("test", cluster_size).unwrap());
}

#[test]
fn bitmap_clear() {
    let img = create_async_image(1 << 20);
    img.bitmap_create("test", None, false).unwrap();

    img.bitmap_set_dirty("test", 0, 1 << 16).unwrap();
    assert!(img.bitmap_get_dirty("test", 0).unwrap());

    img.bitmap_clear("test").unwrap();
    assert!(!img.bitmap_get_dirty("test", 0).unwrap());
}

#[test]
fn bitmap_delete() {
    let img = create_async_image(1 << 20);
    img.bitmap_create("to-delete", None, false).unwrap();
    assert_eq!(img.bitmap_list().unwrap().len(), 1);

    img.bitmap_delete("to-delete").unwrap();
    assert!(img.bitmap_list().unwrap().is_empty());
}

#[test]
fn bitmap_enable_disable_tracking() {
    let img = create_async_image(1 << 20);
    img.bitmap_create("track-me", None, false).unwrap();

    // Enable tracking (makes it auto)
    img.bitmap_enable_tracking("track-me").unwrap();

    let bitmaps = img.bitmap_list().unwrap();
    assert!(bitmaps[0].auto);

    // Disable tracking
    img.bitmap_disable_tracking("track-me").unwrap();

    let bitmaps = img.bitmap_list().unwrap();
    assert!(!bitmaps[0].auto);
}

#[test]
fn bitmap_list_empty() {
    let img = create_async_image(1 << 20);
    assert!(img.bitmap_list().unwrap().is_empty());
}

// ---- Hash API tests ----

#[test]
fn hash_init_and_has_hashes() {
    let img = create_async_image(1 << 20);
    assert!(!img.has_hashes().unwrap());

    img.hash_init(None, None).unwrap();
    assert!(img.has_hashes().unwrap());
}

#[test]
fn hash_init_and_info() {
    let img = create_async_image(1 << 20);
    img.hash_init(None, None).unwrap();

    let info = img.hash_info().unwrap().expect("should have hash info");
    assert_eq!(info.hash_size, 32); // BLAKE3 default
}

#[test]
fn hash_write_then_verify_clean() {
    let img = create_async_image(1 << 20);
    img.hash_init(None, None).unwrap();

    img.write_at(&[0xAA; 4096], 0).unwrap();
    img.write_at(&[0xBB; 4096], 1 << 16).unwrap();
    img.flush().unwrap();

    let mismatches = img.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "freshly written data should verify clean");
}

#[test]
fn hash_rehash_counts_clusters() {
    let img = create_async_image(1 << 20);

    // Write data first, then init hashes
    img.write_at(&[0xAA; 4096], 0).unwrap();
    img.write_at(&[0xBB; 4096], 1 << 16).unwrap();

    img.hash_init(None, None).unwrap();
    let count = img.hash_rehash().unwrap();
    assert!(count >= 2, "should hash at least 2 allocated clusters");

    let mismatches = img.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

#[test]
fn hash_export_returns_entries() {
    let img = create_async_image(1 << 20);
    img.hash_init(None, None).unwrap();

    let cluster_size = 1u64 << 16;
    img.write_at(&vec![0xDD; cluster_size as usize], 0).unwrap();
    img.write_at(&vec![0xEE; cluster_size as usize], cluster_size).unwrap();
    img.flush().unwrap();

    // Rehash to populate hash entries for allocated clusters
    let count = img.hash_rehash().unwrap();
    assert!(count >= 2);

    let entries = img.hash_export(None).unwrap();
    let allocated: Vec<_> = entries.iter().filter(|e| e.hash != vec![0u8; 32]).collect();
    assert!(allocated.len() >= 2, "should have at least 2 non-zero hash entries");

    for e in &allocated {
        assert_eq!(e.hash.len(), 32);
    }
}

#[test]
fn hash_remove() {
    let img = create_async_image(1 << 20);
    img.hash_init(None, None).unwrap();
    assert!(img.has_hashes().unwrap());

    img.hash_remove().unwrap();
    assert!(!img.has_hashes().unwrap());
}

// ---- Integrity API tests ----

#[test]
fn integrity_check_clean_image() {
    let img = create_async_image(1 << 20);
    img.write_at(&[0xAA; 4096], 0).unwrap();
    img.flush().unwrap();

    let report = img.check_integrity().unwrap();
    assert!(
        report.leaks.is_empty() && report.mismatches.is_empty(),
        "fresh image should have clean integrity"
    );
}

#[test]
fn integrity_check_and_repair_clean() {
    let img = create_async_image(1 << 20);
    img.write_at(&[0xBB; 4096], 0).unwrap();
    img.flush().unwrap();

    let report = img.check_and_repair(None).unwrap();
    assert!(report.is_clean(), "fresh image should be clean");
}

// ---- Compressed write tests ----

#[test]
fn write_cluster_maybe_compressed_roundtrip() {
    let img = create_async_image(1 << 20);
    let cluster_size = 1usize << 16;

    // Highly compressible data (all same byte)
    let data = vec![0xAA; cluster_size];
    img.write_cluster_maybe_compressed(&data, 0).unwrap();

    let mut buf = vec![0u8; cluster_size];
    img.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data, "compressed write should read back correctly");
}

#[test]
fn write_cluster_maybe_compressed_falls_back_for_random() {
    let img = create_async_image(1 << 20);
    let cluster_size = 1usize << 16;

    // Pseudo-random data that won't compress well
    let data: Vec<u8> = (0..cluster_size).map(|i| {
        ((i.wrapping_mul(7919) ^ i.wrapping_mul(104729)) & 0xFF) as u8
    }).collect();
    img.write_cluster_maybe_compressed(&data, 0).unwrap();

    let mut buf = vec![0u8; cluster_size];
    img.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data, "uncompressible data should still roundtrip");
}

// ---- Error path tests ----

#[test]
fn readonly_rejects_write() {
    let img = create_readonly_async_image(1 << 20);
    let result = img.write_at(&[0x42; 64], 0);
    assert!(matches!(result, Err(Error::ReadOnly)));
}

#[test]
fn readonly_rejects_flush() {
    let img = create_readonly_async_image(1 << 20);
    let result = img.flush();
    assert!(matches!(result, Err(Error::ReadOnly)));
}

#[test]
fn readonly_rejects_snapshot_create() {
    let img = create_readonly_async_image(1 << 20);
    let result = img.snapshot_create("nope");
    assert!(matches!(result, Err(Error::ReadOnly)));
}

#[test]
fn readonly_rejects_bitmap_create() {
    let img = create_readonly_async_image(1 << 20);
    let result = img.bitmap_create("nope", None, false);
    assert!(matches!(result, Err(Error::ReadOnly)));
}

#[test]
fn readonly_rejects_hash_init() {
    let img = create_readonly_async_image(1 << 20);
    let result = img.hash_init(None, None);
    assert!(matches!(result, Err(Error::ReadOnly)));
}

#[test]
fn readonly_allows_read() {
    let img = create_readonly_async_image(1 << 20);
    let mut buf = vec![0u8; 512];
    img.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn readonly_allows_accessors() {
    let img = create_readonly_async_image(1 << 20);
    assert_eq!(img.virtual_size().unwrap(), 1 << 20);
    assert!(!img.is_encrypted().unwrap());
    assert!(!img.is_writable().unwrap());
}

#[test]
fn readonly_allows_integrity_check() {
    let img = create_readonly_async_image(1 << 20);
    let report = img.check_integrity().unwrap();
    assert!(report.leaks.is_empty() && report.mismatches.is_empty());
}
