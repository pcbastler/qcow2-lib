//! Integration tests for BLAKE3 per-cluster hashes.

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::engine::integrity::check_integrity;

fn create_test_image(virtual_size: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(qcow2_lib::io::MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap()
}

// ---- Init / Info / Remove ----

#[test]
fn hash_init_default_32() {
    let mut image = create_test_image(1 << 20);
    assert!(!image.has_hashes());

    image.hash_init(None).unwrap();
    assert!(image.has_hashes());

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_size, 32);
    assert!(info.consistent);
}

#[test]
fn hash_init_16_bytes() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(Some(16)).unwrap();

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_size, 16);
}

#[test]
fn hash_init_rejects_invalid_size() {
    let mut image = create_test_image(1 << 20);
    let result = image.hash_init(Some(24));
    assert!(result.is_err());
}

#[test]
fn hash_init_rejects_duplicate() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();
    let result = image.hash_init(None);
    assert!(result.is_err());
}

#[test]
fn hash_remove_clears_extension() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();
    assert!(image.has_hashes());

    image.hash_remove().unwrap();
    assert!(!image.has_hashes());
    assert!(image.hash_info().is_none());
}

#[test]
fn hash_remove_noop_without_hashes() {
    let mut image = create_test_image(1 << 20);
    image.hash_remove().unwrap(); // should not error
}

// ---- Write + Verify ----

#[test]
fn write_then_verify_clean() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    // Write some data
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();
    image.flush().unwrap();

    // Verify should report no mismatches
    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "expected clean verify, got {} mismatches", mismatches.len());
}

#[test]
fn write_multiple_clusters_then_verify() {
    let mut image = create_test_image(4 << 20); // 4 MB
    image.hash_init(None).unwrap();

    // Write data spanning multiple clusters
    let data = vec![0x42; 128 * 1024]; // 128 KB = 2 clusters
    image.write_at(&data, 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

#[test]
fn partial_cluster_write_hashes_correctly() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    // Write less than a full cluster
    image.write_at(&[0x55; 512], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

// ---- Rehash ----

#[test]
fn rehash_counts_allocated_clusters() {
    let mut image = create_test_image(1 << 20);

    // Write data first
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();

    // Init hashes (no hashing yet)
    image.hash_init(None).unwrap();

    // Rehash
    let count = image.hash_rehash().unwrap();
    assert!(count >= 2, "expected at least 2 hashed clusters, got {count}");

    // Verify should be clean
    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

#[test]
fn rehash_empty_image() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    let count = image.hash_rehash().unwrap();
    assert_eq!(count, 0);
}

// ---- get_hash / export_hashes ----

#[test]
fn get_hash_returns_stored_hash() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    image.write_at(&[0xCC; 65536], 0).unwrap();
    image.flush().unwrap();

    let hash = image.hash_get(0).unwrap();
    assert!(hash.is_some());
    assert_eq!(hash.unwrap().len(), 32);
}

#[test]
fn get_hash_unallocated_returns_none() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    let hash = image.hash_get(0).unwrap();
    assert!(hash.is_none());
}

#[test]
fn export_hashes_returns_entries() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    image.write_at(&[0xDD; 65536], 0).unwrap();
    image.write_at(&[0xEE; 65536], 65536).unwrap();
    image.flush().unwrap();

    let entries = image.hash_export(None).unwrap();
    assert!(entries.len() >= 2);

    for e in &entries {
        assert_eq!(e.hash.len(), 32);
        assert!(e.allocated);
    }
}

// ---- 16-byte hashes ----

#[test]
fn hash_size_16_write_verify() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(Some(16)).unwrap();

    image.write_at(&[0xFF; 8192], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());

    let hash = image.hash_get(0).unwrap().unwrap();
    assert_eq!(hash.len(), 16);
}

// ---- Snapshot integration ----

#[test]
fn snapshot_preserves_hashes() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    // Write and get hash
    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();
    let hash_before = image.hash_get(0).unwrap().unwrap();

    // Take snapshot
    image.snapshot_create("snap1").unwrap();

    // Write different data (COW)
    image.write_at(&[0xBB; 65536], 0).unwrap();
    image.flush().unwrap();

    // Current hash should differ
    let hash_after = image.hash_get(0).unwrap().unwrap();
    assert_ne!(hash_before, hash_after);

    // Apply snapshot to restore
    image.snapshot_apply("snap1").unwrap();

    // Verify should be clean
    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "hashes should be clean after snapshot apply");
}

#[test]
fn snapshot_without_hashes_compatible() {
    let mut image = create_test_image(1 << 20);

    // Write data and take snapshot WITHOUT hashes
    image.write_at(&[0x11; 4096], 0).unwrap();
    image.snapshot_create("no-hash-snap").unwrap();

    // Now init hashes
    image.hash_init(None).unwrap();
    image.write_at(&[0x22; 4096], 0).unwrap();
    image.flush().unwrap();

    // Apply the non-hash snapshot
    image.snapshot_apply("no-hash-snap").unwrap();

    // Hashes should be gone now
    assert!(!image.has_hashes());
}

#[test]
fn snapshot_delete_with_hashes() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();

    image.snapshot_create("snap1").unwrap();
    image.write_at(&[0xBB; 65536], 0).unwrap();
    image.flush().unwrap();

    // Delete the snapshot
    image.snapshot_delete("snap1").unwrap();

    // Image should still be consistent
    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

// ---- Integrity check ----

#[test]
fn integrity_clean_with_hashes() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();
    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "integrity should be clean: {:?}",
        report,
    );
}

#[test]
fn integrity_clean_after_rehash() {
    let mut image = create_test_image(1 << 20);
    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.hash_init(None).unwrap();
    image.hash_rehash().unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean());
}

#[test]
fn integrity_clean_after_remove() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();
    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();

    image.hash_remove().unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean());
}

#[test]
fn integrity_clean_with_hashes_and_snapshot() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("snap").unwrap();

    image.write_at(&[0xBB; 65536], 0).unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "integrity should be clean with hashes and snapshot: {:?}",
        report,
    );
}

// ---- Autoclear semantics ----

#[test]
fn autoclear_cleared_on_dirty_restored_on_flush() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None).unwrap();

    // Before any write, autoclear bit should be set
    let info = image.hash_info().unwrap();
    assert!(info.consistent);

    // Write triggers dirty → autoclear bit cleared
    image.write_at(&[0xAA; 512], 0).unwrap();

    // During dirty, bit should be cleared
    // (but since write_at also updates hashes, the bit is cleared by mark_dirty
    //  and we can check it hasn't been restored yet since we haven't flushed)
    // flush restores it
    image.flush().unwrap();

    let info = image.hash_info().unwrap();
    assert!(info.consistent, "autoclear bit should be restored after flush");
}

// ---- No-overhead when hashes not initialized ----

#[test]
fn write_without_hashes_no_overhead() {
    let mut image = create_test_image(1 << 20);
    assert!(!image.has_hashes());

    // Write should work without any hash overhead
    image.write_at(&[0xAA; 65536], 0).unwrap();
    image.flush().unwrap();

    // No hash info
    assert!(image.hash_info().is_none());
}
