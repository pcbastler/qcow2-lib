//! Integration tests for BLAKE3 per-hash-chunk hashes.

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::engine::integrity::check_integrity;

fn create_test_image(virtual_size: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(qcow2_lib::io::MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap()
}

fn create_test_image_with_cluster_bits(virtual_size: u64, cluster_bits: u32) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(qcow2_lib::io::MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap()
}

// ---- Init / Info / Remove ----

#[test]
fn hash_init_default_32() {
    let mut image = create_test_image(1 << 20);
    assert!(!image.has_hashes());

    image.hash_init(None, None).unwrap();
    assert!(image.has_hashes());

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_size, 32);
    assert_eq!(info.hash_chunk_bits, 16); // default 64KB
    assert!(info.consistent);
}

#[test]
fn hash_init_16_bytes() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(Some(16), None).unwrap();

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_size, 16);
}

#[test]
fn hash_init_rejects_invalid_size() {
    let mut image = create_test_image(1 << 20);
    let result = image.hash_init(Some(24), None);
    assert!(result.is_err());
}

#[test]
fn hash_init_rejects_duplicate() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();
    let result = image.hash_init(None, None);
    assert!(result.is_err());
}

#[test]
fn hash_remove_clears_extension() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();
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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();

    // Rehash
    let count = image.hash_rehash().unwrap();
    assert!(count >= 2, "expected at least 2 hashed hash chunks, got {count}");

    // Verify should be clean
    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

#[test]
fn rehash_empty_image() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();

    let count = image.hash_rehash().unwrap();
    assert_eq!(count, 0);
}

// ---- get_hash / export_hashes ----

#[test]
fn get_hash_returns_stored_hash() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();

    image.write_at(&[0xCC; 65536], 0).unwrap();
    image.flush().unwrap();

    let hash = image.hash_get(0).unwrap();
    assert!(hash.is_some());
    assert_eq!(hash.unwrap().len(), 32);
}

#[test]
fn get_hash_unallocated_returns_none() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();

    let hash = image.hash_get(0).unwrap();
    assert!(hash.is_none());
}

#[test]
fn export_hashes_returns_entries() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();

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
    image.hash_init(Some(16), None).unwrap();

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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();
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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();
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
    image.hash_init(None, None).unwrap();
    image.hash_rehash().unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean());
}

#[test]
fn integrity_clean_after_remove() {
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();
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
    image.hash_init(None, None).unwrap();

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
    image.hash_init(None, None).unwrap();

    // Before any write, autoclear bit should be set
    let info = image.hash_info().unwrap();
    assert!(info.consistent);

    // Write triggers dirty → autoclear bit cleared
    image.write_at(&[0xAA; 512], 0).unwrap();

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

// ---- Custom hash chunk sizes ----

#[test]
fn hash_init_custom_chunk_bits() {
    let mut image = create_test_image(1 << 20);
    // 4KB hash chunks
    image.hash_init(None, Some(12)).unwrap();

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_chunk_bits, 12);
    assert_eq!(info.hash_size, 32);
}

#[test]
fn hash_write_verify_small_chunks() {
    // 4KB hash chunks with default 64KB clusters
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, Some(12)).unwrap();

    // Write 8KB of data → should touch 2 hash chunks (each 4KB)
    image.write_at(&[0xAA; 8192], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "verify with 4KB hash chunks should be clean");

    // Should have hashes for hash chunk 0 and 1
    assert!(image.hash_get(0).unwrap().is_some());
    assert!(image.hash_get(1).unwrap().is_some());
}

#[test]
fn hash_write_verify_large_chunks() {
    // 128KB hash chunks with default 64KB clusters (hash chunk spans 2 clusters)
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, Some(17)).unwrap(); // 2^17 = 128KB

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_chunk_bits, 17);

    // Write 128KB of data → fills exactly 1 hash chunk
    image.write_at(&vec![0xBB; 128 * 1024], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "verify with 128KB hash chunks should be clean");

    assert!(image.hash_get(0).unwrap().is_some());
}

#[test]
fn hash_info_shows_chunk_bits() {
    let mut image = create_test_image(1 << 20);

    // Default → hash_chunk_bits = 16
    image.hash_init(None, None).unwrap();
    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_chunk_bits, 16);

    image.hash_remove().unwrap();

    // Custom 8KB → hash_chunk_bits = 13
    image.hash_init(None, Some(13)).unwrap();
    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_chunk_bits, 13);
}

#[test]
fn hash_init_rejects_invalid_chunk_bits() {
    let mut image = create_test_image(1 << 20);

    // Too small (< 12)
    assert!(image.hash_init(None, Some(11)).is_err());
    // Too large (> 24)
    assert!(image.hash_init(None, Some(25)).is_err());
}

#[test]
fn hash_with_small_clusters() {
    // 4KB clusters with default 64KB hash chunks (16 clusters per hash chunk)
    let mut image = create_test_image_with_cluster_bits(256 * 1024, 12); // 256KB image, 4KB clusters

    image.hash_init(None, None).unwrap(); // default 64KB hash chunks

    let info = image.hash_info().unwrap();
    assert_eq!(info.hash_chunk_bits, 16); // 64KB hash chunks

    // Write 64KB → fills one hash chunk composed of 16 clusters
    image.write_at(&vec![0xCC; 65536], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty(), "verify with 4KB clusters and 64KB hash chunks should be clean");

    // Rehash should also work
    let count = image.hash_rehash().unwrap();
    assert!(count >= 1);

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}

#[test]
fn open_rejects_misaligned_hash_table_offset() {
    use qcow2_lib::io::MemoryBackend;

    // Create a valid image with hashes, then corrupt the hash_table_offset
    // to be 512-aligned but not cluster-aligned (cluster_bits=16 → 64KB alignment).
    let mut image = create_test_image(1 << 20);
    image.hash_init(None, None).unwrap();
    image.flush().unwrap();

    // Extract raw image data and find the BLAKE3 extension to corrupt it
    let data = {
        let size = image.backend().file_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        image.backend().read_exact_at(&mut buf, 0).unwrap();
        buf
    };
    drop(image);

    // Find the BLAKE3 extension magic (0x434C4233) in the header area
    let ext_magic = 0x434C4233u32.to_be_bytes();
    let ext_pos = data.windows(4).position(|w| w == ext_magic).unwrap();
    // Extension data starts 8 bytes after the type field (4 bytes type + 4 bytes length)
    let offset_pos = ext_pos + 8; // first 8 bytes of extension data = hash_table_offset

    let mut corrupted = data.clone();
    // Set hash_table_offset to 0x10200 (512-aligned but not 64KB-aligned)
    corrupted[offset_pos..offset_pos + 8].copy_from_slice(&0x10200u64.to_be_bytes());

    let backend = Box::new(MemoryBackend::new(corrupted));
    let result = Qcow2Image::from_backend(backend);
    assert!(
        result.is_err(),
        "should reject non-cluster-aligned hash_table_offset"
    );
}

#[test]
fn zero_length_write_does_not_panic_with_hashes() {
    let mut image = create_test_image(1 << 20); // 1 MB
    image.hash_init(None, None).unwrap();

    // Empty write must not panic (previously caused u64 underflow in update_hashes_for_range)
    image.write_at(&[], 0).unwrap();
    image.flush().unwrap();

    let mismatches = image.hash_verify().unwrap();
    assert!(mismatches.is_empty());
}
