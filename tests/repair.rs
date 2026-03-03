//! Integration tests: integrity checking, repair, compact, and shrink
//! with qemu-img cross-validation.

mod common;

use std::path::Path;

use byteorder::{BigEndian, ByteOrder};
use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::engine::integrity::RepairMode;
use qcow2_lib::io::sync_backend::SyncFileBackend;
use qcow2_lib::io::IoBackend;

/// Helper: run `qemu-img check` and assert success.
fn assert_qemu_check(path: &Path) {
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "qemu-img check failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Helper: create our image, write data, flush, and return path.
fn create_image_with_data(
    dir: &Path,
    name: &str,
    virtual_size: u64,
    data: &[(u64, &[u8])],
) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    for &(offset, buf) in data {
        image.write_at(buf, offset).unwrap();
    }
    image.flush().unwrap();
    drop(image);
    path
}

/// Corrupt a refcount entry on disk for a given cluster index.
fn corrupt_refcount(path: &Path, cluster_index: u64, new_value: u16) {
    let image = Qcow2Image::open(path).unwrap();
    let header = image.header().clone();
    drop(image);

    let backend = SyncFileBackend::open_rw(path).unwrap();
    let entries_per_block = header.refcounts_per_block();
    let rt_idx = cluster_index / entries_per_block;
    let block_idx = cluster_index % entries_per_block;

    let mut rt_entry_buf = [0u8; 8];
    let rt_entry_offset = header.refcount_table_offset.0 + rt_idx * 8;
    backend
        .read_exact_at(&mut rt_entry_buf, rt_entry_offset)
        .unwrap();
    let block_offset = u64::from_be_bytes(rt_entry_buf);

    // refcount_order=4 → 16-bit refcounts, 2 bytes each
    let byte_offset = block_offset + block_idx * 2;
    let mut val_buf = [0u8; 2];
    BigEndian::write_u16(&mut val_buf, new_value);
    backend.write_all_at(&val_buf, byte_offset).unwrap();
    backend.flush().unwrap();
}

// ---- 1. Library check agrees with qemu-img on clean image ----

#[test]
fn check_agrees_with_qemu_on_clean_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "clean.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096]), (65536, &[0xBB; 4096])],
    );

    assert_qemu_check(&path);

    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "library check should agree with qemu-img: mismatches={:?}, leaks={:?}",
        report.mismatches,
        report.leaks
    );
}

// ---- 2. Repair corrupt refcounts → qemu-img check OK ----

#[test]
fn repair_corrupt_refcounts_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "corrupt.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096])],
    );

    // Corrupt: set data cluster's refcount to 5 (should be 1)
    // Find a data cluster — cluster 0 is header, so data is further out
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    drop(image);

    // Pick the highest cluster index from the reference map (likely a data cluster)
    let data_cluster = *report.reference_map.keys().max().unwrap();
    corrupt_refcount(&path, data_cluster, 5);

    // Library should detect the mismatch
    let image = Qcow2Image::open(&path).unwrap();
    let pre_report = image.check_integrity().unwrap();
    drop(image);
    assert!(
        !pre_report.is_clean(),
        "corrupted image should fail check"
    );

    // Repair
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.check_and_repair(Some(RepairMode::Full)).unwrap();
    drop(image);

    // qemu-img should be happy now
    assert_qemu_check(&path);
}

// ---- 3. Repair after writes → valid ----

#[test]
fn repair_after_writes_produces_valid_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "written.qcow2",
        4 * 1024 * 1024,
        &[
            (0, &[0xAA; 65536]),
            (65536, &[0xBB; 65536]),
            (2 * 65536, &[0xCC; 65536]),
        ],
    );

    // Repair on a clean image should be a no-op — verify nothing breaks
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let report = image.check_and_repair(Some(RepairMode::Full)).unwrap();
    drop(image);

    assert!(report.is_clean(), "image with writes should already be clean");
    assert_eq!(report.total_errors(), 0, "clean image should have zero errors");
    assert_qemu_check(&path);

    // Verify data integrity after repair
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "data at offset 0 should survive repair");
    image.read_at(&mut buf, 65536).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "data at offset 65536 should survive repair");
}

// ---- 4. Repair after snapshot create+delete → valid ----

#[test]
fn repair_after_snapshot_cycle_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "snap-cycle.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xDD; 4096])],
    );

    // Create then delete a snapshot
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        image.snapshot_create("temp").unwrap();
        image.flush().unwrap();
    }
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        image.snapshot_delete("temp").unwrap();
        image.flush().unwrap();
    }

    // Repair
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let report = image.check_and_repair(Some(RepairMode::Full)).unwrap();
    drop(image);

    assert!(report.is_clean(), "should be clean after snapshot cycle");
    assert_qemu_check(&path);
}

// ---- 5. Repair corrupted → fixed + qemu-img check OK ----

#[test]
fn repair_fixes_leaked_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "leaked.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096])],
    );

    // Find the last used cluster + 1 to create a fake leaked cluster
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    let max_cluster = *report.reference_map.keys().max().unwrap();
    drop(image);

    // Set refcount of the next cluster to 1 (a leak — no references)
    let leaked_cluster = max_cluster + 1;
    corrupt_refcount(&path, leaked_cluster, 1);

    // Check detects the leak
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    drop(image);
    assert!(!report.leaks.is_empty(), "should detect the leaked cluster");

    // Repair
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.check_and_repair(Some(RepairMode::Full)).unwrap();
    drop(image);

    assert_qemu_check(&path);

    // Verify clean after repair
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "should be clean after repair");
}

// ---- 6. Compact → qemu-img check OK ----

#[test]
fn compact_produces_valid_image() {
    let dir = tempfile::tempdir().unwrap();
    let input = create_image_with_data(
        dir.path(),
        "input.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096]), (65536, &[0xBB; 4096])],
    );

    let output = dir.path().join("compacted.qcow2");
    qcow2_lib::engine::converter::convert_qcow2_to_qcow2(&input, &output, false).unwrap();

    assert_qemu_check(&output);
}

// ---- 7. Compact preserves data integrity ----

#[test]
fn compact_preserves_data() {
    let dir = tempfile::tempdir().unwrap();
    let pattern_a = vec![0xAAu8; 65536];
    let pattern_b = vec![0xBBu8; 4096];
    let input = create_image_with_data(
        dir.path(),
        "data.qcow2",
        4 * 1024 * 1024,
        &[(0, &pattern_a), (65536, &pattern_b)],
    );

    let output = dir.path().join("compacted.qcow2");
    qcow2_lib::engine::converter::convert_qcow2_to_qcow2(&input, &output, false).unwrap();

    // Read back from compacted image
    let mut image = Qcow2Image::open(&output).unwrap();
    let mut buf_a = vec![0u8; 65536];
    image.read_at(&mut buf_a, 0).unwrap();
    assert_eq!(buf_a, pattern_a);

    let mut buf_b = vec![0u8; 4096];
    image.read_at(&mut buf_b, 65536).unwrap();
    assert_eq!(buf_b, pattern_b);
}

// ---- 8. Compact --compress → qemu-img check OK ----

#[test]
fn compact_compressed_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let input = create_image_with_data(
        dir.path(),
        "compressible.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 65536])],
    );

    let output = dir.path().join("compressed.qcow2");
    qcow2_lib::engine::converter::convert_qcow2_to_qcow2(&input, &output, true).unwrap();

    assert_qemu_check(&output);

    // Verify data
    let mut image = Qcow2Image::open(&output).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// ---- 9. Shrink → qemu-img check OK ----

#[test]
fn shrink_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "shrink.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096])], // data at offset 0, well within new size
    );

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(2 * 1024 * 1024).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);

    // Verify data still readable
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// ---- 10. Shrink + truncate → smaller file ----

#[test]
fn shrink_and_truncate_reduces_file_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncate.qcow2");

    // Create image, write data, snapshot, delete snapshot → leaves freed clusters at end
    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 4 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xBB; 4096], 0).unwrap();
        image.snapshot_create("temp").unwrap();
        image.snapshot_delete("temp").unwrap();
        image.flush().unwrap();
    }

    let original_size = std::fs::metadata(&path).unwrap().len();

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let saved = image.truncate_free_tail().unwrap();
    image.flush().unwrap();
    drop(image);

    let new_size = std::fs::metadata(&path).unwrap().len();
    assert!(
        new_size < original_size,
        "file should shrink after truncate: was {original_size}, now {new_size}"
    );
    assert_eq!(
        original_size - new_size,
        saved,
        "saved bytes should match actual size reduction"
    );
    assert_qemu_check(&path);

    // Data preserved
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

// ---- 11. Repair is idempotent ----

#[test]
fn repair_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "idempotent.qcow2",
        4 * 1024 * 1024,
        &[(0, &[0xAA; 4096])],
    );

    // Corrupt and repair
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    let data_cluster = *report.reference_map.keys().max().unwrap();
    drop(image);
    corrupt_refcount(&path, data_cluster, 10);

    // First repair
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        image.check_and_repair(Some(RepairMode::Full)).unwrap();
    }
    assert_qemu_check(&path);

    // Second repair — should be a no-op
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let report = image.check_and_repair(Some(RepairMode::Full)).unwrap();
        assert!(
            report.is_clean(),
            "second repair should find image already clean"
        );
    }
    assert_qemu_check(&path);
}

// ---- 12. Round-trip: write → corrupt → repair → read → verify ----

#[test]
fn write_corrupt_repair_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pattern = vec![0xCDu8; 65536];
    let path = create_image_with_data(
        dir.path(),
        "roundtrip.qcow2",
        4 * 1024 * 1024,
        &[(0, &pattern)],
    );

    // Corrupt: set the header cluster refcount to 2 (should be 1)
    corrupt_refcount(&path, 0, 2);

    // Library should detect the mismatch
    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    drop(image);
    assert!(!report.is_clean(), "corrupted image should fail check");

    // Repair
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.check_and_repair(Some(RepairMode::Full)).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);

    // Read back data and verify
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, pattern, "data should survive corrupt + repair cycle");
}
