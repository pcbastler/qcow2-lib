//! Corruption detection and repair tests.
//!
//! Tests that our integrity checker detects refcount mismatches,
//! L1/L2 corruption, leaked clusters, and that repair mode fixes them.
//! Mirrors QEMU's qcow2-check and corruption-handling tests.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::engine::integrity::RepairMode;
use qcow2::io::IoBackend;
use qcow2::io::sync_backend::SyncFileBackend;

const CLUSTER_SIZE: u64 = 65536;
const IMAGE_SIZE: u64 = 4 * 1024 * 1024;

fn create_test_image(dir: &tempfile::TempDir, name: &str) -> Qcow2Image {
    let path = dir.path().join(name);
    Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

// =====================================================================
// 1. Clean images pass integrity check
// =====================================================================

#[test]
fn empty_image_passes_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let image = create_test_image(&dir, "empty.qcow2");
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "empty image should be clean: {report:?}");
}

#[test]
fn image_with_data_passes_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_test_image(&dir, "data.qcow2");
    image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
    image.flush().unwrap();
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "data image should be clean: {report:?}");
}

#[test]
fn image_with_snapshots_passes_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snaps.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0x11; CLUSTER_SIZE as usize], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();
    image.write_at(&vec![0x22; CLUSTER_SIZE as usize], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s2").unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "snapshot image should be clean: {report:?}");
}

// =====================================================================
// 2. Refcount corruption detection
// =====================================================================

#[test]
fn detect_refcount_too_low() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rc_low.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Corrupt: zero out the refcount for the data cluster
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        // Read refcount table offset from header
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 48).unwrap(); // offset 48 = refcount_table_offset
        let rct_offset = u64::from_be_bytes(buf);

        // Read refcount block offset from refcount table
        backend.read_exact_at(&mut buf, rct_offset).unwrap();
        let rcb_offset = u64::from_be_bytes(buf);

        // Zero out a non-zero refcount (data cluster is likely cluster index 4+)
        // Set refcounts for clusters 4-7 to 0 (they were likely allocated)
        for i in 4..8u64 {
            let rc_offset = rcb_offset + i * 2; // 16-bit refcounts
            backend.write_all_at(&[0, 0], rc_offset).unwrap();
        }
    }

    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        !report.is_clean(),
        "should detect refcount mismatch after corruption"
    );
    assert!(
        !report.mismatches.is_empty(),
        "should have refcount mismatches"
    );
}

#[test]
fn detect_leaked_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leaked.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Corrupt: make L2 entry point to unallocated, leaving cluster with refcount but no reference
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        // Read L1 table offset
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap(); // offset 40 = l1_table_offset
        let l1_offset = u64::from_be_bytes(buf);

        // Read L2 table offset from L1[0]
        backend.read_exact_at(&mut buf, l1_offset).unwrap();
        let l2_raw = u64::from_be_bytes(buf);
        let l2_offset = l2_raw & 0x00FFFFFFFFFFFE00;

        // Zero out L2[0] to make the data cluster unreachable
        backend.write_all_at(&[0u8; 8], l2_offset).unwrap();
    }

    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        !report.is_clean(),
        "should detect leaked cluster"
    );
    assert!(
        !report.leaks.is_empty(),
        "should report leaked clusters"
    );
}

// =====================================================================
// 3. Repair
// =====================================================================

#[test]
fn repair_leaked_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repair_leak.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Create leak: zero L2 entry but leave refcount
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap();
        let l1_offset = u64::from_be_bytes(buf);
        backend.read_exact_at(&mut buf, l1_offset).unwrap();
        let l2_raw = u64::from_be_bytes(buf);
        let l2_offset = l2_raw & 0x00FFFFFFFFFFFE00;
        backend.write_all_at(&[0u8; 8], l2_offset).unwrap();
    }

    // Verify corruption detected
    let image = Qcow2Image::open_rw(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(!report.is_clean());
    drop(image);

    // Repair
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let report = image.check_and_repair(Some(RepairMode::Full)).unwrap();

    // After repair, check again
    let report2 = image.check_integrity().unwrap();
    assert!(
        report2.is_clean(),
        "image should be clean after repair: {report2:?}"
    );
}

#[test]
fn repair_leaks_only_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repair_leaks_only.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xCC; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Create leak
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap();
        let l1_offset = u64::from_be_bytes(buf);
        backend.read_exact_at(&mut buf, l1_offset).unwrap();
        let l2_raw = u64::from_be_bytes(buf);
        let l2_offset = l2_raw & 0x00FFFFFFFFFFFE00;
        backend.write_all_at(&[0u8; 8], l2_offset).unwrap();
    }

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let _report = image.check_and_repair(Some(RepairMode::LeaksOnly)).unwrap();

    // LeaksOnly should fix the refcount leak
    let report2 = image.check_integrity().unwrap();
    assert!(
        report2.leaks.is_empty(),
        "leaks should be fixed in LeaksOnly mode"
    );
}

// =====================================================================
// 4. QEMU cross-validation of repair
// =====================================================================

#[test]
fn qemu_check_passes_after_our_repair() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_repair.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xDD; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Create leak
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap();
        let l1_offset = u64::from_be_bytes(buf);
        backend.read_exact_at(&mut buf, l1_offset).unwrap();
        let l2_raw = u64::from_be_bytes(buf);
        let l2_offset = l2_raw & 0x00FFFFFFFFFFFE00;
        backend.write_all_at(&[0u8; 8], l2_offset).unwrap();
    }

    // Repair with our code
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        image.check_and_repair(Some(RepairMode::Full)).unwrap();
        image.flush().unwrap();
    }

    // QEMU should accept the repaired image
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img check should pass after our repair: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// =====================================================================
// 5. Integrity report statistics
// =====================================================================

#[test]
fn integrity_report_counts_cluster_types() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stats.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    // Write data to 2 clusters
    image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
    // Write a compressed cluster
    image
        .write_cluster_maybe_compressed(&vec![0xCC; CLUSTER_SIZE as usize], 2 * CLUSTER_SIZE)
        .unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
    // Should have at least 2 data clusters (possibly 3 if compressed counted separately)
    assert!(
        report.stats.data_clusters + report.stats.compressed_clusters >= 2,
        "should count allocated clusters: {:?}",
        report.stats
    );
}

#[test]
fn total_errors_reflects_mismatches_and_leaks() {
    let dir = tempfile::tempdir().unwrap();
    let image = create_test_image(&dir, "clean.qcow2");
    let report = image.check_integrity().unwrap();
    assert_eq!(report.total_errors(), 0);
    assert!(report.mismatches.is_empty());
    assert!(report.leaks.is_empty());
}

// =====================================================================
// 6. L1 table corruption
// =====================================================================

#[test]
fn corrupted_l1_entry_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l1_corrupt.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
        image.flush().unwrap();
    }

    // Corrupt L1[0] to point to nonsense offset
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap();
        let l1_offset = u64::from_be_bytes(buf);

        // Write a misaligned/bogus L2 offset
        let bogus_l2: u64 = 0x8000_0000_DEAD_BE00; // copied bit set, misaligned
        backend.write_all_at(&bogus_l2.to_be_bytes(), l1_offset).unwrap();
    }

    // Should either error on open or detect issues on integrity check
    let result = Qcow2Image::open(&path);
    match result {
        Err(_) => {} // Rejection on open is fine
        Ok(image) => {
            // If it opens, integrity check should either error or find issues
            match image.check_integrity() {
                Err(_) => {} // Error during check is fine for corrupted L1
                Ok(report) => {
                    assert!(
                        !report.is_clean(),
                        "corrupted L1 should be detected by integrity check"
                    );
                }
            }
        }
    }
}

// =====================================================================
// 7. Double allocation detection
// =====================================================================

#[test]
fn detect_double_referenced_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("double_ref.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        // Write two clusters
        image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
        image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
        image.flush().unwrap();
    }

    // Make L2[1] point to the same host offset as L2[0]
    {
        let backend = SyncFileBackend::open_rw(&path).unwrap();
        let mut buf = [0u8; 8];
        backend.read_exact_at(&mut buf, 40).unwrap();
        let l1_offset = u64::from_be_bytes(buf);

        backend.read_exact_at(&mut buf, l1_offset).unwrap();
        let l2_raw = u64::from_be_bytes(buf);
        let l2_offset = l2_raw & 0x00FFFFFFFFFFFE00;

        // Read L2[0] host offset
        backend.read_exact_at(&mut buf, l2_offset).unwrap();
        let l2_entry_0 = u64::from_be_bytes(buf);

        // Copy L2[0] to L2[1] (double reference)
        backend.write_all_at(&l2_entry_0.to_be_bytes(), l2_offset + 8).unwrap();
    }

    let image = Qcow2Image::open(&path).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        !report.is_clean(),
        "double-referenced cluster should be detected"
    );
    assert!(
        !report.mismatches.is_empty(),
        "should have refcount mismatches for double-referenced cluster"
    );
}

// =====================================================================
// 8. Repair preserves data
// =====================================================================

#[test]
fn repair_does_not_corrupt_good_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repair_safe.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
        image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
        image.flush().unwrap();
    }

    // Run repair on a clean image — should be a no-op
    {
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let report = image.check_and_repair(Some(RepairMode::Full)).unwrap();
        assert!(report.is_clean(), "clean image should report clean after repair");
        image.flush().unwrap();
    }

    // Verify data is still intact
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "data cluster 0 should be intact");
    image.read_at(&mut buf, CLUSTER_SIZE).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "data cluster 1 should be intact");
}
