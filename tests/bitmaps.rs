//! Integration tests for persistent dirty bitmaps.
//!
//! Cross-validates bitmap operations between our library and QEMU tools.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::engine::integrity::check_integrity;

/// Create a bitmap with our library, verify with qemu-img bitmap --list.
#[test]
fn library_create_bitmap_qemu_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("backup-0", Some(16), false).unwrap();
    image.flush().unwrap();
    drop(image);

    // qemu-img check should pass
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img");

    assert!(
        output.status.success(),
        "image with bitmap should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // qemu-img info should show the bitmap
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("backup-0"),
        "qemu-img info should show our bitmap: {stdout}"
    );
    assert!(
        stdout.contains("65536") || stdout.contains("granularity"),
        "should show granularity: {stdout}"
    );
}

/// Create a bitmap with qemu-img, read it with our library.
#[test]
fn qemu_create_bitmap_library_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    // Create image with qemu-img
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&path)
        .arg("10M")
        .output()
        .expect("failed to run qemu-img create");
    assert!(output.status.success());

    // Add bitmap with qemu-img
    let output = std::process::Command::new("qemu-img")
        .args(["bitmap", "--add", "-g", "65536", "-f", "qcow2"])
        .arg(&path)
        .arg("dirty-bitmap")
        .output()
        .expect("failed to run qemu-img bitmap");
    assert!(
        output.status.success(),
        "qemu-img bitmap --add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read with our library
    let image = Qcow2Image::open(&path).unwrap();
    let bitmaps = image.bitmap_list().unwrap();

    assert_eq!(bitmaps.len(), 1, "should find 1 bitmap");
    assert_eq!(bitmaps[0].name, "dirty-bitmap");
    assert_eq!(bitmaps[0].granularity, 65536);
    assert_eq!(bitmaps[0].bitmap_type, 1); // dirty
    assert!(!bitmaps[0].in_use);
}

/// Multiple bitmaps: create with library, verify with qemu-img.
#[test]
fn multiple_bitmaps_library_to_qemu() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("bitmap-a", Some(16), false).unwrap();
    image.bitmap_create("bitmap-b", Some(20), true).unwrap();
    image.flush().unwrap();
    drop(image);

    // Verify both show up in qemu-img info
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bitmap-a"), "should list bitmap-a: {stdout}");
    assert!(stdout.contains("bitmap-b"), "should list bitmap-b: {stdout}");

    // Should pass check
    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success(),
        "multi-bitmap image should pass qemu-img check"
    );
}

/// Delete bitmap, verify qemu no longer sees it.
#[test]
fn delete_bitmap_qemu_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("to-delete", Some(16), false).unwrap();
    image.bitmap_create("to-keep", Some(16), false).unwrap();
    image.bitmap_delete("to-delete").unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("to-delete"),
        "deleted bitmap should not appear: {stdout}"
    );
    assert!(
        stdout.contains("to-keep"),
        "kept bitmap should still appear: {stdout}"
    );

    // qemu-img check should pass
    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
}

/// Image with bitmap passes our integrity check.
#[test]
fn bitmap_image_integrity_clean() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("integrity-test", Some(16), false).unwrap();
    image.bitmap_set_dirty("integrity-test", 0, 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "bitmap image should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );
}

/// Bitmap with dirty bits: set with library, verify integrity.
#[test]
fn set_dirty_and_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("dirty-test", Some(16), false).unwrap();

    // Set some dirty ranges
    image.bitmap_set_dirty("dirty-test", 0, 65536).unwrap();
    image
        .bitmap_set_dirty("dirty-test", 131072, 65536)
        .unwrap();

    // Query dirty bits
    assert!(image.bitmap_get_dirty("dirty-test", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty-test", 65536).unwrap());
    assert!(image.bitmap_get_dirty("dirty-test", 131072).unwrap());

    // Clear and verify
    image.bitmap_clear("dirty-test").unwrap();
    assert!(!image.bitmap_get_dirty("dirty-test", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty-test", 131072).unwrap());

    image.flush().unwrap();
    drop(image);

    // Verify integrity
    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "after set/clear should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );
}

/// Auto-tracking: writes automatically mark bitmap dirty.
#[test]
fn auto_tracking_sets_dirty_on_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    // Create bitmap with AUTO flag
    image
        .bitmap_create("auto-track", Some(16), true)
        .unwrap();

    // Before write, nothing is dirty
    assert!(!image.bitmap_get_dirty("auto-track", 0).unwrap());

    // Write data — should auto-mark dirty
    image.write_at(&[0xAA; 4096], 0).unwrap();

    // Now the written area should be dirty
    assert!(image.bitmap_get_dirty("auto-track", 0).unwrap());

    // Unwritten area should still be clean
    assert!(!image.bitmap_get_dirty("auto-track", 65536).unwrap());

    image.flush().unwrap();
}

/// QEMU-created bitmap with data, readable by our library.
#[test]
fn qemu_bitmap_with_enable_library_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    // Create image and add bitmap
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = std::process::Command::new("qemu-img")
        .args(["bitmap", "--add", "-g", "65536", "-f", "qcow2"])
        .arg(&path)
        .arg("qemu-bitmap")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bitmap --add: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Enable the bitmap
    let output = std::process::Command::new("qemu-img")
        .args(["bitmap", "--enable", "-f", "qcow2"])
        .arg(&path)
        .arg("qemu-bitmap")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bitmap --enable: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read with our library
    let image = Qcow2Image::open(&path).unwrap();
    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "qemu-bitmap");
    assert_eq!(bitmaps[0].granularity, 65536);
}

/// Min granularity (512 bytes) round-trip.
#[test]
fn min_granularity_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("fine-grained", Some(9), false)
        .unwrap();
    image.bitmap_set_dirty("fine-grained", 0, 512).unwrap();
    assert!(image.bitmap_get_dirty("fine-grained", 0).unwrap());

    image.flush().unwrap();
    drop(image);

    // qemu should accept it
    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success(),
        "min-granularity bitmap should pass qemu check"
    );
}

/// Large granularity (1 MiB) round-trip.
#[test]
fn large_granularity_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 64 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("coarse", Some(20), false) // 1 MiB granularity
        .unwrap();
    image.flush().unwrap();
    drop(image);

    // Verify with qemu
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("coarse"), "should list bitmap: {stdout}");
    assert!(
        stdout.contains("1048576"),
        "should show 1MiB granularity: {stdout}"
    );
}

/// Bitmap create + delete + re-create cycle, check integrity at each step.
#[test]
fn bitmap_lifecycle_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    // Create
    image.bitmap_create("lifecycle", Some(16), false).unwrap();
    image.bitmap_set_dirty("lifecycle", 0, 65536).unwrap();
    image.flush().unwrap();

    // Check
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean(), "after create: not clean");

    // Delete
    image.bitmap_delete("lifecycle").unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean(), "after delete: not clean");

    // Re-create
    image
        .bitmap_create("lifecycle-v2", Some(20), false)
        .unwrap();
    image.flush().unwrap();

    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(report.is_clean(), "after re-create: not clean");

    drop(image);

    // qemu check
    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
}

// --- Round-trip persistence tests ---

/// Dirty bits survive flush + reopen.
#[test]
fn dirty_bits_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("persist", Some(16), false).unwrap();
    image.bitmap_set_dirty("persist", 0, 65536).unwrap();
    image
        .bitmap_set_dirty("persist", 131072, 65536)
        .unwrap();
    image.flush().unwrap();
    drop(image);

    // Reopen and verify dirty bits
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert!(image.bitmap_get_dirty("persist", 0).unwrap());
    assert!(!image.bitmap_get_dirty("persist", 65536).unwrap());
    assert!(image.bitmap_get_dirty("persist", 131072).unwrap());
}

/// Cleared bitmap stays clean after reopen.
#[test]
fn cleared_bitmap_stays_clean_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("test", Some(16), false).unwrap();
    image.bitmap_set_dirty("test", 0, 65536).unwrap();
    image.bitmap_clear("test").unwrap();
    image.flush().unwrap();
    drop(image);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert!(!image.bitmap_get_dirty("test", 0).unwrap());
}

/// Multiple bitmaps survive reopen independently.
#[test]
fn multiple_bitmaps_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("bm-a", Some(16), false).unwrap();
    image.bitmap_create("bm-b", Some(16), true).unwrap();
    image.bitmap_set_dirty("bm-a", 0, 65536).unwrap();
    // bm-b left clean
    image.flush().unwrap();
    drop(image);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 2);

    assert!(image.bitmap_get_dirty("bm-a", 0).unwrap());
    assert!(!image.bitmap_get_dirty("bm-b", 0).unwrap());

    // Verify flags persisted
    let bm_b = bitmaps.iter().find(|b| b.name == "bm-b").unwrap();
    assert!(bm_b.auto);
}

// --- Write + bitmap interaction tests ---

/// Write at the very last byte of virtual size with auto-tracking.
#[test]
fn auto_tracking_write_at_last_byte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");
    let vsize = 1024 * 1024;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: vsize,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("auto", Some(16), true)
        .unwrap();

    // Write single byte near end
    let offset = vsize - 512;
    image.write_at(&[0xFF; 512], offset).unwrap();

    assert!(image.bitmap_get_dirty("auto", offset).unwrap());
    // Earlier blocks should be clean
    assert!(!image.bitmap_get_dirty("auto", 0).unwrap());

    image.flush().unwrap();
}

/// Write spanning multiple granules marks all as dirty.
#[test]
fn auto_tracking_write_spanning_granules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("auto", Some(16), true)
        .unwrap();

    // Write 128K starting at 32K — covers bytes 32768..163840
    // Granule 0 (0..65535): touched, granule 1 (65536..131071): touched,
    // granule 2 (131072..196607): touched (up to 163839)
    image.write_at(&vec![0xAA; 128 * 1024], 32768).unwrap();

    assert!(image.bitmap_get_dirty("auto", 0).unwrap());      // granule 0
    assert!(image.bitmap_get_dirty("auto", 65536).unwrap());  // granule 1
    assert!(image.bitmap_get_dirty("auto", 131072).unwrap()); // granule 2
    assert!(!image.bitmap_get_dirty("auto", 196608).unwrap()); // granule 3 untouched

    image.flush().unwrap();
}

/// Multiple writes accumulate dirty bits.
#[test]
fn auto_tracking_multiple_writes_accumulate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("auto", Some(16), true)
        .unwrap();

    // First write
    image.write_at(&[0xAA; 4096], 0).unwrap();
    // Second write at different granule
    image.write_at(&[0xBB; 4096], 131072).unwrap();

    assert!(image.bitmap_get_dirty("auto", 0).unwrap());
    assert!(!image.bitmap_get_dirty("auto", 65536).unwrap());
    assert!(image.bitmap_get_dirty("auto", 131072).unwrap());

    image.flush().unwrap();
}

// --- Integrity interaction tests ---

/// Image with writes + auto-tracking bitmap passes integrity.
#[test]
fn integrity_clean_after_writes_with_auto_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("auto", Some(16), true).unwrap();

    // Do several writes
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();
    image.write_at(&[0xCC; 4096], 131072).unwrap();
    image.flush().unwrap();
    drop(image);

    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "image with writes+auto bitmap should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );
}

/// Multiple bitmaps with data all pass integrity.
#[test]
fn integrity_clean_with_multiple_dirty_bitmaps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("bm-a", Some(16), false).unwrap();
    image.bitmap_create("bm-b", Some(16), false).unwrap();

    image.bitmap_set_dirty("bm-a", 0, 65536).unwrap();
    image.bitmap_set_dirty("bm-b", 65536, 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "multiple dirty bitmaps should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );
}

/// Integrity remains clean after delete + re-create cycle.
#[test]
fn integrity_clean_after_delete_recreate_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    // Create, dirty, delete 3 times
    for i in 0..3 {
        let name = format!("cycle-{i}");
        image.bitmap_create(&name, Some(16), false).unwrap();
        image
            .bitmap_set_dirty(&name, (i as u64) * 65536, 65536)
            .unwrap();
        image.flush().unwrap();
        image.bitmap_delete(&name).unwrap();
        image.flush().unwrap();
    }

    // Final bitmap stays
    image.bitmap_create("final", Some(16), false).unwrap();
    image.bitmap_set_dirty("final", 0, 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "after create/delete cycles: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    // qemu agrees
    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
}

// --- Edge case integration tests ---

/// Zero-length virtual size (degenerate case).
#[test]
fn bitmap_on_zero_size_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    // qcow2 with 0 size is unusual but valid
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 0,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    // Creating a bitmap on a zero-size image should work (table size = 0)
    image.bitmap_create("test", Some(16), false).unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);

    image.flush().unwrap();
}

/// Bitmap with custom cluster size (non-default).
#[test]
fn bitmap_with_custom_cluster_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 * 1024 * 1024,
            cluster_bits: Some(17), // 128K clusters
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("test", Some(16), false).unwrap();
    image.bitmap_set_dirty("test", 0, 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    // Verify with our integrity check
    let image = Qcow2Image::open(&path).unwrap();
    let report = check_integrity(image.backend(), image.header()).unwrap();
    assert!(
        report.is_clean(),
        "custom cluster size: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );
}

/// Bitmap persists through flush cycle without modification.
#[test]
fn bitmap_survives_unrelated_flush() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("test", Some(16), false).unwrap();
    image.bitmap_set_dirty("test", 0, 65536).unwrap();
    image.flush().unwrap();

    // Do unrelated write + flush — bitmap should survive
    image.write_at(&[0xFF; 4096], 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert!(image.bitmap_get_dirty("test", 0).unwrap());
}

/// Read from image with bitmap doesn't corrupt bitmap state.
#[test]
fn read_does_not_affect_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("test", Some(16), true).unwrap();

    // Write to set dirty
    image.write_at(&[0xAA; 4096], 0).unwrap();
    assert!(image.bitmap_get_dirty("test", 0).unwrap());
    assert!(!image.bitmap_get_dirty("test", 65536).unwrap());

    // Read should not change dirty state
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 65536).unwrap();
    assert!(!image.bitmap_get_dirty("test", 65536).unwrap());
}

/// QEMU interop: our bitmap with dirty bits, qemu-img check passes.
#[test]
fn qemu_check_after_set_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image.bitmap_create("dirty-test", Some(16), false).unwrap();

    // Set many dirty ranges
    for i in 0..8 {
        image
            .bitmap_set_dirty("dirty-test", i * 65536, 65536)
            .unwrap();
    }

    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "qemu-img check after set_dirty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// QEMU interop: bitmap with 512-byte granularity passes qemu check.
#[test]
fn qemu_check_min_granularity_with_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("fine", Some(9), false)
        .unwrap();
    image.bitmap_set_dirty("fine", 0, 512).unwrap();
    image.bitmap_set_dirty("fine", 1024, 512).unwrap();
    image.flush().unwrap();
    drop(image);

    assert!(
        std::process::Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success(),
        "min-granularity bitmap with dirty bits should pass qemu check"
    );
}

/// Bitmap after image data writes + qemu cross-validation.
#[test]
fn qemu_validates_auto_tracked_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
        },
    )
    .unwrap();

    image
        .bitmap_create("auto", Some(16), true)
        .unwrap();

    // Write real data — auto-tracking marks bitmap
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 131072).unwrap();
    image.flush().unwrap();
    drop(image);

    // qemu-img check
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "auto-tracked bitmap should pass qemu check: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // qemu-img info should show the bitmap
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auto"), "should show auto bitmap: {stdout}");
}
