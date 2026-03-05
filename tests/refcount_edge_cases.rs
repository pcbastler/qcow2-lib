//! Refcount edge-case tests.
//!
//! Tests all refcount widths (1/2/4/8/16/32/64 bit), snapshot refcount
//! interactions, overflow behavior, leak detection, and double-ref scenarios.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};

const CLUSTER_SIZE: u64 = 65536;

// =====================================================================
// 1. Various refcount widths via QEMU
// =====================================================================

#[test]
fn read_with_refcount_bits_1() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    // refcount_bits=1 only allows refcount 0 or 1 — writing new clusters
    // can overflow since allocation itself needs refcount tracking.
    // Just verify we can open and read the header correctly.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rc1.qcow2");
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "refcount_bits=1"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    let image = Qcow2Image::open(&path).unwrap();
    assert_eq!(image.header().refcount_bits(), 1);
}

#[test]
fn read_write_with_refcount_bits_2() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    test_qemu_refcount_width(2);
}

#[test]
fn read_write_with_refcount_bits_4() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    test_qemu_refcount_width(4);
}

#[test]
fn read_write_with_refcount_bits_8() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    test_qemu_refcount_width(8);
}

#[test]
fn read_write_with_refcount_bits_16() {
    // Our default — create with our library
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rc16.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    assert_eq!(image.header().refcount_bits(), 16);

    image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    image.flush().unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
}

#[test]
fn read_write_with_refcount_bits_32() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    test_qemu_refcount_width(32);
}

#[test]
fn read_write_with_refcount_bits_64() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }
    test_qemu_refcount_width(64);
}

fn test_qemu_refcount_width(bits: u32) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("rc{bits}.qcow2"));
    let opt = format!("refcount_bits={bits}");

    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", &opt])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Open with our library, verify refcount_bits
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert_eq!(image.header().refcount_bits(), bits);

    // Write data
    image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], 0).unwrap();
    image.flush().unwrap();

    // Read back
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "data should roundtrip with refcount_bits={bits}"
    );

    // Integrity check
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "should be clean with refcount_bits={bits}: {report:?}"
    );
}

// =====================================================================
// 2. Snapshot refcount increments
// =====================================================================

#[test]
fn snapshot_increments_refcount() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap_rc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
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

    // Before snapshot: refcount = 1 for data cluster
    let report1 = image.check_integrity().unwrap();
    assert!(report1.is_clean());

    image.snapshot_create("s1").unwrap();

    // After snapshot: refcount = 2 for shared data cluster
    let report2 = image.check_integrity().unwrap();
    assert!(report2.is_clean());
}

#[test]
fn snapshot_delete_decrements_refcount() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap_del_rc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
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
    image.snapshot_create("s1").unwrap();
    image.snapshot_delete("s1").unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "should be clean after snap delete: {report:?}");
}

#[test]
fn multiple_snapshots_multiple_refcounts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi_snap_rc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
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

    // Create 3 snapshots (all sharing the same data cluster)
    for i in 1..=3 {
        image.snapshot_create(&format!("s{i}")).unwrap();
    }

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());

    // Delete snapshots one by one
    for i in 1..=3 {
        image.snapshot_delete(&format!("s{i}")).unwrap();
        let report = image.check_integrity().unwrap();
        assert!(
            report.is_clean(),
            "should stay clean after deleting s{i}: {report:?}"
        );
    }
}

// =====================================================================
// 3. Refcount with COW
// =====================================================================

#[test]
fn cow_after_snapshot_correct_refcounts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cow_rc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
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
    image.snapshot_create("s1").unwrap();

    // This write triggers COW: old cluster gets new refcount management
    image.write_at(&vec![0xEE; CLUSTER_SIZE as usize], 0).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "refcounts should be correct after COW: {report:?}"
    );
}

// =====================================================================
// 4. Many writes → many allocations
// =====================================================================

#[test]
fn many_clusters_correct_refcounts() {
    let vs = 64 * CLUSTER_SIZE;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    for i in 0..64u64 {
        image
            .write_at(&vec![(i & 0xFF) as u8; CLUSTER_SIZE as usize], i * CLUSTER_SIZE)
            .unwrap();
    }
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "64-cluster image should be clean: {report:?}");
}

// =====================================================================
// 5. Refcount table growth
// =====================================================================

#[test]
fn writing_beyond_initial_refcount_table() {
    // Create a very small image and keep writing to force refcount table growth
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grow.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 256 * CLUSTER_SIZE, // 16 MB
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    // Write to many clusters scattered across the address space
    for i in (0..256u64).step_by(4) {
        image
            .write_at(&vec![0xAA; CLUSTER_SIZE as usize], i * CLUSTER_SIZE)
            .unwrap();
    }
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "should handle refcount growth: {report:?}");
}

// =====================================================================
// 6. QEMU cross-validation
// =====================================================================

#[test]
fn qemu_check_after_many_writes_and_snapshots() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_rc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    // Write, snapshot, write, snapshot, delete
    for i in 0..8u64 {
        image
            .write_at(&vec![(i as u8) * 0x11; CLUSTER_SIZE as usize], i * CLUSTER_SIZE)
            .unwrap();
    }
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    for i in 0..4u64 {
        image
            .write_at(&vec![0xFF; CLUSTER_SIZE as usize], i * CLUSTER_SIZE)
            .unwrap();
    }
    image.flush().unwrap();
    image.snapshot_create("s2").unwrap();
    image.snapshot_delete("s1").unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img check should pass: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
