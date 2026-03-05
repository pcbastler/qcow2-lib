//! Detailed snapshot lifecycle tests.
//!
//! Tests snapshot create/apply/delete, data isolation, COW after snapshot,
//! multiple snapshots, compressed clusters with snapshots, and integrity.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};

const CS: usize = 65536;
const CSU: u64 = CS as u64;

fn create_file(dir: &tempfile::TempDir, name: &str, vs: u64) -> Qcow2Image {
    Qcow2Image::create(
        &dir.path().join(name),
        CreateOptions {
            virtual_size: vs,
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
// 1. Basic lifecycle
// =====================================================================

#[test]
fn create_and_list_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "snap.qcow2", 1 << 20);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    image.snapshot_create("test_snap").unwrap();
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "test_snap");
}

#[test]
fn delete_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "del.qcow2", 1 << 20);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();
    image.snapshot_delete("s1").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert!(snaps.is_empty());
}

#[test]
fn apply_snapshot_restores_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "apply.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));

    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 2. Data isolation between snapshots
// =====================================================================

#[test]
fn snapshots_isolate_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "isolate.qcow2", 4 * CSU);

    image.write_at(&vec![0x11; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0x22; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s2").unwrap();

    image.write_at(&vec![0x33; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s3").unwrap();

    let mut buf = vec![0u8; CS];

    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));

    image.snapshot_apply("s3").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x33));

    image.snapshot_apply("s2").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22));
}

#[test]
fn snapshot_different_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "diff_clusters.qcow2", 4 * CSU);

    // Write cluster 0
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Write cluster 1, modify cluster 0
    image.write_at(&vec![0xBB; CS], CSU).unwrap();
    image.write_at(&vec![0xCC; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];

    // Current state: cluster 0 = 0xCC, cluster 1 = 0xBB
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));

    // Revert: cluster 0 = 0xAA, cluster 1 = unallocated (zeros)
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

// =====================================================================
// 3. COW after snapshot
// =====================================================================

#[test]
fn cow_after_snapshot_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "cow_partial.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Partial write triggers COW
    image.write_at(&vec![0xFF; 512], 100).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..100].iter().all(|&b| b == 0xAA));
    assert!(buf[100..612].iter().all(|&b| b == 0xFF));
    assert!(buf[612..].iter().all(|&b| b == 0xAA));

    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 4. Multiple snapshots stress
// =====================================================================

#[test]
fn ten_snapshots_create_apply_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "ten.qcow2", 1 << 20);

    for i in 0u8..10 {
        image.write_at(&vec![i * 10 + 10; CS], 0).unwrap();
        image.flush().unwrap();
        image.snapshot_create(&format!("s{i}")).unwrap();
    }

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 10);

    // Verify each snapshot
    let mut buf = vec![0u8; CS];
    for i in 0u8..10 {
        image.snapshot_apply(&format!("s{i}")).unwrap();
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == i * 10 + 10), "snapshot s{i}");
    }
}

#[test]
fn create_and_delete_all_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "del_all.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    for i in 0..5 {
        image.snapshot_create(&format!("s{i}")).unwrap();
    }
    assert_eq!(image.snapshot_list().unwrap().len(), 5);

    for i in 0..5 {
        image.snapshot_delete(&format!("s{i}")).unwrap();
    }
    assert!(image.snapshot_list().unwrap().is_empty());

    // Data should still be readable
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 5. Snapshots with compressed clusters
// =====================================================================

#[test]
fn snapshot_with_compressed_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "comp_snap.qcow2", 1 << 20);

    image.write_cluster_maybe_compressed(&vec![0xDD; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0xEE; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xEE));

    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

// =====================================================================
// 6. Snapshots with zero clusters
// =====================================================================

#[test]
fn snapshot_preserves_zero_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "zero_snap.qcow2", 4 * CSU);

    // Write data then zero it
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.write_at(&vec![0u8; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Write data again
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();

    image.snapshot_apply("s1").unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00), "reverted should be zeros");
}

// =====================================================================
// 7. Snapshot with backing chain
// =====================================================================

#[test]
fn snapshot_in_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    let mut base_img = Qcow2Image::create(
        &base,
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
    base_img.write_at(&vec![0xAA; CS], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();

    // Write to overlay, snapshot, write again, revert
    ov.write_at(&vec![0xBB; CS], 0).unwrap();
    ov.flush().unwrap();
    ov.snapshot_create("s1").unwrap();

    ov.write_at(&vec![0xCC; CS], 0).unwrap();
    ov.flush().unwrap();

    let mut buf = vec![0u8; CS];
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));

    ov.snapshot_apply("s1").unwrap();
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

// =====================================================================
// 8. Error cases
// =====================================================================

#[test]
fn duplicate_snapshot_name_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "dup.qcow2", 1 << 20);
    image.flush().unwrap();
    image.snapshot_create("same_name").unwrap();
    let result = image.snapshot_create("same_name");
    assert!(result.is_err(), "duplicate snapshot name should be rejected");
}

#[test]
fn apply_nonexistent_snapshot_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "noexist.qcow2", 1 << 20);
    image.flush().unwrap();
    let result = image.snapshot_apply("doesnt_exist");
    assert!(result.is_err());
}

#[test]
fn delete_nonexistent_snapshot_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "noexist2.qcow2", 1 << 20);
    image.flush().unwrap();
    let result = image.snapshot_delete("doesnt_exist");
    assert!(result.is_err());
}

// =====================================================================
// 9. Integrity after snapshot operations
// =====================================================================

#[test]
fn integrity_clean_after_complex_snapshot_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "complex.qcow2", 4 * CSU);

    // Write, snapshot, write, snapshot, delete first, apply second
    image.write_at(&vec![0x11; CS], 0).unwrap();
    image.write_at(&vec![0x22; CS], CSU).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0x33; CS], 0).unwrap();
    image.write_at(&vec![0x44; CS], 2 * CSU).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s2").unwrap();

    image.snapshot_delete("s1").unwrap();
    image.snapshot_apply("s2").unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "should be clean: {report:?}");
}

// =====================================================================
// 10. QEMU interop
// =====================================================================

#[test]
fn qemu_check_after_snapshot_operations() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_snap.qcow2");

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

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();
    image.write_at(&vec![0xBB; CS], 0).unwrap();
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
        "qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn qemu_reads_our_snapshot_data() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_read_snap.qcow2");

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
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    // QEMU should read the active state (0xBB)
    let ti = common::TestImage::wrap(path, dir);
    let data = ti.read_via_qemu(0, 512);
    assert!(data.iter().all(|&b| b == 0xBB));
}
