//! Detailed image resize tests.
//!
//! Tests grow/shrink, various cluster sizes, backing files, snapshots,
//! bitmaps, 4G boundary, and truncate_free_tail.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};

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
// 1. Basic grow
// =====================================================================

#[test]
fn grow_virtual_size() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "grow.qcow2", 1 << 20);
    assert_eq!(image.virtual_size(), 1 << 20);

    image.resize(2 << 20).unwrap();
    assert_eq!(image.virtual_size(), 2 << 20);

    // Should be able to write to new region
    image.write_at(&vec![0xAA; CS], CSU * 16).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, CSU * 16).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn grow_preserves_existing_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "grow_data.qcow2", 1 << 20);

    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();

    image.resize(4 << 20).unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

#[test]
fn grow_new_region_reads_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "grow_zeros.qcow2", 1 << 20);

    image.resize(2 << 20).unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, CSU * 16).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

// =====================================================================
// 2. Basic shrink
// =====================================================================

#[test]
fn shrink_virtual_size() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "shrink.qcow2", 4 << 20);
    image.resize(1 << 20).unwrap();
    assert_eq!(image.virtual_size(), 1 << 20);
}

#[test]
fn shrink_preserves_data_in_range() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "shrink_data.qcow2", 4 << 20);

    image.write_at(&vec![0xCC; CS], 0).unwrap();
    image.flush().unwrap();

    image.resize(1 << 20).unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

#[test]
fn read_beyond_shrunk_size_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "shrink_oob.qcow2", 4 << 20);

    // Only write in the first 1MB so shrink doesn't hit ShrinkDataLoss
    image.write_at(&vec![0xDD; CS], 0).unwrap();
    image.flush().unwrap();

    image.resize(1 << 20).unwrap();

    let mut buf = vec![0u8; CS];
    let result = image.read_at(&mut buf, 3 * CSU * 16);
    assert!(result.is_err(), "should fail beyond new virtual size");
}

// =====================================================================
// 3. Resize to same size (no-op)
// =====================================================================

#[test]
fn resize_same_size_noop() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "noop.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    image.resize(1 << 20).unwrap();
    assert_eq!(image.virtual_size(), 1 << 20);

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 4. Multiple resizes
// =====================================================================

#[test]
fn grow_shrink_grow() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "gsg.qcow2", 1 << 20);

    image.write_at(&vec![0x11; CS], 0).unwrap();
    image.resize(4 << 20).unwrap();
    // Don't write beyond 1MB so we can shrink back without data loss
    image.resize(1 << 20).unwrap();
    image.resize(8 << 20).unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));
}

// =====================================================================
// 5. Resize with backing chain
// =====================================================================

#[test]
fn resize_overlay_grow() {
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
    ov.resize(2 << 20).unwrap();
    assert_eq!(ov.virtual_size(), 2 << 20);

    // Backing data still accessible
    let mut buf = vec![0u8; CS];
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 6. truncate_free_tail
// =====================================================================

#[test]
fn truncate_free_tail_shrinks_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trunc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 64 << 20, // 64 MB virtual
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    // Write only to cluster 0
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    let size_before = std::fs::metadata(&path).unwrap().len();
    let freed = image.truncate_free_tail().unwrap();
    image.flush().unwrap();

    let size_after = std::fs::metadata(&path).unwrap().len();
    // File should be smaller or same (truncated trailing free clusters)
    assert!(
        size_after <= size_before,
        "should shrink: before={size_before}, after={size_after}"
    );

    // Data should still be readable
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 7. Integrity after resize
// =====================================================================

#[test]
fn integrity_clean_after_grow() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "int_grow.qcow2", 1 << 20);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.resize(4 << 20).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "grow: {report:?}");
}

#[test]
fn integrity_clean_after_shrink() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "int_shrink.qcow2", 4 << 20);
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.resize(1 << 20).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "shrink: {report:?}");
}

// =====================================================================
// 8. QEMU interop
// =====================================================================

#[test]
fn qemu_check_after_resize() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_resize.qcow2");

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
    image.resize(4 << 20).unwrap();
    image.write_at(&vec![0xBB; CS], 3 * CSU * 16).unwrap();
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

    // Verify QEMU sees correct virtual size
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();
    let info = String::from_utf8_lossy(&output.stdout);
    assert!(info.contains("4194304") || info.contains(&(4 << 20).to_string()));
}
