//! Detailed persistent dirty bitmap tests.
//!
//! Tests bitmap lifecycle, dirty tracking, multiple bitmaps, persistence
//! across reopen, resize interaction, and QEMU interop.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};

const CS: usize = 65536;
const CSU: u64 = CS as u64;

fn create_file(dir: &tempfile::TempDir, name: &str, vs: u64) -> Qcow2Image {
    Qcow2Image::create(
        dir.path().join(name),
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
// 1. Basic bitmap lifecycle
// =====================================================================

#[test]
fn create_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "bm.qcow2", 1 << 20);
    image.bitmap_create("dirty", None, false).unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "dirty");
}

#[test]
fn delete_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "bm_del.qcow2", 1 << 20);
    image.bitmap_create("dirty", None, false).unwrap();
    image.bitmap_delete("dirty").unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert!(bitmaps.is_empty());
}

#[test]
fn create_multiple_bitmaps() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "multi_bm.qcow2", 1 << 20);
    image.bitmap_create("bm1", None, false).unwrap();
    image.bitmap_create("bm2", None, false).unwrap();
    image.bitmap_create("bm3", None, false).unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 3);
    let names: Vec<&str> = bitmaps.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"bm1"));
    assert!(names.contains(&"bm2"));
    assert!(names.contains(&"bm3"));
}

#[test]
fn duplicate_bitmap_name_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "dup_bm.qcow2", 1 << 20);
    image.bitmap_create("same", None, false).unwrap();
    let result = image.bitmap_create("same", None, false);
    assert!(result.is_err());
}

#[test]
fn delete_nonexistent_bitmap_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "no_bm.qcow2", 1 << 20);
    let result = image.bitmap_delete("doesnt_exist");
    assert!(result.is_err());
}

// =====================================================================
// 2. Dirty tracking
// =====================================================================

#[test]
fn set_and_get_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "dirty.qcow2", 1 << 20);
    image.bitmap_create("dirty", None, false).unwrap();

    image.bitmap_set_dirty("dirty", 0, CSU).unwrap();
    assert!(image.bitmap_get_dirty("dirty", 0).unwrap());
}

#[test]
fn unset_region_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "clean_region.qcow2", 4 * CSU);
    image.bitmap_create("dirty", None, false).unwrap();

    image.bitmap_set_dirty("dirty", 0, CSU).unwrap();

    // Cluster 1 not marked dirty
    assert!(!image.bitmap_get_dirty("dirty", CSU).unwrap());
}

#[test]
fn set_dirty_multiple_regions() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "multi_dirty.qcow2", 16 * CSU);
    image.bitmap_create("dirty", None, false).unwrap();

    image.bitmap_set_dirty("dirty", 0, CSU).unwrap();
    image.bitmap_set_dirty("dirty", 4 * CSU, 2 * CSU).unwrap();

    assert!(image.bitmap_get_dirty("dirty", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty", CSU).unwrap());
    assert!(image.bitmap_get_dirty("dirty", 4 * CSU).unwrap());
    assert!(image.bitmap_get_dirty("dirty", 5 * CSU).unwrap());
    assert!(!image.bitmap_get_dirty("dirty", 6 * CSU).unwrap());
}

#[test]
fn clear_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "clear.qcow2", 4 * CSU);
    image.bitmap_create("dirty", None, false).unwrap();

    image.bitmap_set_dirty("dirty", 0, 4 * CSU).unwrap();
    assert!(image.bitmap_get_dirty("dirty", 0).unwrap());

    image.bitmap_clear("dirty").unwrap();
    assert!(!image.bitmap_get_dirty("dirty", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty", CSU).unwrap());
}

// =====================================================================
// 3. Multiple independent bitmaps
// =====================================================================

#[test]
fn independent_bitmaps_dont_interfere() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "indep.qcow2", 4 * CSU);
    image.bitmap_create("bm1", None, false).unwrap();
    image.bitmap_create("bm2", None, false).unwrap();

    image.bitmap_set_dirty("bm1", 0, CSU).unwrap();
    image.bitmap_set_dirty("bm2", CSU, CSU).unwrap();

    assert!(image.bitmap_get_dirty("bm1", 0).unwrap());
    assert!(!image.bitmap_get_dirty("bm1", CSU).unwrap());
    assert!(!image.bitmap_get_dirty("bm2", 0).unwrap());
    assert!(image.bitmap_get_dirty("bm2", CSU).unwrap());
}

// =====================================================================
// 4. Persistence across reopen
// =====================================================================

#[test]
fn bitmap_persists_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("persist.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 4 * CSU,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.bitmap_create("dirty", None, false).unwrap();
        image.bitmap_set_dirty("dirty", 0, CSU).unwrap();
        image.bitmap_set_dirty("dirty", 2 * CSU, CSU).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);
    assert_eq!(bitmaps[0].name, "dirty");

    assert!(image.bitmap_get_dirty("dirty", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty", CSU).unwrap());
    assert!(image.bitmap_get_dirty("dirty", 2 * CSU).unwrap());
}

// =====================================================================
// 5. Auto-tracking
// =====================================================================

#[test]
fn auto_tracking_marks_written_regions() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "auto.qcow2", 4 * CSU);
    image.bitmap_create("dirty", None, true).unwrap();
    image.bitmap_enable_tracking("dirty").unwrap();

    // Write to cluster 0 — should auto-mark dirty
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    assert!(image.bitmap_get_dirty("dirty", 0).unwrap());
    assert!(!image.bitmap_get_dirty("dirty", CSU).unwrap());
}

// =====================================================================
// 6. Bitmap granularity
// =====================================================================

#[test]
fn custom_granularity_bitmap() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "gran.qcow2", 4 * CSU);
    // granularity_bits = 16 means 64KB granularity (same as cluster)
    image.bitmap_create("dirty", Some(16), false).unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps[0].granularity_bits, 16);
    assert_eq!(bitmaps[0].granularity, 65536);
}

// =====================================================================
// 7. Bitmap info
// =====================================================================

#[test]
fn bitmap_info_correct() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "info.qcow2", 1 << 20);
    image.bitmap_create("test_bm", Some(16), true).unwrap();

    let bitmaps = image.bitmap_list().unwrap();
    assert_eq!(bitmaps.len(), 1);
    let bm = &bitmaps[0];
    assert_eq!(bm.name, "test_bm");
    assert_eq!(bm.granularity_bits, 16);
    assert!(bm.auto);
}

// =====================================================================
// 8. Integrity with bitmaps
// =====================================================================

#[test]
fn integrity_clean_with_bitmaps() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_file(&dir, "bm_int.qcow2", 4 * CSU);

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.bitmap_create("dirty", None, false).unwrap();
    image.bitmap_set_dirty("dirty", 0, CSU).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "integrity with bitmaps: {report:?}");
}

// =====================================================================
// 9. QEMU interop
// =====================================================================

#[test]
fn qemu_check_image_with_bitmaps() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_bm.qcow2");

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
    image.bitmap_create("dirty", None, false).unwrap();
    image.bitmap_set_dirty("dirty", 0, CSU).unwrap();
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
fn qemu_sees_our_bitmaps() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_see_bm.qcow2");

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
    image.bitmap_create("my_bitmap", None, false).unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let info = String::from_utf8_lossy(&output.stdout);
    assert!(
        info.contains("my_bitmap"),
        "qemu-img info should show our bitmap"
    );
}
