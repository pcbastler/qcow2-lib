//! Tests for commit with compressed clusters.
//!
//! Verifies that `commit()` correctly decompresses compressed overlay
//! clusters and writes them to the backing file.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use tempfile::TempDir;

const CLUSTER_SIZE: u64 = 65536; // 64 KB (default)

/// Helper: create a base image, return its path. The base has `base_pattern` in cluster 0.
fn create_base(dir: &std::path::Path, base_pattern: u8) -> std::path::PathBuf {
    let base_path = dir.join("base.qcow2");
    let mut base = Qcow2Image::create(
        &base_path,
        CreateOptions {
            virtual_size: 4 * CLUSTER_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
                refcount_order: None,
        },
    )
    .unwrap();
    base.write_at(&vec![base_pattern; CLUSTER_SIZE as usize], 0).unwrap();
    base.flush().unwrap();
    base_path
}

/// Helper: create overlay on disk, write data, flush, close, then reopen RW
/// so that backing_chain is resolved (needed for commit).
fn create_overlay_with_data(
    dir: &std::path::Path,
    base_path: &std::path::Path,
    writes: &[(u64, Vec<u8>)],
    use_compressed: bool,
) -> (Qcow2Image, std::path::PathBuf) {
    let overlay_path = dir.join("overlay.qcow2");
    {
        let mut overlay =
            Qcow2Image::create_overlay(&overlay_path, base_path, 4 * CLUSTER_SIZE).unwrap();
        for (offset, data) in writes {
            if use_compressed && data.len() == CLUSTER_SIZE as usize && *offset % CLUSTER_SIZE == 0
            {
                overlay.write_cluster_maybe_compressed(data, *offset).unwrap();
            } else {
                overlay.write_at(data, *offset).unwrap();
            }
        }
        overlay.flush().unwrap();
    }
    // Reopen so backing_chain is resolved
    let overlay = Qcow2Image::open_rw(&overlay_path).unwrap();
    (overlay, overlay_path)
}

#[test]
fn commit_deflate_compressed_to_backing() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0xAA);

    let data = vec![0x55; CLUSTER_SIZE as usize];
    let (mut overlay, _) =
        create_overlay_with_data(dir.path(), &base_path, &[(CLUSTER_SIZE, data)], true);

    overlay.commit().unwrap();

    let mut base = Qcow2Image::open_rw(&base_path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    base.read_at(&mut buf, CLUSTER_SIZE).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x55),
        "committed data should be in backing"
    );
}

#[test]
fn commit_mixed_compressed_uncompressed() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0xAA);
    let overlay_path = dir.path().join("overlay.qcow2");

    {
        let mut overlay =
            Qcow2Image::create_overlay(&overlay_path, &base_path, 4 * CLUSTER_SIZE).unwrap();
        // Compressed write
        overlay
            .write_cluster_maybe_compressed(&vec![0x11; CLUSTER_SIZE as usize], CLUSTER_SIZE)
            .unwrap();
        // Uncompressed write
        overlay
            .write_at(&vec![0x22; CLUSTER_SIZE as usize], 2 * CLUSTER_SIZE)
            .unwrap();
        overlay.flush().unwrap();
    }

    let mut overlay = Qcow2Image::open_rw(&overlay_path).unwrap();
    overlay.commit().unwrap();

    let mut base = Qcow2Image::open_rw(&base_path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];

    base.read_at(&mut buf, CLUSTER_SIZE).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x11),
        "compressed cluster committed"
    );

    base.read_at(&mut buf, 2 * CLUSTER_SIZE).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x22),
        "uncompressed cluster committed"
    );
}

#[test]
fn commit_preserves_data_integrity() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0x00);

    let mut pattern = vec![0u8; CLUSTER_SIZE as usize];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let (mut overlay, _) =
        create_overlay_with_data(dir.path(), &base_path, &[(0, pattern.clone())], true);
    overlay.commit().unwrap();

    let mut base = Qcow2Image::open_rw(&base_path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    base.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, pattern, "pattern integrity after commit");
}

#[test]
fn commit_partial_overlay() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0xBB);

    let data = vec![0xCC; CLUSTER_SIZE as usize];
    let (mut overlay, _) =
        create_overlay_with_data(dir.path(), &base_path, &[(2 * CLUSTER_SIZE, data)], false);
    overlay.commit().unwrap();

    let mut base = Qcow2Image::open_rw(&base_path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];

    base.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "untouched cluster preserved"
    );

    base.read_at(&mut buf, 2 * CLUSTER_SIZE).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xCC),
        "committed cluster present"
    );
}

#[test]
fn backing_readable_after_commit() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0x10);

    let data = vec![0x20; CLUSTER_SIZE as usize];
    let (mut overlay, _) =
        create_overlay_with_data(dir.path(), &base_path, &[(CLUSTER_SIZE, data)], false);
    overlay.commit().unwrap();
    drop(overlay);

    let mut base = Qcow2Image::open(&base_path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    base.read_at(&mut buf, CLUSTER_SIZE).unwrap();
    assert!(buf.iter().all(|&b| b == 0x20));
}

#[test]
fn commit_all_clusters() {
    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0x00);
    let overlay_path = dir.path().join("overlay.qcow2");

    {
        let mut overlay =
            Qcow2Image::create_overlay(&overlay_path, &base_path, 4 * CLUSTER_SIZE).unwrap();
        for i in 0..4u8 {
            let data = vec![i + 1; CLUSTER_SIZE as usize];
            overlay
                .write_at(&data, i as u64 * CLUSTER_SIZE)
                .unwrap();
        }
        overlay.flush().unwrap();
    }

    let mut overlay = Qcow2Image::open_rw(&overlay_path).unwrap();
    overlay.commit().unwrap();

    let mut base = Qcow2Image::open_rw(&base_path).unwrap();
    for i in 0..4u8 {
        let mut buf = vec![0u8; CLUSTER_SIZE as usize];
        base.read_at(&mut buf, i as u64 * CLUSTER_SIZE).unwrap();
        assert!(
            buf.iter().all(|&b| b == i + 1),
            "cluster {i} should have pattern {}",
            i + 1
        );
    }
}

#[test]
fn qemu_check_backing_after_commit() {
    if !common::has_qemu_img() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let base_path = create_base(dir.path(), 0xAA);

    let data = vec![0x55; CLUSTER_SIZE as usize];
    let (mut overlay, _) =
        create_overlay_with_data(dir.path(), &base_path, &[(CLUSTER_SIZE, data)], false);
    overlay.commit().unwrap();
    drop(overlay);

    let base_dir = TempDir::new().unwrap();
    // Copy base to a new temp dir so TestImage can own it
    let check_path = base_dir.path().join("base.qcow2");
    std::fs::copy(&base_path, &check_path).unwrap();
    let ti = common::TestImage::wrap(check_path, base_dir);
    assert!(
        ti.qemu_check(),
        "qemu-img check should pass on backing after commit"
    );
}
