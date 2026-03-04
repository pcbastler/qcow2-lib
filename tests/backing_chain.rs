//! Integration tests: backing chain, commit, and rebase operations
//! with qemu-img cross-validation.

mod common;

use std::path::Path;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::error::Error;

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

/// Helper: get qemu-img info output as string.
fn qemu_img_info(path: &Path) -> String {
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img info");

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Helper: create a base image with data.
fn create_base(dir: &Path, name: &str, size: u64, data: &[(u64, &[u8])]) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: size,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
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

/// Helper: create an overlay with data.
fn create_overlay_with_data(
    dir: &Path,
    name: &str,
    backing: &Path,
    size: u64,
    data: &[(u64, &[u8])],
) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create_overlay(&path, backing, size).unwrap();

    for &(offset, buf) in data {
        image.write_at(buf, offset).unwrap();
    }
    image.flush().unwrap();
    drop(image);
    path
}

// ===== Deep chain tests =====

#[test]
fn three_level_chain_read_through() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    // base: 0xAA at offset 0
    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    // mid: 0xBB at offset cluster
    let mid = create_overlay_with_data(
        dir.path(),
        "mid.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );

    // top: 0xCC at offset 2*cluster
    let top = create_overlay_with_data(
        dir.path(),
        "top.qcow2",
        &mid,
        size,
        &[(2 * cluster, &[0xCC; 4096])],
    );

    // Read from top should see all three layers
    let mut image = Qcow2Image::open(&top).unwrap();
    let mut buf = vec![0u8; 4096];

    // Data from base
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "should read base data");

    // Data from mid
    image.read_at(&mut buf, cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "should read mid data");

    // Data from top
    image.read_at(&mut buf, 2 * cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC), "should read top data");

    // Unallocated area should be zeros
    image.read_at(&mut buf, 3 * cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "unallocated should be zeros");
}

#[test]
fn four_level_chain_with_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    let l1 = create_overlay_with_data(
        dir.path(),
        "l1.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );
    let l2 = create_overlay_with_data(
        dir.path(),
        "l2.qcow2",
        &l1,
        size,
        &[(2 * cluster, &[0xCC; 4096])],
    );
    let l3 = create_overlay_with_data(
        dir.path(),
        "l3.qcow2",
        &l2,
        size,
        &[(3 * cluster, &[0xDD; 4096])],
    );

    // All images should pass qemu-img check
    assert_qemu_check(&base);
    assert_qemu_check(&l1);
    assert_qemu_check(&l2);
    assert_qemu_check(&l3);
}

#[test]
fn backing_chain_metadata_depth() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[]);
    let mid = create_overlay_with_data(dir.path(), "mid.qcow2", &base, size, &[]);
    let top = create_overlay_with_data(dir.path(), "top.qcow2", &mid, size, &[]);

    let image = Qcow2Image::open(&top).unwrap();
    let chain = image.backing_chain().expect("should have backing chain");
    assert_eq!(chain.depth(), 2, "top → mid → base = depth 2");
}

#[test]
fn qemu_io_cross_validation_deep_chain() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(
        dir.path(),
        "base.qcow2",
        size,
        &[(0, &[0xAA; 4096])],
    );
    let mid = create_overlay_with_data(
        dir.path(),
        "mid.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );
    let top = create_overlay_with_data(
        dir.path(),
        "top.qcow2",
        &mid,
        size,
        &[(2 * cluster, &[0xCC; 4096])],
    );

    // Read with qemu-io to cross-validate
    let check_cmd = "read -P 0xAA 0 4096".to_string();
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", &check_cmd])
        .arg(&top)
        .output()
        .expect("failed to run qemu-io");
    assert!(
        output.status.success(),
        "qemu-io should read base data through chain: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ===== Overlay write tests =====

#[test]
fn overlay_partial_write_cow() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    // Base with full cluster of 0xAA
    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 65536])]);

    // Overlay: write only first 512 bytes with 0xBB (COW should preserve rest)
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0xBB; 512])],
    );

    let mut image = Qcow2Image::open(&overlay).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();

    // First 512 bytes should be 0xBB
    assert!(
        buf[..512].iter().all(|&b| b == 0xBB),
        "first 512 bytes should be 0xBB"
    );
    // Rest should be 0xAA (COW from backing)
    assert!(
        buf[512..].iter().all(|&b| b == 0xAA),
        "remaining bytes should be 0xAA from backing"
    );
}

#[test]
fn overlay_full_cluster_write() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 65536])]);

    // Full cluster write — no COW needed
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0xBB; 65536])],
    );

    let mut image = Qcow2Image::open(&overlay).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
    assert_qemu_check(&overlay);
}

#[test]
fn overlay_many_writes_with_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    let overlay_path = dir.path().join("overlay.qcow2");
    let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();

    // Write to 10 different clusters
    for i in 0..10u64 {
        let pattern = vec![(i as u8).wrapping_add(0x10); 4096];
        image.write_at(&pattern, i * cluster).unwrap();
    }

    image.snapshot_create("snap1").unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&overlay_path);
}

// ===== Commit tests =====

#[test]
fn commit_merges_data_into_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    // Base with 0xAA at offset 0
    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    // Overlay with 0xBB at offset cluster
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );

    // Commit overlay into backing
    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.commit().unwrap();
    drop(image);

    // Backing should now have both pieces of data
    let mut backing_image = Qcow2Image::open(&base).unwrap();

    let mut buf = vec![0u8; 4096];
    backing_image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xAA),
        "original base data preserved"
    );

    backing_image.read_at(&mut buf, cluster).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "overlay data merged into backing"
    );
}

#[test]
fn commit_backing_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(65536, &[0xBB; 4096])],
    );

    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.commit().unwrap();
    drop(image);

    assert_qemu_check(&base);
}

#[test]
fn commit_preserves_existing_backing_data() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    // Base has data at clusters 0, 1, 2
    let base = create_base(
        dir.path(),
        "base.qcow2",
        size,
        &[
            (0, &[0xAA; 4096]),
            (cluster, &[0xBB; 4096]),
            (2 * cluster, &[0xCC; 4096]),
        ],
    );

    // Overlay only writes to cluster 1
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(cluster, &[0xDD; 4096])],
    );

    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.commit().unwrap();
    drop(image);

    // Backing: cluster 0 and 2 should be unchanged, cluster 1 updated
    let mut backing = Qcow2Image::open(&base).unwrap();
    let mut buf = vec![0u8; 4096];

    backing.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "cluster 0 preserved");

    backing.read_at(&mut buf, cluster).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xDD),
        "cluster 1 updated by commit"
    );

    backing.read_at(&mut buf, 2 * cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC), "cluster 2 preserved");
}

#[test]
fn commit_without_backing_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("standalone.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
        },
    )
    .unwrap();

    match image.commit() {
        Err(qcow2_lib::error::Error::CommitNoBacking) => {}
        other => panic!("expected CommitNoBacking, got {other:?}"),
    }
}

#[test]
fn commit_then_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    // Base → overlay → commit → verify backing is standalone readable
    let base = create_base(dir.path(), "base.qcow2", size, &[]);
    let pattern = vec![0xEEu8; 65536];
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &pattern)],
    );

    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.commit().unwrap();
    drop(image);

    // Read from backing directly (no overlay)
    let mut backing = Qcow2Image::open(&base).unwrap();
    let mut buf = vec![0u8; 65536];
    backing.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, pattern, "data survives commit roundtrip");
}

// ===== Rebase tests =====

#[test]
fn rebase_changes_backing_reference() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base1 = create_base(dir.path(), "base1.qcow2", size, &[(0, &[0xAA; 4096])]);
    let base2 = create_base(dir.path(), "base2.qcow2", size, &[(0, &[0xBB; 4096])]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base1,
        size,
        &[],
    );

    // Rebase to base2
    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.rebase_unsafe(Some(&base2)).unwrap();
    image.flush().unwrap();
    drop(image);

    // qemu-img info should show new backing
    let info = qemu_img_info(&overlay);
    assert!(
        info.contains("base2.qcow2"),
        "info should mention new backing: {info}"
    );
    assert_qemu_check(&overlay);
}

#[test]
fn rebase_to_none_removes_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    // Overlay with its own data at offset 0
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0xBB; 4096])],
    );

    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.rebase_unsafe(None).unwrap();
    image.flush().unwrap();
    drop(image);

    // qemu-img info should not show backing
    let info = qemu_img_info(&overlay);
    assert!(
        !info.contains("backing file"),
        "should have no backing file: {info}"
    );
    assert_qemu_check(&overlay);
}

#[test]
fn read_after_rebase_shows_new_backing_data() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base1 = create_base(dir.path(), "base1.qcow2", size, &[(0, &[0xAA; 4096])]);
    let base2 = create_base(dir.path(), "base2.qcow2", size, &[(0, &[0xBB; 4096])]);

    // Overlay has no own data at offset 0 — reads come from backing
    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let _image = Qcow2Image::create_overlay(&overlay_path, &base1, size).unwrap();
    }

    // Initially reads from base1
    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "should read from base1");
    }

    // Rebase to base2
    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.rebase_unsafe(Some(&base2)).unwrap();
        image.flush().unwrap();
    }

    // Now reads from base2
    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "should read from base2");
    }
}

// ===== Round-trip test =====

#[test]
fn full_roundtrip_base_overlay_commit_verify() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    // Create base with some data
    let base = create_base(
        dir.path(),
        "base.qcow2",
        size,
        &[(0, &[0xAA; 4096])],
    );

    // Create overlay, write different data
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[
            (cluster, &[0xBB; 4096]),
            (2 * cluster, &[0xCC; 4096]),
        ],
    );

    // Verify overlay reads
    {
        let mut image = Qcow2Image::open(&overlay).unwrap();
        let mut buf = vec![0u8; 4096];

        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        image.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        image.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));
    }

    // Commit
    {
        let mut image = Qcow2Image::open_rw(&overlay).unwrap();
        image.commit().unwrap();
    }

    // Verify backing is now standalone with all data
    {
        let mut backing = Qcow2Image::open(&base).unwrap();
        let mut buf = vec![0u8; 4096];

        backing.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "base data intact");

        backing.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "overlay data committed");

        backing.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC), "overlay data committed");
    }

    assert_qemu_check(&base);
}

// ================================================================
// Edge cases, corner cases, and adversarial scenarios
// ================================================================

// ---- Empty overlay (no writes at all) ----

#[test]
fn empty_overlay_reads_entirely_from_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(
        dir.path(),
        "base.qcow2",
        size,
        &[
            (0, &[0xAA; 4096]),
            (cluster, &[0xBB; 4096]),
        ],
    );

    // Overlay with zero writes
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[],
    );

    let mut image = Qcow2Image::open(&overlay).unwrap();
    let mut buf = vec![0u8; 4096];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "should read through to base");

    image.read_at(&mut buf, cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "should read through to base");

    // Unallocated in both → zeros
    image.read_at(&mut buf, 2 * cluster).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "unallocated in both = zeros");
}

#[test]
fn commit_empty_overlay_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[],
    );

    // Read virtual content of backing before commit
    let mut before = vec![0u8; size as usize];
    {
        let mut image = Qcow2Image::open(&base).unwrap();
        image.read_at(&mut before, 0).unwrap();
    }

    let mut image = Qcow2Image::open_rw(&overlay).unwrap();
    image.commit().unwrap();
    drop(image);

    // Virtual content of backing should be identical after empty commit
    let mut after = vec![0u8; size as usize];
    {
        let mut image = Qcow2Image::open(&base).unwrap();
        image.read_at(&mut after, 0).unwrap();
    }
    assert_eq!(before, after, "empty overlay commit should not change backing content");
}

// ---- Read-only error paths ----

#[test]
fn rebase_on_readonly_image_fails() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0xAA; 4096])],
    );

    // Open read-only (not open_rw)
    let mut image = Qcow2Image::open(&overlay).unwrap();
    match image.rebase_unsafe(None) {
        Err(Error::ReadOnly) => {}
        other => panic!("expected ReadOnly, got {other:?}"),
    }
}

// ---- Deep chain commit (3-level) ----

#[test]
fn commit_on_three_level_chain() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    // base: 0xAA at cluster 0
    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    // mid: 0xBB at cluster 1
    let mid = create_overlay_with_data(
        dir.path(),
        "mid.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );

    // top: 0xCC at cluster 2
    let top = create_overlay_with_data(
        dir.path(),
        "top.qcow2",
        &mid,
        size,
        &[(2 * cluster, &[0xCC; 4096])],
    );

    // Commit top → mid (should merge 0xCC into mid)
    {
        let mut image = Qcow2Image::open_rw(&top).unwrap();
        image.commit().unwrap();
    }

    // Mid should now have 0xBB at cluster 1 AND 0xCC at cluster 2
    {
        let mut mid_image = Qcow2Image::open(&mid).unwrap();
        let mut buf = vec![0u8; 4096];

        // Base data readable through mid's backing
        mid_image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "base data via mid");

        // Mid's own data
        mid_image.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "mid's own data");

        // Committed from top
        mid_image.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC), "top data committed to mid");
    }

    assert_qemu_check(&mid);
    assert_qemu_check(&base);
}

// ---- Zero cluster handling ----

#[test]
fn overlay_zero_overwrites_backing_data() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    // Base has non-zero data
    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xFF; 65536])]);

    // Overlay explicitly writes zeros
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0x00; 65536])],
    );

    // Should read as zeros, not the 0xFF from backing
    let mut image = Qcow2Image::open(&overlay).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0),
        "overlay zeros should mask backing data"
    );

    // Commit zeros to backing
    drop(image);
    {
        let mut rw = Qcow2Image::open_rw(&overlay).unwrap();
        rw.commit().unwrap();
    }

    // Backing should now have zeros too
    let mut backing = Qcow2Image::open(&base).unwrap();
    backing.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0),
        "committed zeros should overwrite backing"
    );
    assert_qemu_check(&base);
}

// ---- Bit-for-bit commit verification ----

#[test]
fn commit_bit_for_bit_identical() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0x11; 4096])]);

    // Write diverse patterns across multiple clusters
    let mut patterns: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 1..8u64 {
        let mut pattern = vec![0u8; 4096];
        for (j, byte) in pattern.iter_mut().enumerate() {
            *byte = ((i * 31 + j as u64 * 7) & 0xFF) as u8;
        }
        patterns.push((i * cluster, pattern));
    }

    let overlay_data: Vec<(u64, &[u8])> = patterns
        .iter()
        .map(|(off, data)| (*off, data.as_slice()))
        .collect();
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &overlay_data,
    );

    // Read ALL data from overlay before commit
    let mut before_commit = vec![0u8; size as usize];
    {
        let mut image = Qcow2Image::open(&overlay).unwrap();
        for off in (0..size).step_by(cluster as usize) {
            let end = (off + cluster).min(size);
            let len = (end - off) as usize;
            image
                .read_at(&mut before_commit[off as usize..off as usize + len], off)
                .unwrap();
        }
    }

    // Commit
    {
        let mut image = Qcow2Image::open_rw(&overlay).unwrap();
        image.commit().unwrap();
    }

    // Read ALL data from backing after commit
    let mut after_commit = vec![0u8; size as usize];
    {
        let mut backing = Qcow2Image::open(&base).unwrap();
        for off in (0..size).step_by(cluster as usize) {
            let end = (off + cluster).min(size);
            let len = (end - off) as usize;
            backing
                .read_at(&mut after_commit[off as usize..off as usize + len], off)
                .unwrap();
        }
    }

    // Bit-for-bit comparison
    assert_eq!(
        before_commit, after_commit,
        "backing after commit must be bit-for-bit identical to overlay reads"
    );
}

// ---- Integrity check after commit ----

#[test]
fn integrity_clean_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[
            (cluster, &[0xBB; 4096]),
            (2 * cluster, &[0xCC; 65536]),
        ],
    );

    {
        let mut image = Qcow2Image::open_rw(&overlay).unwrap();
        image.commit().unwrap();
    }

    // Library integrity check on backing
    let image = Qcow2Image::open(&base).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "backing should be clean after commit: mismatches={:?}, leaks={:?}",
        report.mismatches,
        report.leaks
    );

    assert_qemu_check(&base);
}

// ---- Snapshot + backing chain interactions ----

#[test]
fn snapshot_on_overlay_then_commit() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0xBB; 4096], cluster).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.write_at(&[0xCC; 4096], 2 * cluster).unwrap();
        image.flush().unwrap();
    }

    assert_qemu_check(&overlay_path);

    // Commit (should merge current state, not snapshot state)
    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.commit().unwrap();
    }

    // Backing should have the latest writes
    {
        let mut backing = Qcow2Image::open(&base).unwrap();
        let mut buf = vec![0u8; 4096];

        backing.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        backing.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        backing.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));
    }

    assert_qemu_check(&base);
}

// ---- Multiple overlays on same backing ----

#[test]
fn two_overlays_on_same_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    let ov1 = create_overlay_with_data(
        dir.path(),
        "ov1.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );
    let ov2 = create_overlay_with_data(
        dir.path(),
        "ov2.qcow2",
        &base,
        size,
        &[(cluster, &[0xCC; 4096])],
    );

    // Both should see base data at offset 0
    {
        let mut img1 = Qcow2Image::open(&ov1).unwrap();
        let mut img2 = Qcow2Image::open(&ov2).unwrap();
        let mut buf = vec![0u8; 4096];

        img1.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        img2.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        // But different data at cluster 1
        img1.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        img2.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));
    }

    assert_qemu_check(&ov1);
    assert_qemu_check(&ov2);
}

#[test]
fn commit_one_overlay_does_not_corrupt_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    let ov1 = create_overlay_with_data(
        dir.path(),
        "ov1.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );
    let ov2 = create_overlay_with_data(
        dir.path(),
        "ov2.qcow2",
        &base,
        size,
        &[(2 * cluster, &[0xCC; 4096])],
    );

    // Commit ov1 into backing
    {
        let mut image = Qcow2Image::open_rw(&ov1).unwrap();
        image.commit().unwrap();
    }

    // ov2 should still work
    {
        let mut img2 = Qcow2Image::open(&ov2).unwrap();
        let mut buf = vec![0u8; 4096];

        img2.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        // Data committed from ov1 is now visible through ov2's backing
        img2.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "ov1 data visible via backing");

        img2.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));
    }

    assert_qemu_check(&ov2);
    assert_qemu_check(&base);
}

// ---- Rebase edge cases ----

#[test]
fn rebase_then_rebase_back() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base1 = create_base(dir.path(), "base1.qcow2", size, &[(0, &[0xAA; 4096])]);
    let base2 = create_base(dir.path(), "base2.qcow2", size, &[(0, &[0xBB; 4096])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let _img = Qcow2Image::create_overlay(&overlay_path, &base1, size).unwrap();
    }

    // Rebase to base2
    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.rebase_unsafe(Some(&base2)).unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    // Rebase back to base1
    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.rebase_unsafe(Some(&base1)).unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    assert_qemu_check(&overlay_path);
}

#[test]
fn rebase_to_none_preserves_allocated_data() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 4096])],
    );

    // Remove backing
    {
        let mut image = Qcow2Image::open_rw(&overlay).unwrap();
        image.rebase_unsafe(None).unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay).unwrap();
        let mut buf = vec![0u8; 4096];

        // cluster 1: overlay's own data
        image.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "own data preserved");

        // cluster 0: was from backing, now reads as zeros
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "no backing = zeros");
    }

    assert_qemu_check(&overlay);
}

// ---- COW partial write at various positions ----

#[test]
fn cow_partial_write_end_of_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 65536])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0xBB; 512], 65536 - 512).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();

    assert!(buf[..65024].iter().all(|&b| b == 0xAA), "beginning = 0xAA");
    assert!(buf[65024..].iter().all(|&b| b == 0xBB), "end = 0xBB");
}

#[test]
fn cow_partial_write_middle_of_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 65536])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0xCC; 1024], 32768).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();

    assert!(buf[..32768].iter().all(|&b| b == 0xAA), "before = 0xAA");
    assert!(buf[32768..33792].iter().all(|&b| b == 0xCC), "middle = 0xCC");
    assert!(buf[33792..].iter().all(|&b| b == 0xAA), "after = 0xAA");
}

// ---- Cross-cluster write spanning backing boundary ----

#[test]
fn write_spanning_two_clusters_with_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(
        dir.path(),
        "base.qcow2",
        size,
        &[(0, &[0xAA; 65536]), (cluster, &[0xBB; 65536])],
    );

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0xDD; 8192], cluster - 4096).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();

    let mut buf0 = vec![0u8; 65536];
    image.read_at(&mut buf0, 0).unwrap();
    assert!(buf0[..61440].iter().all(|&b| b == 0xAA));
    assert!(buf0[61440..].iter().all(|&b| b == 0xDD));

    let mut buf1 = vec![0u8; 65536];
    image.read_at(&mut buf1, cluster).unwrap();
    assert!(buf1[..4096].iter().all(|&b| b == 0xDD));
    assert!(buf1[4096..].iter().all(|&b| b == 0xBB));

    assert_qemu_check(&overlay_path);
}

// ---- Adversarial: overlay overwrites same cluster many times ----

#[test]
fn overlay_overwrite_same_cluster_many_times() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 4096])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        for i in 0..50u8 {
            image.write_at(&[i; 4096], 0).unwrap();
        }
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 49), "should see last write (49)");

    assert_qemu_check(&overlay_path);

    // Commit and verify
    drop(image);
    {
        let mut rw = Qcow2Image::open_rw(&overlay_path).unwrap();
        rw.commit().unwrap();
    }

    let mut backing = Qcow2Image::open(&base).unwrap();
    backing.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 49), "committed last write");
}

// ---- Adversarial: very small write (1 byte) ----

#[test]
fn single_byte_write_on_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xFF; 65536])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0x42], 12345).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();

    for (i, &b) in buf.iter().enumerate() {
        if i == 12345 {
            assert_eq!(b, 0x42, "byte 12345 should be 0x42");
        } else {
            assert_eq!(b, 0xFF, "byte {i} should be 0xFF");
        }
    }
}

// ---- Stress: commit loop ----

#[test]
fn stress_overlay_write_commit_verify_loop() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[]);

    for round in 0..5u8 {
        let overlay_path = dir.path().join(format!("overlay_{round}.qcow2"));
        {
            let mut image =
                Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
            let pattern = vec![round.wrapping_add(0x10); 4096];
            image.write_at(&pattern, round as u64 * cluster).unwrap();
            image.flush().unwrap();
        }

        {
            let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
            image.commit().unwrap();
        }

        {
            let mut backing = Qcow2Image::open(&base).unwrap();
            for r in 0..=round {
                let mut buf = vec![0u8; 4096];
                backing.read_at(&mut buf, r as u64 * cluster).unwrap();
                assert!(
                    buf.iter().all(|&b| b == r.wrapping_add(0x10)),
                    "round {r} data should be in backing after round {round} commit"
                );
            }
        }

        assert_qemu_check(&base);
    }

    let image = Qcow2Image::open(&base).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "backing clean after 5 commit rounds: {:?} {:?}",
        report.mismatches,
        report.leaks
    );
}

// ---- Overlay larger than backing ----

#[test]
fn commit_overlay_larger_than_backing() {
    let dir = tempfile::tempdir().unwrap();

    let base = create_base(
        dir.path(),
        "base.qcow2",
        1024 * 1024,
        &[(0, &[0xAA; 4096])],
    );

    // Overlay: 4 MB virtual_size > backing 1 MB
    // Partial writes trigger COW which must handle backing being smaller.
    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image =
            Qcow2Image::create_overlay(&overlay_path, &base, 4 * 1024 * 1024).unwrap();
        image.write_at(&[0xBB; 4096], 0).unwrap();
        image.write_at(&[0xCC; 4096], 2 * 1024 * 1024).unwrap();
        image.flush().unwrap();
    }

    // Commit resizes backing to match overlay's virtual size (like qemu-img commit)
    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.commit().unwrap();
    }

    {
        let mut backing = Qcow2Image::open(&base).unwrap();
        assert_eq!(backing.virtual_size(), 4 * 1024 * 1024, "backing must be resized");

        let mut buf = vec![0u8; 4096];
        backing.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "committed within original range");

        let mut buf2 = vec![0u8; 4096];
        backing.read_at(&mut buf2, 2 * 1024 * 1024).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xCC), "committed beyond original backing size");
    }

    assert_qemu_check(&base);
}

// ---- Overlay larger than backing: COW boundary tests ----

#[test]
fn partial_write_beyond_backing_size() {
    let dir = tempfile::tempdir().unwrap();
    let base = create_base(dir.path(), "base.qcow2", 1024 * 1024, &[]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image =
            Qcow2Image::create_overlay(&overlay_path, &base, 4 * 1024 * 1024).unwrap();
        // Partial write at 2MB — beyond backing's 1MB, triggers COW
        image.write_at(&[0xDD; 4096], 2 * 1024 * 1024).unwrap();
        image.flush().unwrap();
    }

    // Read back: written bytes present, rest of cluster is zeros
    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 2 * 1024 * 1024).unwrap();
        assert!(buf.iter().all(|&b| b == 0xDD));

        // Bytes before the write within the same cluster should be zeros
        let mut before = vec![0xFFu8; 4096];
        image.read_at(&mut before, 2 * 1024 * 1024 - 4096).unwrap();
        assert!(before.iter().all(|&b| b == 0x00), "COW region beyond backing must be zeros");
    }

    assert_qemu_check(&overlay_path);
}

#[test]
fn read_unallocated_beyond_backing_size() {
    let dir = tempfile::tempdir().unwrap();
    let base = create_base(dir.path(), "base.qcow2", 1024 * 1024, &[(0, &[0xAA; 4096])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let _image =
            Qcow2Image::create_overlay(&overlay_path, &base, 4 * 1024 * 1024).unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();

        // Within backing range — backing data visible
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "backing data visible");

        // Beyond backing range — zeros
        let mut beyond = vec![0xFFu8; 4096];
        image.read_at(&mut beyond, 2 * 1024 * 1024).unwrap();
        assert!(beyond.iter().all(|&b| b == 0x00), "beyond backing must be zeros");
    }
}

#[test]
fn cow_at_backing_boundary() {
    // Backing is 1MB (= 16 clusters of 64KB). Write at offset that makes
    // the cluster straddle the backing boundary: cluster start at 960KB
    // (within backing), cluster end at 1024KB (= 1MB, at boundary).
    // The first 64KB of the cluster comes from backing, but since backing
    // is exactly 1MB = 16*64KB, the last cluster is fully within backing.
    //
    // Use a non-cluster-aligned backing size to create a true boundary overlap.
    // Backing = 1MB, cluster = 64KB. Place backing data at cluster 15 (offset 960KB).
    // Then create a 2MB overlay and do a partial write within the last backing cluster.
    let dir = tempfile::tempdir().unwrap();
    let cluster: u64 = 65536;

    // Base with data in last cluster (offset 15*64KB = 983040)
    let last_cluster_offset = 15 * cluster;
    let base = create_base(
        dir.path(),
        "base.qcow2",
        1024 * 1024,
        &[(last_cluster_offset, &[0xEE; 4096])],
    );

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image =
            Qcow2Image::create_overlay(&overlay_path, &base, 2 * 1024 * 1024).unwrap();
        // Partial write in the same last-backing cluster, at a different intra-offset
        image
            .write_at(&[0xFF; 4096], last_cluster_offset + 8192)
            .unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();

        // Original backing data at start of cluster preserved via COW
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, last_cluster_offset).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xEE),
            "COW must preserve backing data within same cluster"
        );

        // Our written data
        let mut written = vec![0u8; 4096];
        image
            .read_at(&mut written, last_cluster_offset + 8192)
            .unwrap();
        assert!(written.iter().all(|&b| b == 0xFF));

        // Beyond backing (offset 1MB) — unallocated, should be zeros
        let mut beyond = vec![0xAAu8; 4096];
        image.read_at(&mut beyond, 1024 * 1024).unwrap();
        assert!(
            beyond.iter().all(|&b| b == 0x00),
            "beyond backing boundary must be zeros"
        );
    }

    assert_qemu_check(&overlay_path);
}

// ---- Rebase with snapshots present ----

#[test]
fn rebase_overlay_with_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base1 = create_base(dir.path(), "base1.qcow2", size, &[(0, &[0xAA; 4096])]);
    let base2 = create_base(dir.path(), "base2.qcow2", size, &[(0, &[0xBB; 4096])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base1, size).unwrap();
        image.write_at(&[0xCC; 4096], cluster).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.write_at(&[0xDD; 4096], 2 * cluster).unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open_rw(&overlay_path).unwrap();
        image.rebase_unsafe(Some(&base2)).unwrap();
        image.flush().unwrap();
    }

    {
        let mut image = Qcow2Image::open(&overlay_path).unwrap();
        let mut buf = vec![0u8; 4096];

        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "reads from new backing");

        image.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC), "overlay data intact");

        image.read_at(&mut buf, 2 * cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xDD), "overlay data intact");

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 1, "snapshot preserved after rebase");
        assert_eq!(snaps[0].name, "snap1");
    }

    assert_qemu_check(&overlay_path);
}

// ---- Diamond: two overlays committed sequentially ----

#[test]
fn diamond_commit_two_overlays_into_same_backing() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;
    let cluster = 65536u64;

    let base = create_base(dir.path(), "base.qcow2", size, &[]);

    let ov_a = create_overlay_with_data(
        dir.path(),
        "ov_a.qcow2",
        &base,
        size,
        &[(0, &[0xAA; 65536])],
    );
    let ov_b = create_overlay_with_data(
        dir.path(),
        "ov_b.qcow2",
        &base,
        size,
        &[(cluster, &[0xBB; 65536])],
    );

    {
        let mut image = Qcow2Image::open_rw(&ov_a).unwrap();
        image.commit().unwrap();
    }
    {
        let mut image = Qcow2Image::open_rw(&ov_b).unwrap();
        image.commit().unwrap();
    }

    {
        let mut backing = Qcow2Image::open(&base).unwrap();
        let mut buf = vec![0u8; 65536];

        backing.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        backing.read_at(&mut buf, cluster).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    let image = Qcow2Image::open(&base).unwrap();
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
    assert_qemu_check(&base);
}

// ---- Conflicting commits: last writer wins ----

#[test]
fn conflicting_commits_last_writer_wins() {
    let dir = tempfile::tempdir().unwrap();
    let size = 4 * 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0x00; 4096])]);

    let ov_a = create_overlay_with_data(
        dir.path(),
        "ov_a.qcow2",
        &base,
        size,
        &[(0, &[0xAA; 65536])],
    );
    let ov_b = create_overlay_with_data(
        dir.path(),
        "ov_b.qcow2",
        &base,
        size,
        &[(0, &[0xBB; 65536])],
    );

    {
        let mut image = Qcow2Image::open_rw(&ov_a).unwrap();
        image.commit().unwrap();
    }
    {
        let mut image = Qcow2Image::open_rw(&ov_b).unwrap();
        image.commit().unwrap();
    }

    let mut backing = Qcow2Image::open(&base).unwrap();
    let mut buf = vec![0u8; 65536];
    backing.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "last commit wins");

    assert_qemu_check(&base);
}

// ---- Adversarial: rebase overlay to itself → loop on reopen ----

#[test]
fn rebase_overlay_to_itself_detects_loop_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let size = 1024 * 1024;

    let base = create_base(dir.path(), "base.qcow2", size, &[]);
    let overlay = create_overlay_with_data(
        dir.path(),
        "overlay.qcow2",
        &base,
        size,
        &[(0, &[0xAA; 4096])],
    );

    {
        let mut image = Qcow2Image::open_rw(&overlay).unwrap();
        image.rebase_unsafe(Some(&overlay)).unwrap();
        image.flush().unwrap();
    }

    // Re-opening should detect the self-referencing loop
    match Qcow2Image::open(&overlay) {
        Err(Error::BackingChainLoop { .. }) => {}
        Ok(_) => panic!("should have detected self-referencing loop"),
        Err(other) => panic!("expected BackingChainLoop, got {other:?}"),
    }
}

// ---- Boundary: write at last byte of virtual size ----

#[test]
fn write_at_last_byte_of_virtual_size() {
    let dir = tempfile::tempdir().unwrap();
    let size = 2 * 65536; // exactly 2 clusters

    let base = create_base(dir.path(), "base.qcow2", size, &[(0, &[0xAA; 65536])]);

    let overlay_path = dir.path().join("overlay.qcow2");
    {
        let mut image = Qcow2Image::create_overlay(&overlay_path, &base, size).unwrap();
        image.write_at(&[0xBB; 1], size - 1).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&overlay_path).unwrap();
    let mut buf = vec![0u8; 1];
    image.read_at(&mut buf, size - 1).unwrap();
    assert_eq!(buf[0], 0xBB);

    assert_qemu_check(&overlay_path);
}
