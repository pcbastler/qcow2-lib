//! Integration tests: snapshot and COW operations.
//!
//! Cross-validates our QCOW2 snapshot implementation against qemu-img check,
//! qemu-img snapshot, and qemu-io reads.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};

/// Helper: create, write, flush, and drop an image, returning the path.
fn create_image_with_data(dir: &std::path::Path, name: &str, data: &[(u64, &[u8])]) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
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

/// Helper: run `qemu-img check` and assert success.
fn assert_qemu_check(path: &std::path::Path) {
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

/// Helper: run `qemu-img snapshot -l` and return the output.
fn qemu_snapshot_list(path: &std::path::Path) -> String {
    let output = std::process::Command::new("qemu-img")
        .args(["snapshot", "-l"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img snapshot -l");

    String::from_utf8_lossy(&output.stdout).to_string()
}

// ---- qemu-img check after snapshot operations ----

#[test]
fn qemu_check_after_snapshot_create() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "snap.qcow2", &[(0, &[0xAA; 4096])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("snap-1").unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

#[test]
fn qemu_check_after_cow_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "cow.qcow2", &[(0, &[0xAA; 4096])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("pre-cow").unwrap();
    // This write triggers COW (data cluster refcount > 1)
    image.write_at(&[0xBB; 4096], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

#[test]
fn qemu_check_after_snapshot_delete() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "del.qcow2", &[(0, &[0xAA; 4096])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("to-delete").unwrap();
    image.snapshot_delete("to-delete").unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

#[test]
fn qemu_check_after_snapshot_apply() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "apply.qcow2", &[(0, &[0xAA; 4096])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("base").unwrap();
    image.write_at(&[0xBB; 4096], 0).unwrap();
    image.snapshot_apply("base").unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

// ---- Cross-validation: our snapshots visible to qemu ----

#[test]
fn qemu_sees_our_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "visible.qcow2", &[(0, &[0xCC; 512])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("my-snap").unwrap();
    image.flush().unwrap();
    drop(image);

    let listing = qemu_snapshot_list(&path);
    assert!(
        listing.contains("my-snap"),
        "qemu-img snapshot -l should list our snapshot. Got:\n{listing}"
    );
}

// ---- Cross-validation: qemu snapshots visible to us ----

#[test]
fn our_code_reads_qemu_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu-snap.qcow2");

    // Create image with qemu
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&path)
        .arg("10M")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Create a snapshot with qemu
    let output = std::process::Command::new("qemu-img")
        .args(["snapshot", "-c", "qemu-snap"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img snapshot -c failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Open with our code and verify the snapshot is listed
    let image = Qcow2Image::open(&path).unwrap();
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "qemu-snap");
}

// ---- Data integrity: COW write verified by qemu-io ----

#[test]
fn cow_write_data_integrity() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "integrity.qcow2", &[(0, &[0x11; 512])]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.snapshot_create("before").unwrap();
    // COW write: new data to the same offset
    image.write_at(&[0x22; 512], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    // Verify with qemu-io that the new data is readable
    let img = common::TestImage {
        path: path.clone(),
        _dir: dir,
    };
    let data = img.read_via_qemu(0, 512);
    assert_eq!(data.len(), 512);
    assert!(
        data.iter().all(|&b| b == 0x22),
        "qemu-io should read our COW-written data"
    );
}

// ---- Full lifecycle: create, snap, write, apply, snap, delete, check ----

#[test]
fn full_snapshot_cycle_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "lifecycle.qcow2",
        &[(0, &[0xAA; 4096]), (65536, &[0xBB; 4096])],
    );

    let mut image = Qcow2Image::open_rw(&path).unwrap();

    // Snapshot the initial state
    image.snapshot_create("initial").unwrap();

    // Overwrite data (triggers COW)
    image.write_at(&[0xCC; 4096], 0).unwrap();

    // Take another snapshot
    image.snapshot_create("modified").unwrap();

    // Revert to initial
    image.snapshot_apply("initial").unwrap();

    // Verify reverted data
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "should revert to initial data");

    // Delete the modified snapshot
    image.snapshot_delete("modified").unwrap();

    image.flush().unwrap();
    drop(image);

    // Final validation with qemu-img check
    assert_qemu_check(&path);
}
