//! Integration tests: image creation, writes, and overlay operations.
//!
//! Cross-validates our QCOW2 creation and write implementation
//! against qemu-img check and qemu-io reads.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};

#[test]
fn qemu_check_our_created_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("created.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 * 1024 * 1024, // 10 MB
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap();
    image.flush().unwrap();
    drop(image);

    // Validate with qemu-img check
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "our created image should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn qemu_check_our_created_image_after_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("written.qcow2");

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

    // Write to several clusters
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();
    image.write_at(&[0xCC; 512], 200000).unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "written image should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn qemu_io_reads_our_written_data() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verify.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap();

    image.write_at(&[0x42; 512], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    // Use qemu-io to read back and verify
    let img = common::TestImage::wrap(path.clone(), dir);
    let data = img.read_via_qemu(0, 512);
    assert_eq!(data.len(), 512);
    assert!(
        data.iter().all(|&b| b == 0x42),
        "qemu-io should read our written data"
    );
}

#[test]
fn qemu_check_our_overlay_image() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("base.qcow2");
    let overlay_path = dir.path().join("overlay.qcow2");

    // Create base with qemu-img (guaranteed valid)
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&base_path)
        .arg("1M")
        .output()
        .expect("failed to run qemu-img create");
    assert!(output.status.success());

    // Create overlay with our code
    let mut overlay = Qcow2Image::create_overlay(
        &overlay_path,
        &base_path,
        1 << 20,
    )
    .unwrap();
    overlay.write_at(&[0xDD; 1024], 0).unwrap();
    overlay.flush().unwrap();
    drop(overlay);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&overlay_path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "our overlay should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn our_code_reads_qemu_created_overlay() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("base.qcow2");
    let overlay_path = dir.path().join("overlay.qcow2");

    // Create base with data written by qemu
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&base_path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "write -P 0xAA 0 4096"])
        .arg(&base_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Create overlay with qemu
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-b"])
        .arg(&base_path)
        .args(["-F", "qcow2"])
        .arg(&overlay_path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Write to overlay with qemu
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "write -P 0xBB 65536 512"])
        .arg(&overlay_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Open the overlay with our code and verify
    let mut image = Qcow2Image::open(&overlay_path).unwrap();

    // Read backing data from cluster 0
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xAA),
        "should read backing data through overlay"
    );

    // Read overlay data from cluster 1
    let mut buf2 = vec![0u8; 512];
    image.read_at(&mut buf2, 65536).unwrap();
    assert!(
        buf2.iter().all(|&b| b == 0xBB),
        "should read overlay-specific data"
    );
}
