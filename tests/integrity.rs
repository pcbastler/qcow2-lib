//! Integration tests: image integrity validation.
//!
//! Uses qemu-img check to validate that our understanding of the
//! QCOW2 format is correct by cross-validating with QEMU's implementation.

mod common;

use qcow2::engine::image::Qcow2Image;

#[test]
fn qemu_check_fresh_default_image() {
    let img = common::TestImage::create("10M");
    assert!(img.qemu_check(), "fresh default image should pass check");
}

#[test]
fn qemu_check_after_writes() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    let cluster_size = 65536u64;

    // Write to several clusters
    img.write_pattern(0xAA, 0, cluster_size as usize);
    img.write_pattern(0xBB, cluster_size, cluster_size as usize);
    img.write_pattern(0xCC, 5 * cluster_size, 4096);

    assert!(
        img.qemu_check(),
        "image should pass check after qemu-io writes"
    );
}

#[test]
fn qemu_check_compressed_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let source = common::TestImage::create("1M");
    source.write_pattern(0xAA, 0, 65536);

    let dir = tempfile::TempDir::new().unwrap();
    let compressed_path = dir.path().join("compressed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed_path)
        .output()
        .expect("failed to run qemu-img convert");

    assert!(output.status.success());

    // Verify compressed image passes qemu-img check
    let check_output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&compressed_path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        check_output.status.success(),
        "compressed image should pass check"
    );

    // Verify our library can read the compressed image
    let mut image = Qcow2Image::open(&compressed_path).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xAA),
        "library should read compressed data correctly"
    );
}

#[test]
fn qemu_check_image_with_backing() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let base = common::TestImage::create("1M");
    base.write_pattern(0xBB, 0, 4096);

    let overlay = common::TestImage::create_with_backing("1M", &base.path);

    assert!(
        overlay.qemu_check(),
        "image with backing should pass check"
    );

    // Verify our library reads through the backing chain
    let mut image = Qcow2Image::open(&overlay.path).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "library should read backing data through overlay"
    );
}
