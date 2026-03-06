//! Integration tests: read compressed QCOW2 clusters.
//!
//! Creates images with compressed clusters using qemu-img convert,
//! then verifies our library reads them correctly.

mod common;

use qcow2::engine::image::Qcow2Image;

#[test]
fn read_compressed_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    // Create a source image and write data to it
    let source = common::TestImage::create("1M");
    source.write_pattern(0xAA, 0, 65536);

    // Convert to a compressed qcow2 image
    let dir = tempfile::TempDir::new().unwrap();
    let compressed_path = dir.path().join("compressed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed_path)
        .output()
        .expect("failed to run qemu-img convert");

    assert!(
        output.status.success(),
        "qemu-img convert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read the compressed image with our library
    let mut image = Qcow2Image::open(&compressed_path).unwrap();

    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();

    assert!(
        buf.iter().all(|&b| b == 0xAA),
        "compressed data should read back as 0xAA, got first byte 0x{:02x}",
        buf[0]
    );
}

#[test]
fn read_compressed_multiple_clusters() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let source = common::TestImage::create("1M");
    let cluster_size = 65536u64;

    // Write different patterns to different clusters
    source.write_pattern(0x11, 0, cluster_size as usize);
    source.write_pattern(0x22, cluster_size, cluster_size as usize);
    source.write_pattern(0x33, 2 * cluster_size, cluster_size as usize);

    let dir = tempfile::TempDir::new().unwrap();
    let compressed_path = dir.path().join("compressed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed_path)
        .output()
        .expect("failed to run qemu-img convert");

    assert!(output.status.success());

    let mut image = Qcow2Image::open(&compressed_path).unwrap();

    let mut buf = vec![0u8; 4096];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11), "cluster 0 should be 0x11");

    image.read_at(&mut buf, cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22), "cluster 1 should be 0x22");

    image.read_at(&mut buf, 2 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0x33), "cluster 2 should be 0x33");
}

#[test]
fn read_compressed_spanning_cluster() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let source = common::TestImage::create("1M");
    let cluster_size = 65536u64;

    source.write_pattern(0xAA, 0, cluster_size as usize);
    source.write_pattern(0xBB, cluster_size, cluster_size as usize);

    let dir = tempfile::TempDir::new().unwrap();
    let compressed_path = dir.path().join("compressed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed_path)
        .output()
        .expect("failed to run qemu-img convert");

    assert!(output.status.success());

    let mut image = Qcow2Image::open(&compressed_path).unwrap();

    // Read across boundary
    let read_offset = cluster_size - 512;
    let mut buf = vec![0u8; 1024];
    image.read_at(&mut buf, read_offset).unwrap();

    assert!(
        buf[..512].iter().all(|&b| b == 0xAA),
        "first half should be 0xAA"
    );
    assert!(
        buf[512..].iter().all(|&b| b == 0xBB),
        "second half should be 0xBB"
    );
}
