//! Integration tests: Zstandard compression support.
//!
//! Tests creating, writing, reading, and converting images with
//! zstd compression (compression_type=1).

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};

// ---- Library-only tests (no QEMU needed) ----

#[test]
fn create_zstd_image_sets_header_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
        },
    )
    .unwrap();

    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);
    assert!(image.header().header_length > 104, "header_length should include compression_type byte");
    assert!(
        image.header().incompatible_features.contains(
            qcow2::format::feature_flags::IncompatibleFeatures::COMPRESSION_TYPE
        ),
        "COMPRESSION_TYPE incompatible feature must be set"
    );
}

#[test]
fn create_deflate_image_has_default_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deflate.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None, encryption: None,
     refcount_order: None,
        },
    )
    .unwrap();

    assert_eq!(image.header().compression_type, COMPRESSION_DEFLATE);
    assert_eq!(image.header().header_length, 104);
    assert!(
        !image.header().incompatible_features.contains(
            qcow2::format::feature_flags::IncompatibleFeatures::COMPRESSION_TYPE
        ),
    );
}

#[test]
fn zstd_write_read_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 2 * 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
        },
    )
    .unwrap();

    // Write various patterns
    let data_a = vec![0xAA; 65536];
    let data_b = vec![0xBB; 512];
    image.write_at(&data_a, 0).unwrap();
    image.write_at(&data_b, 65536).unwrap();
    image.flush().unwrap();

    // Read back
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    let mut buf2 = vec![0u8; 512];
    image.read_at(&mut buf2, 65536).unwrap();
    assert!(buf2.iter().all(|&b| b == 0xBB));
}

#[test]
fn zstd_compressed_write_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd_compressed.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
        },
    )
    .unwrap();

    // Write compressible data using compressed write path
    let data = vec![0xCC; 65536];
    image.write_cluster_maybe_compressed(&data, 0).unwrap();
    image.flush().unwrap();

    // Read back
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn zstd_compressed_cluster_cow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd_cow.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
        },
    )
    .unwrap();

    // Write a full cluster of 0xAA as compressed
    let original = vec![0xAA; 65536];
    image.write_cluster_maybe_compressed(&original, 0).unwrap();

    // Partial write into the compressed cluster triggers COW
    let patch = vec![0xBB; 64];
    image.write_at(&patch, 100).unwrap();
    image.flush().unwrap();

    // Read back — bytes 0..100 should be 0xAA, 100..164 should be 0xBB, rest 0xAA
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..100].iter().all(|&b| b == 0xAA), "pre-patch region");
    assert!(buf[100..164].iter().all(|&b| b == 0xBB), "patched region");
    assert!(buf[164..].iter().all(|&b| b == 0xAA), "post-patch region");
}

#[test]
fn zstd_reopen_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd_reopen.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
                extended_l2: false,
                compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
            },
        )
        .unwrap();

        image.write_at(&[0xDD; 4096], 0).unwrap();
        image.write_cluster_maybe_compressed(&vec![0xEE; 65536], 65536).unwrap();
        image.flush().unwrap();
    }

    // Reopen and verify
    let mut image = Qcow2Image::open(&path).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);

    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));

    let mut buf2 = vec![0u8; 65536];
    image.read_at(&mut buf2, 65536).unwrap();
    assert!(buf2.iter().all(|&b| b == 0xEE));
}

#[test]
fn convert_raw_to_zstd_qcow2() {
    let dir = tempfile::tempdir().unwrap();

    // Create a raw file
    let raw_path = dir.path().join("input.raw");
    let mut raw_data = vec![0u8; 1024 * 1024];
    raw_data[..512].fill(0xAA);
    raw_data[65536..66048].fill(0xBB);
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("output.qcow2");
    qcow2::engine::converter::convert_from_raw(
        &raw_path,
        &qcow2_path,
        true, // compress
        Some(COMPRESSION_ZSTD),
        None,
        None,
    )
    .unwrap();

    let mut image = Qcow2Image::open(&qcow2_path).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    image.read_at(&mut buf, 65536).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

// ---- QEMU interop tests (require QEMU with zstd support) ----

/// Check if the installed QEMU supports zstd compression.
fn qemu_supports_zstd() -> bool {
    if !common::has_qemu_img() {
        return false;
    }
    // Try to create a zstd image — if QEMU doesn't support it, it will fail.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd_test.qcow2");
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "compression_type=zstd"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap_or_else(|_| panic!("failed to run qemu-img"));
    output.status.success()
}

#[test]
fn qemu_reads_our_zstd_image() {
    if !qemu_supports_zstd() {
        eprintln!("skipping: qemu-img with zstd support not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lib_zstd.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
                extended_l2: false,
                compression_type: Some(COMPRESSION_ZSTD), data_file: None, encryption: None,
     refcount_order: None,
            },
        )
        .unwrap();

        image.write_at(&[0xAA; 65536], 0).unwrap();
        image.write_cluster_maybe_compressed(&vec![0xBB; 65536], 65536).unwrap();
        image.flush().unwrap();
    }

    // qemu-img check should pass
    let check = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "qemu-img check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    // qemu-io should read back correct data
    let ti = common::TestImage::wrap(path, dir);
    let data = ti.read_via_qemu(0, 512);
    assert!(data.iter().all(|&b| b == 0xAA), "first cluster via qemu-io");

    let data2 = ti.read_via_qemu(65536, 512);
    assert!(data2.iter().all(|&b| b == 0xBB), "second cluster via qemu-io");
}

#[test]
fn library_reads_qemu_zstd_image() {
    if !qemu_supports_zstd() {
        eprintln!("skipping: qemu-img with zstd support not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_zstd.qcow2");

    // Create zstd image with QEMU
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "compression_type=zstd"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Write data via qemu-io
    let write_cmd = "write -P 0xCC 0 65536";
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", write_cmd])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Read with our library
    let mut image = Qcow2Image::open(&path).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

#[test]
fn library_reads_qemu_zstd_compressed_image() {
    if !qemu_supports_zstd() {
        eprintln!("skipping: qemu-img with zstd support not available");
        return;
    }

    // First create a source with data
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("source.qcow2");
    let compressed = dir.path().join("compressed_zstd.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "compression_type=zstd"])
        .arg(&src)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    let write_cmd = "write -P 0xDD 0 65536";
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", write_cmd])
        .arg(&src)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Convert to compressed zstd image
    let output = std::process::Command::new("qemu-img")
        .args([
            "convert", "-c", "-f", "qcow2", "-O", "qcow2",
            "-o", "compression_type=zstd",
        ])
        .arg(&src)
        .arg(&compressed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img convert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read the compressed zstd image with our library
    let mut image = Qcow2Image::open(&compressed).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);

    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xDD),
        "compressed zstd data from QEMU should read correctly"
    );
}
