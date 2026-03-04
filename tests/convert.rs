//! Integration tests: image conversion with qemu cross-validation.

mod common;

use qcow2_lib::engine::converter;
use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};

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

/// Helper: create a test image with data.
fn create_image_with_data(
    dir: &std::path::Path,
    name: &str,
    data: &[(u64, &[u8])],
) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 2 * 1024 * 1024, // 2 MB
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None,
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

// ---- qcow2 → raw ----

#[test]
fn convert_qcow2_to_raw_matches_qemu_convert() {
    let dir = tempfile::tempdir().unwrap();
    let src = create_image_with_data(
        dir.path(),
        "src.qcow2",
        &[(0, &[0xAA; 4096]), (65536, &[0xBB; 512])],
    );

    // Our conversion
    let our_raw = dir.path().join("our.raw");
    converter::convert_to_raw(&src, &our_raw).unwrap();

    // qemu conversion for reference
    let qemu_raw = dir.path().join("qemu.raw");
    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw"])
        .arg(&src)
        .arg(&qemu_raw)
        .output()
        .expect("failed to run qemu-img convert");
    assert!(
        output.status.success(),
        "qemu-img convert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Compare both raw files byte-for-byte
    let our_data = std::fs::read(&our_raw).unwrap();
    let qemu_data = std::fs::read(&qemu_raw).unwrap();
    assert_eq!(
        our_data.len(),
        qemu_data.len(),
        "raw file sizes should match"
    );
    assert_eq!(
        our_data, qemu_data,
        "our raw output should match qemu-img convert output byte-for-byte"
    );
}

// ---- raw → qcow2 ----

#[test]
fn convert_raw_to_qcow2_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("input.raw");

    // Create a raw file with some data
    let mut raw_data = vec![0u8; 2 * 1024 * 1024];
    raw_data[..4096].fill(0xCC);
    raw_data[65536..65536 + 512].fill(0xDD);
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("output.qcow2");
    converter::convert_from_raw(&raw_path, &qcow2_path, false, None, None).unwrap();

    assert_qemu_check(&qcow2_path);
}

#[test]
fn convert_raw_to_qcow2_data_integrity() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("input.raw");

    let mut raw_data = vec![0u8; 2 * 1024 * 1024];
    raw_data[..512].fill(0xEE);
    raw_data[131072..131072 + 512].fill(0xFF);
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("output.qcow2");
    converter::convert_from_raw(&raw_path, &qcow2_path, false, None, None).unwrap();

    // Verify with qemu-io
    let img = common::TestImage {
        path: qcow2_path,
        _dir: dir,
    };
    let data0 = img.read_via_qemu(0, 512);
    assert!(
        data0.iter().all(|&b| b == 0xEE),
        "data at offset 0 should be preserved"
    );

    let data1 = img.read_via_qemu(131072, 512);
    assert!(
        data1.iter().all(|&b| b == 0xFF),
        "data at offset 131072 should be preserved"
    );
}

// ---- raw → qcow2 with compression ----

#[test]
fn convert_raw_to_qcow2_compressed_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("input.raw");

    // Highly compressible data
    let mut raw_data = vec![0u8; 2 * 1024 * 1024];
    for (i, byte) in raw_data.iter_mut().enumerate() {
        *byte = (i % 4) as u8;
    }
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("compressed.qcow2");
    converter::convert_from_raw(&raw_path, &qcow2_path, true, None, None).unwrap();

    assert_qemu_check(&qcow2_path);
}

#[test]
fn convert_compressed_data_readable_by_qemu() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("input.raw");

    let mut raw_data = vec![0u8; 2 * 1024 * 1024];
    raw_data[..512].fill(0x42);
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("compressed.qcow2");
    converter::convert_from_raw(&raw_path, &qcow2_path, true, None, None).unwrap();

    let img = common::TestImage {
        path: qcow2_path,
        _dir: dir,
    };
    let data = img.read_via_qemu(0, 512);
    assert!(
        data.iter().all(|&b| b == 0x42),
        "qemu-io should read compressed data correctly"
    );
}

// ---- qcow2 → qcow2 (compact) ----

#[test]
fn convert_qcow2_to_qcow2_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let src = create_image_with_data(
        dir.path(),
        "src.qcow2",
        &[(0, &[0x11; 4096]), (65536, &[0x22; 512])],
    );

    let dst = dir.path().join("compact.qcow2");
    converter::convert_qcow2_to_qcow2(&src, &dst, false, None, None).unwrap();

    assert_qemu_check(&dst);

    // Verify data integrity with our library
    let mut image = Qcow2Image::open(&dst).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));

    let mut buf2 = vec![0u8; 512];
    image.read_at(&mut buf2, 65536).unwrap();
    assert!(buf2.iter().all(|&b| b == 0x22));
}

#[test]
fn convert_qcow2_to_qcow2_compressed_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let src = create_image_with_data(
        dir.path(),
        "src.qcow2",
        &[(0, &[0x33; 4096]), (65536, &[0x44; 4096])],
    );

    let dst = dir.path().join("compressed.qcow2");
    converter::convert_qcow2_to_qcow2(&src, &dst, true, None, None).unwrap();

    assert_qemu_check(&dst);
}
