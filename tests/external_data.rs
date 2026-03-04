//! Integration tests: External Data File support.
//!
//! Tests creating, writing, reading, and verifying QCOW2 images
//! with external data files (RAW_EXTERNAL mode).

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use qcow2_lib::format::header_extension::HeaderExtension;
use qcow2_lib::io::MemoryBackend;

// ---- Library-only tests (no QEMU needed) ----

#[test]
fn create_external_data_sets_header_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("ext.raw".to_string()),
        },
    )
    .unwrap();

    assert!(
        image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::EXTERNAL_DATA_FILE),
        "EXTERNAL_DATA_FILE bit should be set"
    );
    assert!(
        image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::RAW_EXTERNAL),
        "RAW_EXTERNAL bit should be set"
    );
    assert!(image.has_external_data_file());

    // Check header extension
    let has_ext = image.extensions().iter().any(|e| {
        matches!(e, HeaderExtension::ExternalDataFile(name) if name == "ext.raw")
    });
    assert!(has_ext, "ExternalDataFile extension should be present");
}

#[test]
fn create_external_data_creates_data_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let _image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("ext.raw".to_string()),
        },
    )
    .unwrap();

    let data_path = dir.path().join("ext.raw");
    assert!(data_path.exists(), "data file should exist");
    let meta = std::fs::metadata(&data_path).unwrap();
    assert_eq!(meta.len(), 1024 * 1024, "data file should be virtual_size");
}

#[test]
fn write_read_round_trip_with_memory_backends() {
    // Use MemoryBackend pair to test without files
    let meta_be = MemoryBackend::zeroed(0);
    let data_be = MemoryBackend::zeroed(1024 * 1024);

    let mut image = Qcow2Image::create_on_backend(
        Box::new(meta_be),
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("data.raw".to_string()),
        },
    )
    .unwrap();

    // Attach data backend manually (create_on_backend doesn't open files)
    image.set_data_backend(Box::new(data_be));

    let write_data = vec![0xAB; 4096];
    image.write_at(&write_data, 0).unwrap();

    let mut read_buf = vec![0u8; 4096];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, write_data);
}

#[test]
fn write_read_round_trip_file_based() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let write_data = vec![0xCD; 512];

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: Some("ext.raw".to_string()),
            },
        )
        .unwrap();

        image.write_at(&write_data, 0).unwrap();
        image.write_at(&[0xEF; 512], 65536).unwrap();
        image.flush().unwrap();
    }

    // Reopen and verify
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert!(image.has_external_data_file());

    let mut read_buf = vec![0u8; 512];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, write_data);

    image.read_at(&mut read_buf, 65536).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0xEF));

    // Unwritten area should be zero
    image.read_at(&mut read_buf, 512).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));
}

#[test]
fn compressed_write_rejected_with_external_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("ext.raw".to_string()),
        },
    )
    .unwrap();

    // Regular write should work
    image.write_at(&[0xAA; 512], 0).unwrap();

    // Compressed write should fail
    let data = vec![0xBB; image.cluster_size() as usize];
    let result = image.write_cluster_maybe_compressed(&data, 65536);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("compressed"),
        "error should mention compressed: {err}"
    );
}

#[test]
fn create_with_compression_and_external_data_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.qcow2");

    let result = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(qcow2_lib::format::constants::COMPRESSION_ZSTD),
            data_file: Some("data.raw".to_string()),
        },
    );
    assert!(result.is_err(), "zstd + external data should fail");
}

#[test]
fn integrity_check_passes_with_external_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("ext.raw".to_string()),
        },
    )
    .unwrap();

    // Write some data
    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();
    image.flush().unwrap();

    // Integrity check should pass
    let report = image.check_integrity().unwrap();
    assert!(
        report.mismatches.is_empty(),
        "should have no mismatches: {:?}",
        report.mismatches
    );
    assert!(
        report.leaks.is_empty(),
        "should have no leaks: {:?}",
        report.leaks
    );
}

#[test]
fn convert_raw_to_qcow2_with_data_file() {
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("input.raw");

    // Create a small raw file with data
    let mut raw_data = vec![0u8; 1024 * 1024];
    raw_data[..512].fill(0xDD);
    std::fs::write(&raw_path, &raw_data).unwrap();

    let qcow2_path = dir.path().join("output.qcow2");
    qcow2_lib::engine::converter::convert_from_raw(
        &raw_path,
        &qcow2_path,
        false,
        None,
        Some("output.raw".to_string()),
    )
    .unwrap();

    // Verify
    let mut image = Qcow2Image::open_rw(&qcow2_path).unwrap();
    assert!(image.has_external_data_file());

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

#[test]
fn data_offsets_are_identity_mapped() {
    // Verify that with RAW_EXTERNAL, host_offset == guest_offset
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some("ext.raw".to_string()),
        },
    )
    .unwrap();

    // Write at guest offset 0
    image.write_at(&[0xAA; 512], 0).unwrap();
    // Write at guest offset 65536 (cluster 1)
    image.write_at(&[0xBB; 512], 65536).unwrap();
    image.flush().unwrap();

    // Read the raw data file directly and verify identity mapping
    let raw_data = std::fs::read(dir.path().join("ext.raw")).unwrap();
    assert_eq!(raw_data[0], 0xAA, "byte 0 of data file should be 0xAA");
    assert_eq!(raw_data[65536], 0xBB, "byte 65536 of data file should be 0xBB");
}

// ---- QEMU interop tests ----

#[test]
fn qemu_reads_our_external_data_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");
    let data_raw = dir.path().join("ext.raw");

    // Create image with our library, using absolute path for QEMU compat
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some(data_raw.display().to_string()),
        },
    )
    .unwrap();

    image.write_at(&[0x42; 512], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    // Read with qemu-io
    let ti = common::TestImage::wrap(path, dir);
    let data = ti.read_via_qemu(0, 512);
    assert_eq!(data.len(), 512);
    assert!(data.iter().all(|&b| b == 0x42), "QEMU should read our data");
}

#[test]
fn we_read_qemu_external_data_image() {
    if !common::has_qemu_img() || !common::has_qemu_io() {
        eprintln!("skipping: qemu-img/qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_ext.qcow2");
    let data_path = dir.path().join("qemu_ext.raw");

    // Create with qemu-img (data_file_raw=on for RAW_EXTERNAL)
    let output = std::process::Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            "-o",
            &format!("data_file={},data_file_raw=on", data_path.display()),
        ])
        .arg(&path)
        .arg("1M")
        .output()
        .expect("qemu-img create");
    assert!(output.status.success(), "qemu-img create failed: {}", String::from_utf8_lossy(&output.stderr));

    // Write data with qemu-io
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "write -P 0x55 0 512"])
        .arg(&path)
        .output()
        .expect("qemu-io write");
    assert!(output.status.success(), "qemu-io write failed: {}", String::from_utf8_lossy(&output.stderr));

    // Read with our library
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    assert!(image.has_external_data_file());

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x55), "should read QEMU-written data");
}

#[test]
fn qemu_check_passes_on_our_image() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ext.qcow2");
    let data_raw = dir.path().join("ext.raw");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1024 * 1024,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some(data_raw.display().to_string()),
        },
    )
    .unwrap();

    image.write_at(&[0xAA; 4096], 0).unwrap();
    image.write_at(&[0xBB; 4096], 65536).unwrap();
    image.flush().unwrap();
    drop(image);

    let ti = common::TestImage::wrap(path, dir);
    assert!(ti.qemu_check(), "qemu-img check should pass");
}
