//! Image operations tests: info, cluster status, convert, QEMU interop.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const CS: usize = 65536;
const CSU: u64 = CS as u64;

fn create_mem(vs: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
                refcount_order: None,
        },
    )
    .unwrap()
}

// =====================================================================
// 1. Header / metadata access
// =====================================================================

#[test]
fn header_fields_accessible() {
    let image = create_mem(10 << 20);
    assert_eq!(image.header().version, 3);
    assert_eq!(image.virtual_size(), 10 << 20);
    assert_eq!(image.cluster_bits(), 16);
    assert_eq!(image.cluster_size(), 65536);
}

#[test]
fn cache_stats_available() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    let _stats = image.cache_stats();
    // Just checking it doesn't panic
}

#[test]
fn extensions_list() {
    let image = create_mem(1 << 20);
    // Verify extensions() is callable (may be empty for minimal in-memory images)
    let _exts = image.extensions();
}

// =====================================================================
// 2. Writable vs read-only
// =====================================================================

#[test]
fn created_image_is_writable() {
    let image = create_mem(1 << 20);
    assert!(image.is_writable());
}

#[test]
fn opened_readonly_is_not_writable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ro.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
                refcount_order: None,
        },
    )
    .unwrap();
    image.flush().unwrap();
    drop(image);

    let image = Qcow2Image::open(&path).unwrap();
    assert!(!image.is_writable());
}

#[test]
fn write_to_readonly_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ro_write.qcow2");
    Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
                refcount_order: None,
        },
    )
    .unwrap()
    .flush()
    .unwrap();

    let mut image = Qcow2Image::open(&path).unwrap();
    let result = image.write_at(&vec![0xAA; 512], 0);
    assert!(result.is_err(), "write to read-only should fail");
}

// =====================================================================
// 3. From backend
// =====================================================================

#[test]
fn from_backend_memory() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

#[test]
fn from_backend_reads_qemu_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("1M");
    img.write_pattern(0xCC, 0, 4096);

    let data = std::fs::read(&img.path).unwrap();
    let backend = MemoryBackend::new(data);
    let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

// =====================================================================
// 4. Integrity check
// =====================================================================

#[test]
fn integrity_check_fresh_image() {
    let mut image = create_mem(1 << 20);
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
    assert_eq!(report.total_errors(), 0);
}

#[test]
fn integrity_check_after_writes() {
    let mut image = create_mem(4 * CSU);
    for i in 0..4u64 {
        image.write_at(&vec![(i as u8 + 1) * 0x11; CS], i * CSU).unwrap();
    }
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
    assert!(report.stats.data_clusters >= 4);
}

// =====================================================================
// 5. Convert
// =====================================================================

#[test]
fn convert_from_raw() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("input.raw");
    let qcow2 = dir.path().join("output.qcow2");

    let mut data = vec![0u8; 1 << 20];
    data[..CS].fill(0xAA);
    std::fs::write(&raw, &data).unwrap();

    qcow2::engine::converter::convert_from_raw(&raw, &qcow2, false, None, None, None).unwrap();

    let mut image = Qcow2Image::open(&qcow2).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    // Zero region
    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

#[test]
fn convert_to_raw() {
    let dir = tempfile::tempdir().unwrap();
    let qcow2 = dir.path().join("source.qcow2");
    let raw = dir.path().join("output.raw");

    let mut image = Qcow2Image::create(
        &qcow2,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
                refcount_order: None,
        },
    )
    .unwrap();
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    qcow2::engine::converter::convert_to_raw(&qcow2, &raw, None).unwrap();

    let raw_data = std::fs::read(&raw).unwrap();
    assert_eq!(raw_data.len(), 1 << 20);
    assert!(raw_data[..CS].iter().all(|&b| b == 0xBB));
    assert!(raw_data[CS..2 * CS].iter().all(|&b| b == 0x00));
}

#[test]
fn convert_with_compression() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("input.raw");
    let qcow2 = dir.path().join("compressed.qcow2");

    let mut data = vec![0u8; 1 << 20];
    data[..CS].fill(0xCC);
    std::fs::write(&raw, &data).unwrap();

    qcow2::engine::converter::convert_from_raw(&raw, &qcow2, true, None, None, None).unwrap();

    let mut image = Qcow2Image::open(&qcow2).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

// =====================================================================
// 6. QEMU interop
// =====================================================================

#[test]
fn qemu_check_our_converted_image() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("input.raw");
    let qcow2 = dir.path().join("converted.qcow2");

    let mut data = vec![0u8; 1 << 20];
    data[..CS].fill(0xDD);
    std::fs::write(&raw, &data).unwrap();

    qcow2::engine::converter::convert_from_raw(&raw, &qcow2, false, None, None, None).unwrap();

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&qcow2)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cross_validate_convert_roundtrip() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();

    // Create with QEMU, write data
    let source = common::TestImage::create("1M");
    source.write_pattern(0xEE, 0, CS);

    // Convert to raw with our code
    let raw = dir.path().join("roundtrip.raw");
    qcow2::engine::converter::convert_to_raw(&source.path, &raw, None).unwrap();

    let raw_data = std::fs::read(&raw).unwrap();
    assert!(raw_data[..CS].iter().all(|&b| b == 0xEE));
}
