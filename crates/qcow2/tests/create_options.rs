//! CreateOptions validation tests.
//!
//! Tests all CreateOptions fields: virtual_size, cluster_bits, extended_l2,
//! compression_type, data_file, encryption, and various combinations.

mod common;

use qcow2::engine::encryption::CipherMode;
use qcow2::engine::image::{CreateOptions, EncryptionOptions, Qcow2Image};
use qcow2::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};
use qcow2::io::MemoryBackend;

const CS: usize = 65536;

fn opts(vs: u64) -> CreateOptions {
    CreateOptions {
        virtual_size: vs,
        cluster_bits: None,
        extended_l2: false,
        compression_type: None,
        data_file: None,
        encryption: None,
    }
}

// =====================================================================
// 1. Virtual size
// =====================================================================

#[test]
fn create_1mb() {
    let mut image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(1 << 20)).unwrap();
    assert_eq!(image.virtual_size(), 1 << 20);
    image.write_at(&vec![0xAA; 512], 0).unwrap();
    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn create_1gb() {
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(1 << 30)).unwrap();
    assert_eq!(image.virtual_size(), 1 << 30);
}

#[test]
fn create_non_aligned_virtual_size() {
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(123456)).unwrap();
    assert_eq!(image.virtual_size(), 123456);
}

#[test]
fn create_zero_size_rejected() {
    let result = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(0));
    assert!(result.is_err());
}

// =====================================================================
// 2. Cluster bits
// =====================================================================

#[test]
fn cluster_bits_9() {
    let mut o = opts(1 << 20);
    o.cluster_bits = Some(9);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert_eq!(image.cluster_size(), 512);
}

#[test]
fn cluster_bits_12() {
    let mut o = opts(1 << 20);
    o.cluster_bits = Some(12);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert_eq!(image.cluster_size(), 4096);
}

#[test]
fn cluster_bits_16_default() {
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(1 << 20)).unwrap();
    assert_eq!(image.cluster_bits(), 16);
}

#[test]
fn cluster_bits_21() {
    let mut o = opts(4 << 20);
    o.cluster_bits = Some(21);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert_eq!(image.cluster_size(), 2 * 1024 * 1024);
}

#[test]
fn cluster_bits_8_rejected() {
    let mut o = opts(1 << 20);
    o.cluster_bits = Some(8);
    assert!(Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).is_err());
}

#[test]
fn cluster_bits_22_rejected() {
    let mut o = opts(1 << 20);
    o.cluster_bits = Some(22);
    assert!(Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).is_err());
}

// =====================================================================
// 3. Extended L2
// =====================================================================

#[test]
fn extended_l2_true() {
    let mut o = opts(1 << 20);
    o.extended_l2 = true;
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert!(image.header().has_extended_l2());
    assert_eq!(image.header().l2_entry_size(), 16);
}

#[test]
fn extended_l2_false() {
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(1 << 20)).unwrap();
    assert!(!image.header().has_extended_l2());
    assert_eq!(image.header().l2_entry_size(), 8);
}

#[test]
fn extended_l2_write_read_subcluster() {
    let mut o = opts(1 << 20);
    o.extended_l2 = true;
    let mut image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();

    let sc_size = CS / 32;
    image.write_at(&vec![0xAA; sc_size], 0).unwrap();
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 4. Compression type
// =====================================================================

#[test]
fn compression_type_none_is_deflate() {
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), opts(1 << 20)).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_DEFLATE);
}

#[test]
fn compression_type_deflate_explicit() {
    let mut o = opts(1 << 20);
    o.compression_type = Some(COMPRESSION_DEFLATE);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_DEFLATE);
}

#[test]
fn compression_type_zstd() {
    let mut o = opts(1 << 20);
    o.compression_type = Some(COMPRESSION_ZSTD);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);
}

#[test]
fn invalid_compression_type_rejected() {
    let mut o = opts(1 << 20);
    o.compression_type = Some(255);
    assert!(Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).is_err());
}

// =====================================================================
// 5. External data file
// =====================================================================

#[test]
fn create_with_data_file() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("img.qcow2");
    let data = dir.path().join("data.raw");
    std::fs::write(&data, vec![0u8; 1 << 20]).unwrap();

    let image = Qcow2Image::create(
        &img,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some(data.to_string_lossy().to_string()),
            encryption: None,
        },
    )
    .unwrap();

    assert!(image.has_external_data_file());
}

// =====================================================================
// 6. Encryption options
// =====================================================================

#[test]
fn create_with_xts_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc_xts.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: b"pass".to_vec(),
                cipher: CipherMode::AesXtsPlain64,
                luks_version: 1,
                iter_time_ms: Some(10),
            }),
        },
    )
    .unwrap();

    assert!(image.is_encrypted());
    assert_eq!(image.header().crypt_method, 2);
}

#[test]
fn create_with_cbc_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc_cbc.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: b"pass".to_vec(),
                cipher: CipherMode::AesCbcEssiv,
                luks_version: 1,
                iter_time_ms: Some(10),
            }),
        },
    )
    .unwrap();

    assert!(image.is_encrypted());
}

// =====================================================================
// 7. Combinations
// =====================================================================

#[test]
fn extended_l2_with_zstd() {
    let mut o = opts(1 << 20);
    o.extended_l2 = true;
    o.compression_type = Some(COMPRESSION_ZSTD);
    let image = Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();
    assert!(image.header().has_extended_l2());
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);
}

#[test]
fn various_cluster_bits_with_data() {
    for bits in [9, 12, 14, 16, 18, 20] {
        let mut o = opts(std::cmp::max(1u64 << bits, 1 << 20));
        o.cluster_bits = Some(bits);
        let mut image =
            Qcow2Image::create_on_backend(Box::new(MemoryBackend::zeroed(0)), o).unwrap();

        let cs = image.cluster_size() as usize;
        let data = vec![0xBB; cs];
        image.write_at(&data, 0).unwrap();
        let mut buf = vec![0u8; cs];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data, "cluster_bits={bits}");
    }
}

#[test]
fn encryption_with_extended_l2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc_ext.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: true,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: b"pass".to_vec(),
                cipher: CipherMode::AesXtsPlain64,
                luks_version: 1,
                iter_time_ms: Some(10),
            }),
        },
    )
    .unwrap();

    assert!(image.is_encrypted());
    assert!(image.header().has_extended_l2());

    let sc_size = CS / 32;
    image.write_at(&vec![0xAA; sc_size], 0).unwrap();
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 8. File-based creation
// =====================================================================

#[test]
fn create_on_disk_qemu_check() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 10 << 20,
            cluster_bits: Some(16),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    image.write_at(&vec![0xAA; 4096], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
}

// =====================================================================
// 9. Overlay creation
// =====================================================================

#[test]
fn create_overlay_basic() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    let mut base_img = Qcow2Image::create(&base, opts(1 << 20)).unwrap();
    base_img.write_at(&vec![0xAA; CS], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    assert!(ov.header().has_backing_file());

    let mut buf = vec![0u8; CS];
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}
