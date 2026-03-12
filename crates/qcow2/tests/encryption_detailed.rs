//! Detailed LUKS encryption tests.
//!
//! Tests both cipher modes (AES-XTS-plain64, AES-CBC-ESSIV), password
//! handling, cluster boundary writes, snapshot interaction, and QEMU interop.

mod common;

use qcow2::engine::encryption::CipherMode;
use qcow2::engine::image::{CreateOptions, EncryptionOptions, Qcow2Image};

const CS: usize = 65536;
const CSU: u64 = CS as u64;

fn xts_opts(pw: &str) -> Option<EncryptionOptions> {
    Some(EncryptionOptions {
        password: pw.as_bytes().to_vec(),
        cipher: CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: Some(10),
    })
}

fn cbc_opts(pw: &str) -> Option<EncryptionOptions> {
    Some(EncryptionOptions {
        password: pw.as_bytes().to_vec(),
        cipher: CipherMode::AesCbcEssiv,
        luks_version: 1,
        iter_time_ms: Some(10),
    })
}

// =====================================================================
// 1. Basic encryption round-trip
// =====================================================================

#[test]
fn xts_write_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("xts.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("testpass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn cbc_write_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cbc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: cbc_opts("testpass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

// =====================================================================
// 2. Password handling
// =====================================================================

#[test]
fn reopen_with_correct_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reopen.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("secret123"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xCC; CS], 0).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open_with_password(&path, b"secret123").unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

#[test]
fn wrong_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrong_pw.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("correct"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.flush().unwrap();
    }

    let result = Qcow2Image::open_with_password(&path, b"wrong");
    assert!(result.is_err(), "wrong password should be rejected");
}

#[test]
fn open_encrypted_without_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no_pw.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("secret"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.flush().unwrap();
    }

    let result = Qcow2Image::open(&path);
    assert!(result.is_err(), "opening encrypted image without password should fail");
}

// =====================================================================
// 3. Multiple clusters and partial writes
// =====================================================================

#[test]
fn encrypted_multiple_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    for i in 0u64..4 {
        image.write_at(&vec![(i as u8 + 1) * 0x11; CS], i * CSU).unwrap();
    }
    image.flush().unwrap();

    for i in 0u64..4 {
        let mut buf = vec![0u8; CS];
        image.read_at(&mut buf, i * CSU).unwrap();
        assert!(buf.iter().all(|&b| b == (i as u8 + 1) * 0x11), "cluster {i}");
    }
}

#[test]
fn encrypted_partial_cluster_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.write_at(&vec![0xFF; 512], 100).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..100].iter().all(|&b| b == 0xAA));
    assert!(buf[100..612].iter().all(|&b| b == 0xFF));
    assert!(buf[612..].iter().all(|&b| b == 0xAA));
}

#[test]
fn encrypted_cross_cluster_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cross.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.write_at(&vec![0xBB; CS], CSU).unwrap();

    // Write spanning cluster boundary
    let start = CSU - 512;
    image.write_at(&vec![0xFF; 1024], start).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..CS - 512].iter().all(|&b| b == 0xAA));
    assert!(buf[CS - 512..].iter().all(|&b| b == 0xFF));

    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xFF));
    assert!(buf[512..].iter().all(|&b| b == 0xBB));
}

// =====================================================================
// 4. Encryption header properties
// =====================================================================

#[test]
fn encrypted_image_has_crypt_method_luks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("header.qcow2");

    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    assert!(image.is_encrypted());
    assert_eq!(image.header().crypt_method, 2); // 2 = LUKS
}

// =====================================================================
// 5. Snapshots with encryption
// =====================================================================

#[test]
fn encrypted_snapshot_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc_snap.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));

    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 6. Data is actually encrypted on disk
// =====================================================================

#[test]
fn data_not_plaintext_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verify_enc.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("pass"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CS], 0).unwrap();
        image.flush().unwrap();
    }

    // Read raw file and check data area isn't plaintext
    let raw = std::fs::read(&path).unwrap();
    // Count consecutive 0xAA bytes — encrypted data shouldn't have CS of them
    let max_run = raw.windows(CS).filter(|w| w.iter().all(|&b| b == 0xAA)).count();
    assert_eq!(max_run, 0, "encrypted data should not contain plaintext pattern");
}

// =====================================================================
// 7. Integrity check with encryption
// =====================================================================

#[test]
fn integrity_clean_with_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc_int.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: xts_opts("pass"),
                refcount_order: None,
        },
    )
    .unwrap();

    image.write_at(&vec![0xBB; CS], 0).unwrap();
    image.write_at(&vec![0xCC; CS], CSU).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "encrypted image should be clean: {report:?}");
}

// =====================================================================
// 8. QEMU interop
// =====================================================================

#[test]
fn qemu_reads_our_encrypted_xts_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_xts.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("testpw"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0xAA; CS], 0).unwrap();
        image.flush().unwrap();
    }

    let ti = common::EncryptedTestImage {
        path,
        password: "testpw".to_string(),
        _dir: dir,
    };

    assert!(ti.qemu_check(), "qemu-img check should pass");
    let data = ti.read_via_qemu(0, 512);
    assert!(data.iter().all(|&b| b == 0xAA), "qemu should read our encrypted data");
}

#[test]
fn we_read_qemu_encrypted_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let ti = common::EncryptedTestImage::create("1M", "qemupw");
    ti.write_pattern(0xBB, 0, CS);

    let mut image = Qcow2Image::open_with_password(&ti.path, b"qemupw").unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "should read QEMU encrypted data");
}

#[test]
fn bidirectional_encrypted_rw() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bidir.qcow2");

    // Create and write with our library
    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: xts_opts("shared"),
                    refcount_order: None,
            },
        )
        .unwrap();
        image.write_at(&vec![0x11; CS], 0).unwrap();
        image.flush().unwrap();
    }

    // Write with QEMU
    let ti = common::EncryptedTestImage {
        path: path.clone(),
        password: "shared".to_string(),
        _dir: dir,
    };
    ti.write_pattern(0x22, CSU, CS);

    // Read both clusters with our library
    let mut image = Qcow2Image::open_rw_with_password(&path, b"shared").unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11), "our write");
    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22), "qemu write");
}
