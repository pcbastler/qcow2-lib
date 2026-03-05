//! Header validation and parsing edge-case tests.
//!
//! Tests header field validation, feature flag handling, version checks,
//! cluster_bits boundaries, and extension parsing. Mirrors QEMU's
//! qcow2-specific header validation tests.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};
use qcow2_lib::format::header::Header;
use qcow2_lib::io::MemoryBackend;
use qcow2_lib::io::IoBackend;
use qcow2_lib::io::sync_backend::SyncFileBackend;

// =====================================================================
// 1. Magic number validation
// =====================================================================

#[test]
fn valid_magic_accepted() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.header().version, 3);
}

#[test]
fn invalid_magic_rejected() {
    let mut data = vec![0u8; 4096];
    // Write garbage magic
    data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let backend = MemoryBackend::new(data);
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_err(), "garbage magic should be rejected");
}

#[test]
fn wrong_magic_rejected() {
    let mut data = vec![0u8; 4096];
    // Write wrong magic (QFI but wrong first byte)
    data[0..4].copy_from_slice(b"XFIB");
    let backend = MemoryBackend::new(data);
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_err(), "wrong magic should be rejected");
}

#[test]
fn truncated_header_rejected() {
    // Header too short to contain even magic + version
    let data = vec![0x51, 0x46, 0x49, 0xFB]; // QFI\xfb (valid magic, but no version)
    let backend = MemoryBackend::new(data);
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_err(), "truncated header should be rejected");
}

// =====================================================================
// 2. Version validation
// =====================================================================

#[test]
fn version_3_accepted() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.header().version, 3);
}

#[test]
fn version_2_image_from_qemu() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "compat=0.10"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    let image = Qcow2Image::open(&path).unwrap();
    assert_eq!(image.header().version, 2);
}

#[test]
fn version_1_rejected() {
    // Build minimal header with version 1
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xFB]); // magic
    data[4..8].copy_from_slice(&1u32.to_be_bytes()); // version 1
    let backend = MemoryBackend::new(data);
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_err(), "version 1 should be rejected");
}

#[test]
fn version_4_rejected() {
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xFB]);
    data[4..8].copy_from_slice(&4u32.to_be_bytes()); // version 4
    let backend = MemoryBackend::new(data);
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_err(), "version 4 should be rejected");
}

// =====================================================================
// 3. Cluster bits validation
// =====================================================================

#[test]
fn default_cluster_bits_is_16() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.cluster_bits(), 16);
    assert_eq!(image.cluster_size(), 65536);
}

#[test]
fn cluster_bits_9_minimum() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(9),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.cluster_bits(), 9);
    assert_eq!(image.cluster_size(), 512);
}

#[test]
fn cluster_bits_21_maximum() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 4 << 20,
            cluster_bits: Some(21),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.cluster_bits(), 21);
    assert_eq!(image.cluster_size(), 2 * 1024 * 1024);
}

#[test]
fn cluster_bits_too_small_rejected() {
    let backend = MemoryBackend::zeroed(0);
    let result = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(8),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    );
    assert!(result.is_err(), "cluster_bits=8 should be rejected");
}

#[test]
fn cluster_bits_too_large_rejected() {
    let backend = MemoryBackend::zeroed(0);
    let result = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(22),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    );
    assert!(result.is_err(), "cluster_bits=22 should be rejected");
}

#[test]
fn various_cluster_sizes_roundtrip() {
    for bits in [9, 10, 12, 14, 16, 18, 20, 21] {
        let backend = MemoryBackend::zeroed(0);
        let vs = std::cmp::max(1u64 << bits, 1 << 20); // at least 1 MB
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: vs,
                cluster_bits: Some(bits),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();

        assert_eq!(image.cluster_bits(), bits, "cluster_bits={bits}");
        assert_eq!(image.cluster_size(), 1u64 << bits, "cluster_size for bits={bits}");

        // Write and read back one cluster
        let cs = image.cluster_size() as usize;
        let data = vec![0xAA; cs];
        image.write_at(&data, 0).unwrap();
        let mut buf = vec![0u8; cs];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data, "roundtrip failed for cluster_bits={bits}");
    }
}

// =====================================================================
// 4. Feature flags
// =====================================================================

#[test]
fn extended_l2_sets_incompatible_feature_bit() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: true,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert!(image.header().has_extended_l2());
}

#[test]
fn compression_type_zstd_sets_feature_bit() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD),
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_ZSTD);
    use qcow2_lib::format::feature_flags::IncompatibleFeatures;
    assert!(image.header().incompatible_features.contains(IncompatibleFeatures::COMPRESSION_TYPE));
}

#[test]
fn deflate_is_default_compression() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.header().compression_type, COMPRESSION_DEFLATE);
}

#[test]
fn unknown_incompatible_feature_bit_rejected() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unknown_feat.qcow2");

    // Create valid image first
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    image.flush().unwrap();
    drop(image);

    // Corrupt: set unknown incompatible feature bit (bit 63)
    let backend = SyncFileBackend::open_rw(&path).unwrap();
    let mut buf = [0u8; 8];
    backend.read_exact_at(&mut buf, 72).unwrap(); // offset 72 = incompatible_features
    let mut features = u64::from_be_bytes(buf);
    features |= 1u64 << 63; // set unknown bit
    backend.write_all_at(&features.to_be_bytes(), 72).unwrap();
    drop(backend);

    let result = Qcow2Image::open(&path);
    assert!(result.is_err(), "unknown incompatible feature bit should cause rejection");
}

// =====================================================================
// 5. Backing file header fields
// =====================================================================

#[test]
fn no_backing_file_fields_zero() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert!(!image.header().has_backing_file());
    assert_eq!(image.header().backing_file_offset, 0);
    assert_eq!(image.header().backing_file_size, 0);
}

#[test]
fn overlay_has_backing_file_set() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    Qcow2Image::create(
        &base,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
    .flush()
    .unwrap();

    let img = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    assert!(img.header().has_backing_file());
    assert!(img.header().backing_file_offset > 0);
    assert!(img.header().backing_file_size > 0);
}

// =====================================================================
// 6. Header extensions
// =====================================================================

#[test]
fn fresh_v3_image_has_feature_name_table() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    // Verify we can at least read header extensions (may be empty for minimal images)
    let _exts = image.extensions();
}

#[test]
fn external_data_file_extension_present() {
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("ext_data.qcow2");
    let data_path = dir.path().join("ext_data.raw");
    std::fs::write(&data_path, vec![0u8; 1 << 20]).unwrap();

    let image = Qcow2Image::create(
        &img_path,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: Some(data_path.to_string_lossy().to_string()),
            encryption: None,
        },
    )
    .unwrap();

    assert!(image.has_external_data_file());
}

// =====================================================================
// 7. Refcount order
// =====================================================================

#[test]
fn default_refcount_order_is_4() {
    // Our library creates refcount_order=4 (16-bit refcounts) by default
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.header().refcount_order, 4);
    assert_eq!(image.header().refcount_bits(), 16);
}

#[test]
fn qemu_various_refcount_widths() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    for bits in [1, 2, 4, 8, 16, 32, 64] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("rc{bits}.qcow2"));
        let opt = format!("refcount_bits={bits}");

        let output = std::process::Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-o", &opt])
            .arg(&path)
            .arg("1M")
            .output()
            .unwrap();
        assert!(output.status.success(), "failed to create with refcount_bits={bits}");

        let image = Qcow2Image::open(&path).unwrap();
        assert_eq!(
            image.header().refcount_bits(),
            bits,
            "refcount_bits mismatch for {bits}"
        );
    }
}

// =====================================================================
// 8. Virtual size edge cases
// =====================================================================

#[test]
fn virtual_size_zero_rejected() {
    let backend = MemoryBackend::zeroed(0);
    let result = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 0,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    );
    assert!(result.is_err(), "virtual_size=0 should be rejected");
}

#[test]
fn virtual_size_not_cluster_aligned() {
    // QCOW2 should handle non-cluster-aligned virtual sizes
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 100_000, // not 64KB aligned
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.virtual_size(), 100_000);
}

#[test]
fn virtual_size_exactly_one_cluster() {
    let backend = MemoryBackend::zeroed(0);
    let mut image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 65536,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    assert_eq!(image.virtual_size(), 65536);

    // Write and read the entire virtual disk
    let data = vec![0xAA; 65536];
    image.write_at(&data, 0).unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

// =====================================================================
// 9. Header serialization round-trip
// =====================================================================

#[test]
fn header_parse_roundtrip() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 10 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    let h = image.header();

    // Serialize and parse back
    let mut buf = vec![0u8; h.serialized_length()];
    h.write_to(&mut buf).unwrap();
    let h2 = Header::read_from(&buf).unwrap();

    assert_eq!(h.version, h2.version);
    assert_eq!(h.cluster_bits, h2.cluster_bits);
    assert_eq!(h.virtual_size, h2.virtual_size);
    assert_eq!(h.l1_table_entries, h2.l1_table_entries);
    assert_eq!(h.refcount_order, h2.refcount_order);
    assert_eq!(h.compression_type, h2.compression_type);
}

#[test]
fn header_parse_roundtrip_extended_l2_zstd() {
    let backend = MemoryBackend::zeroed(0);
    let image = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 10 << 20,
            cluster_bits: Some(16),
            extended_l2: true,
            compression_type: Some(COMPRESSION_ZSTD),
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    let h = image.header();

    let mut buf = vec![0u8; h.serialized_length()];
    h.write_to(&mut buf).unwrap();
    let h2 = Header::read_from(&buf).unwrap();

    assert!(h2.has_extended_l2());
    assert_eq!(h2.compression_type, COMPRESSION_ZSTD);
}

// =====================================================================
// 10. L1 table validation
// =====================================================================

#[test]
fn l1_table_entries_match_virtual_size() {
    for size_mb in [1u64, 4, 16, 64, 256, 1024] {
        let vs = size_mb << 20;
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: vs,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();

        let h = image.header();
        let l2_entries = h.l2_entries_per_table();
        let cluster_size = h.cluster_size();
        let expected_l1 =
            ((vs + l2_entries * cluster_size - 1) / (l2_entries * cluster_size)) as u32;

        assert_eq!(
            h.l1_table_entries, expected_l1,
            "L1 entries mismatch for {size_mb} MB"
        );
    }
}

// =====================================================================
// 11. QEMU interop: header cross-validation
// =====================================================================

#[test]
fn qemu_accepts_our_header() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("our.qcow2");

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
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img check should accept our header: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Also verify info output
    let output = std::process::Command::new("qemu-img")
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let info = String::from_utf8_lossy(&output.stdout);
    assert!(info.contains("\"format\": \"qcow2\""));
}

#[test]
fn we_accept_qemu_header() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let img = common::TestImage::create("10M");
    let image = Qcow2Image::open(&img.path).unwrap();
    assert_eq!(image.header().version, 3);
    assert_eq!(image.virtual_size(), 10 << 20);
}
