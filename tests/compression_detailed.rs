//! Detailed compression edge-case tests.
//!
//! Covers round-trip for deflate and zstd, mixed compressed/uncompressed
//! clusters, COW interactions, snapshot integration, and QEMU interop.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};

const CLUSTER_SIZE: usize = 65536;
const CS: u64 = CLUSTER_SIZE as u64;
const IMAGE_SIZE: u64 = 4 * 1024 * 1024;

fn create_image(dir: &tempfile::TempDir, name: &str, ct: Option<u8>) -> Qcow2Image {
    let path = dir.path().join(name);
    Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: ct,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

// =====================================================================
// 1. Basic compression round-trip
// =====================================================================

#[test]
fn deflate_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "deflate.qcow2", None);
    let data = vec![0xAA; CLUSTER_SIZE];
    image.write_cluster_maybe_compressed(&data, 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn zstd_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "zstd.qcow2", Some(COMPRESSION_ZSTD));
    let data = vec![0xBB; CLUSTER_SIZE];
    image.write_cluster_maybe_compressed(&data, 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn multiple_compressed_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "multi.qcow2", None);

    for i in 0u64..4 {
        let data = vec![(0x10 + i as u8); CLUSTER_SIZE];
        image.write_cluster_maybe_compressed(&data, i * CS).unwrap();
    }
    image.flush().unwrap();

    for i in 0u64..4 {
        let mut buf = vec![0u8; CLUSTER_SIZE];
        image.read_at(&mut buf, i * CS).unwrap();
        assert!(buf.iter().all(|&b| b == (0x10 + i as u8)));
    }
}

// =====================================================================
// 2. Compression properties
// =====================================================================

#[test]
fn compressible_data_shrinks_deflate() {
    let data = vec![0u8; CLUSTER_SIZE];
    let compressed =
        qcow2::engine::compression::compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
            .unwrap();
    let compressed = compressed.expect("zeros must compress");
    assert!(compressed.len() < CLUSTER_SIZE / 8, "zeros should compress well: {} bytes", compressed.len());
}

#[test]
fn compressible_data_shrinks_zstd() {
    let data: Vec<u8> = (0..CLUSTER_SIZE).map(|i| (i % 4) as u8).collect();
    let compressed =
        qcow2::engine::compression::compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_ZSTD)
            .unwrap();
    let compressed = compressed.expect("repeating pattern must compress");
    assert!(compressed.len() < CLUSTER_SIZE / 4, "pattern should compress: {} bytes", compressed.len());
}

#[test]
fn incompressible_data_still_readable() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "random.qcow2", None);

    // Pseudo-random data that won't compress
    let mut val = 0xDEADBEEFu32;
    let data: Vec<u8> = (0..CLUSTER_SIZE)
        .map(|_| {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            (val >> 16) as u8
        })
        .collect();

    image.write_cluster_maybe_compressed(&data, 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

// =====================================================================
// 3. Mixed compressed / uncompressed
// =====================================================================

#[test]
fn mixed_compressed_and_uncompressed() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "mixed.qcow2", None);

    image.write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE], CS).unwrap();
    image.write_cluster_maybe_compressed(&vec![0xCC; CLUSTER_SIZE], 2 * CS).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
    image.read_at(&mut buf, CS).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
    image.read_at(&mut buf, 2 * CS).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}

#[test]
fn overwrite_compressed_with_uncompressed() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "over.qcow2", None);

    image.write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

#[test]
fn overwrite_uncompressed_with_compressed() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "over2.qcow2", None);

    image.write_at(&vec![0x11; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.write_cluster_maybe_compressed(&vec![0x22; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22));
}

// =====================================================================
// 4. COW with compressed clusters
// =====================================================================

#[test]
fn cow_partial_write_into_compressed() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "cow.qcow2", None);

    image.write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xFF; 128], 256).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..256].iter().all(|&b| b == 0xAA));
    assert!(buf[256..384].iter().all(|&b| b == 0xFF));
    assert!(buf[384..].iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 5. Compression with snapshots
// =====================================================================

#[test]
fn compressed_data_survives_snapshot_revert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    image.write_cluster_maybe_compressed(&vec![0xAB; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0xCD; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();

    image.snapshot_apply("s1").unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAB));
}

#[test]
fn compressed_survives_create_delete_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cycle.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    image.write_cluster_maybe_compressed(&vec![0x77; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("temp").unwrap();
    image.snapshot_delete("temp").unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77));
}

// =====================================================================
// 6. Many adjacent compressed clusters
// =====================================================================

#[test]
fn many_adjacent_compressed() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_image(&dir, "adjacent.qcow2", None);

    for i in 0u64..16 {
        image
            .write_cluster_maybe_compressed(&vec![(i & 0xFF) as u8; CLUSTER_SIZE], i * CS)
            .unwrap();
    }
    image.flush().unwrap();

    for i in 0u64..16 {
        let mut buf = vec![0u8; CLUSTER_SIZE];
        image.read_at(&mut buf, i * CS).unwrap();
        assert!(buf.iter().all(|&b| b == (i & 0xFF) as u8), "cluster {i}");
    }
}

// =====================================================================
// 7. Integrity with compressed clusters
// =====================================================================

#[test]
fn integrity_passes_with_compressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("int.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    image.write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_cluster_maybe_compressed(&vec![0xBB; CLUSTER_SIZE], CS).unwrap();
    image.write_at(&vec![0xCC; CLUSTER_SIZE], 2 * CS).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "integrity: {report:?}");
}

#[test]
fn integrity_passes_zstd() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd_int.qcow2");
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: IMAGE_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(COMPRESSION_ZSTD),
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    image.write_cluster_maybe_compressed(&vec![0xDD; CLUSTER_SIZE], 0).unwrap();
    image.write_cluster_maybe_compressed(&vec![0xEE; CLUSTER_SIZE], CS).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "zstd integrity: {report:?}");
}

// =====================================================================
// 8. Reopen round-trip
// =====================================================================

#[test]
fn reopen_compressed_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reopen.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_cluster_maybe_compressed(&vec![0x99; CLUSTER_SIZE], 0).unwrap();
        image.write_at(&vec![0x88; CLUSTER_SIZE], CS).unwrap();
        image.flush().unwrap();
    }

    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x99));
    image.read_at(&mut buf, CS).unwrap();
    assert!(buf.iter().all(|&b| b == 0x88));
}

// =====================================================================
// 9. QEMU interop
// =====================================================================

#[test]
fn qemu_reads_our_deflate_compressed() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lib_comp.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: IMAGE_SIZE,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();
        image.write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
        image.flush().unwrap();
    }

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "qemu-img check: {}", String::from_utf8_lossy(&output.stderr));

    let ti = common::TestImage::wrap(path, dir);
    let data = ti.read_via_qemu(0, 512);
    assert!(data.iter().all(|&b| b == 0xAA));
}

#[test]
fn library_reads_qemu_compressed() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let source = common::TestImage::create("4M");
    source.write_pattern(0xDD, 0, CLUSTER_SIZE);

    let dir = tempfile::tempdir().unwrap();
    let compressed = dir.path().join("qemu_comp.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed)
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut image = Qcow2Image::open(&compressed).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}
