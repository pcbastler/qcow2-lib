//! Detailed compression edge-case tests.
//!
//! Covers round-trip for deflate and zstd, mixed compressed/uncompressed
//! clusters, COW interactions, snapshot integration, and QEMU interop.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::format::compressed::CompressedClusterDescriptor;
use qcow2::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD, L2_COMPRESSED_FLAG};

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
        let data = vec![0x10 + i as u8; CLUSTER_SIZE];
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
    image.write_at(&[0xFF; 128], 256).unwrap();
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

/// Regression test: QEMU packs compressed clusters at byte granularity,
/// so host_offset can be non-512-aligned. The actual compressed data size
/// is `nb_csectors * 512 - (host_offset & 511)` (QEMU formula), but
/// qcow2-lib was computing `nb_csectors * 512` — up to 511 bytes too much.
///
/// This test writes many clusters with different patterns (to get varying
/// compressed sizes that don't land on sector boundaries), converts with
/// `qemu-img convert -c`, then reads every cluster back through our library.
#[test]
fn library_reads_qemu_compressed_packed_non_aligned() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    // Write 32 clusters with distinct patterns to produce varied compressed
    // sizes — QEMU will pack them at byte granularity, creating non-aligned
    // host offsets after the first cluster.
    let num_clusters = 32u64;
    let source = common::TestImage::create("4M");
    for i in 0..num_clusters {
        // Each cluster gets a different repeating 2-byte pattern so the
        // deflate output varies in size (not all identical).
        let pattern = (0x10 + i) as u8;
        source.write_pattern(pattern, i * CS, CLUSTER_SIZE);
    }

    let dir = tempfile::tempdir().unwrap();
    let compressed = dir.path().join("qemu_packed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img convert -c failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // Read every cluster back through our library and verify contents
    let mut image = Qcow2Image::open(&compressed).unwrap();
    let mut buf = vec![0u8; CLUSTER_SIZE];
    for i in 0..num_clusters {
        let expected = (0x10 + i) as u8;
        image.read_at(&mut buf, i * CS).unwrap();
        assert!(
            buf.iter().all(|&b| b == expected),
            "cluster {i}: expected 0x{expected:02x}, got first divergence at byte {}",
            buf.iter().position(|&b| b != expected).unwrap_or(0),
        );
    }
}

/// Verify the intra-sector correction on a byte-granularity packed image.
///
/// The on-disk sector count is an upper bound — the format cannot encode
/// the exact compressed byte count. But for non-aligned host offsets, the
/// correction `- (host_offset % 512)` must be applied so that
/// `host_offset + compressed_size` lands on a sector boundary. Without the
/// correction it would overshoot by `host_offset % 512` bytes.
#[test]
fn compressed_descriptor_non_aligned_ends_on_sector_boundary() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let num_clusters = 32u64;
    let source = common::TestImage::create("4M");
    for i in 0..num_clusters {
        let pattern = (0x10 + i) as u8;
        source.write_pattern(pattern, i * CS, CLUSTER_SIZE);
    }

    let dir = tempfile::tempdir().unwrap();
    let compressed_path = dir.path().join("qemu_packed.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["convert", "-c", "-f", "qcow2", "-O", "qcow2"])
        .arg(&source.path)
        .arg(&compressed_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let image = Qcow2Image::open(&compressed_path).unwrap();
    let header = image.header();
    let cluster_bits = header.cluster_bits;
    let cluster_size = 1u64 << cluster_bits;
    let backend = image.backend();

    // Read L1 table to find L2 offset
    let mut l1_buf = vec![0u8; 8];
    backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0).unwrap();
    let l2_offset = u64::from_be_bytes(l1_buf[..8].try_into().unwrap()) & 0x00FF_FFFF_FFFF_FE00;

    // Read the L2 table
    let mut l2_buf = vec![0u8; cluster_size as usize];
    backend.read_exact_at(&mut l2_buf, l2_offset).unwrap();

    // Decode all compressed descriptors
    let mut descriptors = Vec::new();
    for i in 0..num_clusters as usize {
        let raw = u64::from_be_bytes(l2_buf[i * 8..(i + 1) * 8].try_into().unwrap());
        assert!(raw & L2_COMPRESSED_FLAG != 0, "cluster {i} should be compressed");
        let raw_no_flag = raw & !L2_COMPRESSED_FLAG;
        let desc = CompressedClusterDescriptor::decode(raw_no_flag, cluster_bits);
        descriptors.push((i, desc));
    }

    // Precondition: the image must have non-aligned offsets.
    let non_aligned: Vec<_> = descriptors.iter()
        .filter(|(_, d)| d.host_offset % 512 != 0)
        .collect();
    assert!(
        !non_aligned.is_empty(),
        "expected non-aligned compressed offsets from byte-granularity packing, \
         but all {} descriptors are sector-aligned — test precondition not met",
        descriptors.len(),
    );

    // Invariant: host_offset + compressed_size must be sector-aligned.
    // The sector count covers whole sectors from the boundary at/before
    // host_offset, so the described range always ends on a sector boundary.
    let mut violations = Vec::new();
    for &(i, ref desc) in &non_aligned {
        let end = desc.host_offset + desc.compressed_size;
        if end % 512 != 0 {
            violations.push((i, desc.host_offset, desc.compressed_size, end));
        }
    }

    assert!(
        violations.is_empty(),
        "host_offset + compressed_size is not sector-aligned for {} descriptors:\n{}",
        violations.len(),
        violations.iter()
            .take(5)
            .map(|(i, off, sz, end)| format!(
                "  cluster {i}: host=0x{off:x} size={sz} end=0x{end:x} (end % 512 = {})",
                end % 512
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
