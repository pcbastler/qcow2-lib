//! Detailed Extended L2 / subcluster tests.
//!
//! Tests subcluster-granular reads/writes, zero subclusters, COW at
//! subcluster level, mixed subcluster states, and QEMU interop.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const CS: usize = 65536;
const CSU: u64 = CS as u64;
const SC_SIZE: usize = CS / 32; // 2048 bytes per subcluster
const SC: u64 = SC_SIZE as u64;

fn create_ext_l2(vs: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: true,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

fn create_ext_l2_file(dir: &tempfile::TempDir, name: &str, vs: u64) -> Qcow2Image {
    Qcow2Image::create(
        &dir.path().join(name),
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: true,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

// =====================================================================
// 1. Basic subcluster operations
// =====================================================================

#[test]
fn write_single_subcluster() {
    let mut image = create_ext_l2(1 << 20);
    image.write_at(&vec![0xAA; SC_SIZE], 0).unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    // Next subcluster should be zeros
    image.read_at(&mut buf, SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

#[test]
fn write_multiple_subclusters() {
    let mut image = create_ext_l2(1 << 20);

    for i in 0u32..8 {
        let data = vec![(i as u8 + 1) * 0x10; SC_SIZE];
        image.write_at(&data, i as u64 * SC).unwrap();
    }

    for i in 0u32..8 {
        let mut buf = vec![0u8; SC_SIZE];
        image.read_at(&mut buf, i as u64 * SC).unwrap();
        assert!(
            buf.iter().all(|&b| b == (i as u8 + 1) * 0x10),
            "subcluster {i}"
        );
    }

    // Subclusters 8-31 should be zeros
    let mut buf = vec![0xFFu8; SC_SIZE];
    image.read_at(&mut buf, 8 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

#[test]
fn write_all_32_subclusters() {
    let mut image = create_ext_l2(1 << 20);

    for i in 0u32..32 {
        let data = vec![(i as u8) | 0x80; SC_SIZE];
        image.write_at(&data, i as u64 * SC).unwrap();
    }

    for i in 0u32..32 {
        let mut buf = vec![0u8; SC_SIZE];
        image.read_at(&mut buf, i as u64 * SC).unwrap();
        assert!(
            buf.iter().all(|&b| b == (i as u8) | 0x80),
            "subcluster {i}"
        );
    }
}

// =====================================================================
// 2. Subcluster-level partial writes
// =====================================================================

#[test]
fn partial_write_within_subcluster() {
    let mut image = create_ext_l2(1 << 20);

    image.write_at(&vec![0xAA; SC_SIZE], 0).unwrap();
    // Write 512 bytes in the middle of the first subcluster
    image.write_at(&vec![0xFF; 512], 256).unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..256].iter().all(|&b| b == 0xAA));
    assert!(buf[256..768].iter().all(|&b| b == 0xFF));
    assert!(buf[768..].iter().all(|&b| b == 0xAA));
}

#[test]
fn write_spanning_subcluster_boundary() {
    let mut image = create_ext_l2(1 << 20);

    image.write_at(&vec![0xAA; 2 * SC_SIZE], 0).unwrap();
    // Write spanning boundary between subcluster 0 and 1
    let start = SC - 256;
    image.write_at(&vec![0xFF; 512], start).unwrap();

    let mut buf = vec![0u8; 2 * SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..SC_SIZE - 256].iter().all(|&b| b == 0xAA));
    assert!(buf[SC_SIZE - 256..SC_SIZE + 256].iter().all(|&b| b == 0xFF));
    assert!(buf[SC_SIZE + 256..].iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 3. Zero subclusters
// =====================================================================

#[test]
fn zero_specific_subclusters() {
    let mut image = create_ext_l2(1 << 20);

    // Fill entire cluster
    image.write_at(&vec![0xBB; CS], 0).unwrap();
    // Zero subcluster 5
    image.write_at(&vec![0u8; SC_SIZE], 5 * SC).unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    // Subcluster 4: still 0xBB
    image.read_at(&mut buf, 4 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
    // Subcluster 5: zeros
    image.read_at(&mut buf, 5 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
    // Subcluster 6: still 0xBB
    image.read_at(&mut buf, 6 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

#[test]
fn zero_then_write_subcluster() {
    let mut image = create_ext_l2(1 << 20);

    image.write_at(&vec![0xCC; CS], 0).unwrap();
    image.write_at(&vec![0u8; SC_SIZE], 0).unwrap();
    image.write_at(&vec![0xDD; SC_SIZE], 0).unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

// =====================================================================
// 4. COW with extended L2
// =====================================================================

#[test]
fn snapshot_cow_at_subcluster_granularity() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_ext_l2_file(&dir, "cow.qcow2", 1 << 20);

    // Fill cluster with pattern
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Write single subcluster (triggers COW for whole cluster)
    image.write_at(&vec![0xBB; SC_SIZE], 3 * SC).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "untouched subcluster 0");
    image.read_at(&mut buf, 3 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "modified subcluster 3");

    // Revert
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 3 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "reverted subcluster 3");
}

// =====================================================================
// 5. Mixed subcluster states in one cluster
// =====================================================================

#[test]
fn mixed_allocated_and_unallocated_subclusters() {
    let mut image = create_ext_l2(1 << 20);

    // Write only even-numbered subclusters
    for i in (0u32..32).step_by(2) {
        image.write_at(&vec![0xAA; SC_SIZE], i as u64 * SC).unwrap();
    }

    let mut buf = vec![0u8; SC_SIZE];
    for i in 0u32..32 {
        image.read_at(&mut buf, i as u64 * SC).unwrap();
        if i % 2 == 0 {
            assert!(buf.iter().all(|&b| b == 0xAA), "even subcluster {i}");
        } else {
            assert!(buf.iter().all(|&b| b == 0x00), "odd subcluster {i}");
        }
    }
}

// =====================================================================
// 6. Extended L2 with backing chain
// =====================================================================

#[test]
fn ext_l2_overlay_subcluster_cow() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    let mut base_img = Qcow2Image::create(
        &base,
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
    base_img.write_at(&vec![0xAA; CS], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    // Write single subcluster in overlay
    ov.write_at(&vec![0xBB; SC_SIZE], 2 * SC).unwrap();
    ov.flush().unwrap();

    let mut buf = vec![0u8; SC_SIZE];
    // Subcluster 0: from base
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
    // Subcluster 2: overlay data
    ov.read_at(&mut buf, 2 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
    // Subcluster 3: from base (COW should preserve)
    ov.read_at(&mut buf, 3 * SC).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 7. Feature flags
// =====================================================================

#[test]
fn extended_l2_feature_bit_set() {
    let image = create_ext_l2(1 << 20);
    assert!(image.header().has_extended_l2());
    use qcow2::format::feature_flags::IncompatibleFeatures;
    assert!(image.header().incompatible_features.contains(IncompatibleFeatures::EXTENDED_L2));
}

#[test]
fn l2_entry_size_is_16_bytes() {
    let image = create_ext_l2(1 << 20);
    assert_eq!(image.header().l2_entry_size(), 16);
}

#[test]
fn subcluster_size_is_cluster_div_32() {
    let image = create_ext_l2(1 << 20);
    assert_eq!(image.header().subcluster_size(), Some(SC));
}

// =====================================================================
// 8. Integrity
// =====================================================================

#[test]
fn integrity_clean_with_extended_l2() {
    let dir = tempfile::tempdir().unwrap();
    let mut image = create_ext_l2_file(&dir, "int.qcow2", 4 * CSU);

    // Write various patterns to subclusters
    for i in 0u32..8 {
        image.write_at(&vec![(i as u8 + 1) * 0x10; SC_SIZE], i as u64 * SC).unwrap();
    }
    image.write_at(&vec![0xFF; CS], CSU).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "ext l2 integrity: {report:?}");
}

// =====================================================================
// 9. QEMU interop
// =====================================================================

#[test]
fn qemu_check_our_extended_l2_image() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_ext_l2.qcow2");

    let mut image = Qcow2Image::create(
        &path,
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

    // Write a few subclusters
    image.write_at(&vec![0xAA; SC_SIZE], 0).unwrap();
    image.write_at(&vec![0xBB; SC_SIZE], 5 * SC).unwrap();
    image.flush().unwrap();
    drop(image);

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn qemu_reads_our_subclusters() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_sc.qcow2");

    let mut image = Qcow2Image::create(
        &path,
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
    image.write_at(&vec![0xCC; SC_SIZE], 3 * SC).unwrap();
    image.flush().unwrap();
    drop(image);

    let ti = common::TestImage::wrap(path, dir);
    let data = ti.read_via_qemu(3 * SC, 512);
    assert!(data.iter().all(|&b| b == 0xCC));

    // Unwritten subcluster should be zeros
    let zeros = ti.read_via_qemu(0, 512);
    assert!(zeros.iter().all(|&b| b == 0x00));
}

#[test]
fn we_read_qemu_extended_l2_image() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemu_created.qcow2");

    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-o", "extended_l2=on"])
        .arg(&path)
        .arg("1M")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Write data with qemu-io
    let write_cmd = format!("write -P 0xDD 0 {SC_SIZE}");
    let output = std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", &write_cmd])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut image = Qcow2Image::open(&path).unwrap();
    assert!(image.header().has_extended_l2());

    let mut buf = vec![0u8; SC_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}
