//! Integration tests: write-zeroes semantics.
//!
//! QCOW2 v3 distinguishes between unallocated and zero clusters at the L2
//! level. Writing a buffer of all zeros through `write_at` should still produce
//! correct reads. These tests exercise zero-buffer writes against fresh,
//! allocated, compressed, and backing-file-backed clusters.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const CLUSTER_SIZE: u64 = 65536;

fn create_mem_image(virtual_size: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

fn assert_reads_zeros(image: &mut Qcow2Image, offset: u64, len: usize) {
    let mut buf = vec![0xFFu8; len];
    image.read_at(&mut buf, offset).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0),
        "expected zeros at {offset:#x} len {len}"
    );
}

fn assert_reads_pattern(image: &mut Qcow2Image, offset: u64, len: usize, pattern: u8) {
    let mut buf = vec![0u8; len];
    image.read_at(&mut buf, offset).unwrap();
    assert!(
        buf.iter().all(|&b| b == pattern),
        "expected 0x{pattern:02x} at {offset:#x} len {len}"
    );
}

// =====================================================================
// 1. Basic zero-write semantics
// =====================================================================

#[test]
fn write_zeros_to_unallocated_reads_zeros() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

#[test]
fn write_zeros_to_allocated_reads_zeros() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

#[test]
fn write_zeros_then_data_reads_data() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_pattern(&mut image, 0, CLUSTER_SIZE as usize, 0xBB);
}

#[test]
fn data_then_zeros_then_read() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0xCC; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

// =====================================================================
// 2. Cluster-aligned zero writes
// =====================================================================

#[test]
fn multiple_full_clusters_zero() {
    let mut image = create_mem_image(4 * CLUSTER_SIZE);
    for i in 0..3u64 {
        image.write_at(&vec![0xEE; CLUSTER_SIZE as usize], i * CLUSTER_SIZE).unwrap();
    }
    image.write_at(&vec![0u8; 3 * CLUSTER_SIZE as usize], 0).unwrap();
    for i in 0..3u64 {
        assert_reads_zeros(&mut image, i * CLUSTER_SIZE, CLUSTER_SIZE as usize);
    }
}

#[test]
fn zero_spanning_partial_full_partial() {
    let mut image = create_mem_image(4 * CLUSTER_SIZE);
    for i in 0..3u64 {
        image.write_at(&vec![0x11; CLUSTER_SIZE as usize], i * CLUSTER_SIZE).unwrap();
    }
    let start = CLUSTER_SIZE / 2;
    let len = 2 * CLUSTER_SIZE;
    image.write_at(&vec![0u8; len as usize], start).unwrap();

    assert_reads_pattern(&mut image, 0, (CLUSTER_SIZE / 2) as usize, 0x11);
    assert_reads_zeros(&mut image, start, len as usize);
    assert_reads_pattern(
        &mut image,
        start + len,
        (CLUSTER_SIZE / 2) as usize,
        0x11,
    );
}

// =====================================================================
// 3. Unaligned zero writes
// =====================================================================

#[test]
fn zero_write_unaligned_head() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0x22; CLUSTER_SIZE as usize], 0).unwrap();
    let offset = 1000u64;
    let len = CLUSTER_SIZE as usize - offset as usize;
    image.write_at(&vec![0u8; len], offset).unwrap();
    assert_reads_pattern(&mut image, 0, 1000, 0x22);
    assert_reads_zeros(&mut image, offset, len);
}

#[test]
fn zero_write_unaligned_tail() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0x33; CLUSTER_SIZE as usize], 0).unwrap();
    let len = 5000usize;
    image.write_at(&vec![0u8; len], 0).unwrap();
    assert_reads_zeros(&mut image, 0, len);
    assert_reads_pattern(&mut image, len as u64, CLUSTER_SIZE as usize - len, 0x33);
}

#[test]
fn zero_write_middle_of_cluster() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0x44; CLUSTER_SIZE as usize], 0).unwrap();
    let start = 4096u64;
    let len = 8192usize;
    image.write_at(&vec![0u8; len], start).unwrap();
    assert_reads_pattern(&mut image, 0, start as usize, 0x44);
    assert_reads_zeros(&mut image, start, len);
    assert_reads_pattern(
        &mut image,
        start + len as u64,
        CLUSTER_SIZE as usize - start as usize - len,
        0x44,
    );
}

#[test]
fn zero_write_one_byte() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0xFF; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&[0u8], 100).unwrap();
    let mut buf = [0xFFu8; 1];
    image.read_at(&mut buf, 100).unwrap();
    assert_eq!(buf[0], 0);
    assert_reads_pattern(&mut image, 0, 100, 0xFF);
    assert_reads_pattern(&mut image, 101, CLUSTER_SIZE as usize - 101, 0xFF);
}

// =====================================================================
// 4. Cross-cluster boundary
// =====================================================================

#[test]
fn zero_write_cross_cluster_boundary() {
    let mut image = create_mem_image(4 * CLUSTER_SIZE);
    image.write_at(&vec![0x66; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0x77; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
    let start = CLUSTER_SIZE - 4096;
    let len = 8192usize;
    image.write_at(&vec![0u8; len], start).unwrap();
    assert_reads_pattern(&mut image, 0, (CLUSTER_SIZE - 4096) as usize, 0x66);
    assert_reads_zeros(&mut image, start, len);
    assert_reads_pattern(
        &mut image,
        start + len as u64,
        CLUSTER_SIZE as usize - 4096,
        0x77,
    );
}

#[test]
fn zero_write_entire_disk() {
    let vs = 4 * CLUSTER_SIZE;
    let mut image = create_mem_image(vs);
    for i in 0..4u64 {
        image.write_at(&vec![0x88; CLUSTER_SIZE as usize], i * CLUSTER_SIZE).unwrap();
    }
    image.write_at(&vec![0u8; vs as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, vs as usize);
}

// =====================================================================
// 5. Backing file interaction
// =====================================================================

#[test]
fn backing_data_hidden_by_zero_write() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    let mut base_img = Qcow2Image::create(
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
    .unwrap();
    base_img.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    ov.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    ov.flush().unwrap();
    assert_reads_zeros(&mut ov, 0, CLUSTER_SIZE as usize);
}

#[test]
fn backing_data_partial_zero() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    let mut base_img = Qcow2Image::create(
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
    .unwrap();
    base_img.write_at(&vec![0xBB; CLUSTER_SIZE as usize], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let half = (CLUSTER_SIZE / 2) as usize;
    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    ov.write_at(&vec![0u8; half], 0).unwrap();
    ov.flush().unwrap();
    assert_reads_zeros(&mut ov, 0, half);
    assert_reads_pattern(&mut ov, CLUSTER_SIZE / 2, half, 0xBB);
}

// =====================================================================
// 6. Extended L2 / subclusters
// =====================================================================

#[test]
fn extended_l2_zero_write_full_cluster() {
    let mut image = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
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

    image.write_at(&vec![0x99; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

#[test]
fn extended_l2_zero_single_subcluster() {
    let mut image = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
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

    let sc_size = CLUSTER_SIZE as usize / 32;
    image.write_at(&vec![0xAA; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; sc_size], sc_size as u64).unwrap();

    assert_reads_pattern(&mut image, 0, sc_size, 0xAA);
    assert_reads_zeros(&mut image, sc_size as u64, sc_size);
    assert_reads_pattern(&mut image, 2 * sc_size as u64, sc_size, 0xAA);
}

// =====================================================================
// 7. Idempotency
// =====================================================================

#[test]
fn zero_write_idempotent_on_unallocated() {
    let mut image = create_mem_image(1 << 20);
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

#[test]
fn double_zero_write_idempotent() {
    let mut image = create_mem_image(1 << 20);
    image.write_at(&vec![0xDD; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 0).unwrap();
    assert_reads_zeros(&mut image, 0, CLUSTER_SIZE as usize);
}

// =====================================================================
// 8. Integrity after zero writes
// =====================================================================

#[test]
fn integrity_ok_after_zero_writes() {
    let mut image = create_mem_image(4 * CLUSTER_SIZE);
    for i in 0..4u64 {
        image.write_at(&vec![0xCC; CLUSTER_SIZE as usize], i * CLUSTER_SIZE).unwrap();
    }
    image.write_at(&vec![0u8; 2 * CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
    image.flush().unwrap();
    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "integrity should pass: {report:?}");
}

// =====================================================================
// 9. QEMU interop
// =====================================================================

#[test]
fn qemu_reads_our_zero_written_cluster() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zero_test.qcow2");

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
    image.write_at(&vec![0xEE; 4096], 0).unwrap();
    image.write_at(&vec![0u8; 4096], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    let img = common::TestImage::wrap(path, dir);
    let data = img.read_via_qemu(0, 4096);
    assert!(
        data.iter().all(|&b| b == 0),
        "qemu should read zeros from our zero-written cluster"
    );
}

#[test]
fn qemu_check_after_zero_overwrites() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("check_zero.qcow2");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 * CLUSTER_SIZE,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    for i in 0..4u64 {
        image.write_at(&vec![0xAB; CLUSTER_SIZE as usize], i * CLUSTER_SIZE).unwrap();
    }
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], CLUSTER_SIZE).unwrap();
    image.write_at(&vec![0u8; CLUSTER_SIZE as usize], 3 * CLUSTER_SIZE).unwrap();
    image.flush().unwrap();
    drop(image);

    let img = common::TestImage::wrap(path, dir);
    assert!(img.qemu_check(), "qemu-img check should pass after zero overwrites");
}
