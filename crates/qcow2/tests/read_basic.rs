//! Integration tests: read from qemu-img-created images.
//!
//! These tests create real QCOW2 images using qemu-img/qemu-io,
//! then read them with our library to verify correctness.

mod common;

use qcow2::engine::image::Qcow2Image;

#[test]
fn read_empty_image_returns_zeros() {
    let img = common::TestImage::create("1M");
    let mut image = Qcow2Image::open(&img.path).unwrap();

    let mut buf = vec![0xFFu8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0),
        "empty image should read as all zeros"
    );
}

#[test]
fn read_written_data_matches() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    img.write_pattern(0xAB, 0, 4096);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xAB),
        "should read back the written pattern 0xAB"
    );
}

#[test]
fn read_at_offset_within_cluster() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    // Write pattern at offset 512 within the first cluster
    img.write_pattern(0xCD, 512, 512);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    // Read the region before the pattern (should be zeros from qemu-io write filling the cluster)
    let mut before = vec![0xFFu8; 512];
    image.read_at(&mut before, 0).unwrap();
    assert!(
        before.iter().all(|&b| b == 0),
        "bytes before pattern should be zero"
    );

    // Read the pattern itself
    let mut pattern = vec![0u8; 512];
    image.read_at(&mut pattern, 512).unwrap();
    assert!(
        pattern.iter().all(|&b| b == 0xCD),
        "should read back 0xCD at offset 512"
    );
}

#[test]
fn read_spanning_cluster_boundary() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    let cluster_size = 65536u64; // default qemu-img cluster size

    // Write different patterns to two adjacent clusters
    img.write_pattern(0xAA, 0, cluster_size as usize);
    img.write_pattern(0xBB, cluster_size, cluster_size as usize);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    // Read 1024 bytes spanning the boundary
    let read_offset = cluster_size - 512;
    let mut buf = vec![0u8; 1024];
    image.read_at(&mut buf, read_offset).unwrap();

    assert!(
        buf[..512].iter().all(|&b| b == 0xAA),
        "first half should be 0xAA"
    );
    assert!(
        buf[512..].iter().all(|&b| b == 0xBB),
        "second half should be 0xBB"
    );
}

#[test]
fn header_metadata_is_correct() {
    let img = common::TestImage::create("1G");
    let image = Qcow2Image::open(&img.path).unwrap();

    assert_eq!(image.header().version, 3);
    assert_eq!(image.virtual_size(), 1 << 30);
    assert!(image.cluster_bits() >= 9);
    assert!(image.cluster_bits() <= 21);
    assert!(image.backing_chain().is_none());
}

#[test]
fn custom_cluster_size() {
    let img = common::TestImage::create_with_cluster_size("1M", 16384);
    let image = Qcow2Image::open(&img.path).unwrap();

    assert_eq!(image.cluster_size(), 16384);
    assert_eq!(image.cluster_bits(), 14);
}

#[test]
fn qemu_check_passes_for_fresh_image() {
    let img = common::TestImage::create("1M");
    assert!(img.qemu_check(), "fresh image should pass qemu-img check");
}

#[test]
fn read_multiple_scattered_regions() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    let cluster_size = 65536u64;

    // Write to clusters 0, 5, and 10
    img.write_pattern(0x11, 0, 4096);
    img.write_pattern(0x55, 5 * cluster_size, 4096);
    img.write_pattern(0xAA, 10 * cluster_size, 4096);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    let mut buf = vec![0u8; 4096];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));

    image.read_at(&mut buf, 5 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0x55));

    image.read_at(&mut buf, 10 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));

    // Unwritten region should be zeros
    image.read_at(&mut buf, 3 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

// ---- Extended integration tests ----

#[test]
fn sparse_image_reads_zeros() {
    // 1 GB virtual image with only 1 cluster written.
    // All other regions should read as zeros.
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("1G");
    // Write just one cluster
    img.write_pattern(0x42, 0, 65536);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    // The written cluster reads correctly
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x42));

    // Far-away unwritten region reads zeros
    let far_offset = 512 * 1024 * 1024; // 512 MB
    image.read_at(&mut buf, far_offset).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "sparse region should be zeros");
}

#[test]
fn read_last_byte_of_virtual_disk() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("1M");
    let mut image = Qcow2Image::open(&img.path).unwrap();
    let vs = image.virtual_size();

    // Read 1 byte at the very last position
    let mut buf = vec![0xFFu8; 1];
    image.read_at(&mut buf, vs - 1).unwrap();
    assert_eq!(buf[0], 0, "last byte of unwritten image should be zero");
}

#[test]
fn cross_validate_with_qemu_io() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = common::TestImage::create("10M");
    let cluster_size = 65536u64;

    // Write various patterns
    img.write_pattern(0xDE, 0, 512);
    img.write_pattern(0xAD, cluster_size, 512);
    img.write_pattern(0xBE, 5 * cluster_size + 100, 512);

    let mut image = Qcow2Image::open(&img.path).unwrap();

    // Read with our library and with qemu-io, then compare byte-for-byte
    let offsets: &[(u64, usize)] = &[
        (0, 512),
        (cluster_size, 512),
        (5 * cluster_size + 100, 512),
    ];

    for &(offset, len) in offsets {
        let mut our_buf = vec![0u8; len];
        image.read_at(&mut our_buf, offset).unwrap();

        let qemu_buf = img.read_via_qemu(offset, len);

        assert_eq!(
            our_buf, qemu_buf,
            "mismatch at offset 0x{offset:x}, length {len}"
        );
    }
}

#[test]
fn image_with_cluster_size_2m() {
    // cluster_bits=21 → 2 MB clusters
    let img = common::TestImage::create_with_cluster_size("4M", 2 * 1024 * 1024);
    let image = Qcow2Image::open(&img.path).unwrap();

    assert_eq!(image.cluster_size(), 2 * 1024 * 1024);
    assert_eq!(image.cluster_bits(), 21);
}

#[test]
fn read_beyond_virtual_size_fails() {
    let img = common::TestImage::create("1M");
    let mut image = Qcow2Image::open(&img.path).unwrap();
    let vs = image.virtual_size();

    let mut buf = vec![0u8; 512];
    let result = image.read_at(&mut buf, vs);
    assert!(result.is_err(), "reading at virtual_size should fail");

    let result = image.read_at(&mut buf, vs - 256);
    assert!(result.is_err(), "reading past virtual_size should fail");
}
