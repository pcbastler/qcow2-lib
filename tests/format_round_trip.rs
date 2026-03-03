//! Integration tests: cross-module format round-trips.
//!
//! Verifies that our format parsing produces correct results
//! when reading headers and metadata from qemu-img-created images.

mod common;

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::format::header::Header;
use qcow2_lib::io::sync_backend::SyncFileBackend;
use qcow2_lib::io::IoBackend;

#[test]
fn parse_header_from_real_image() {
    let img = common::TestImage::create("1G");

    let backend = SyncFileBackend::open(&img.path).unwrap();
    let mut buf = vec![0u8; 512];
    backend.read_exact_at(&mut buf, 0).unwrap();

    let header = Header::read_from(&buf).unwrap();
    assert_eq!(header.version, 3);
    assert_eq!(header.virtual_size, 1 << 30);
    assert!(header.cluster_bits >= 9);
    assert_eq!(header.crypt_method, 0);
}

#[test]
fn header_round_trip_preserves_data() {
    let img = common::TestImage::create("100M");

    let backend = SyncFileBackend::open(&img.path).unwrap();
    let mut original = vec![0u8; 512];
    backend.read_exact_at(&mut original, 0).unwrap();

    let header = Header::read_from(&original).unwrap();

    // Serialize and re-parse
    let mut serialized = vec![0u8; header.header_length as usize];
    header.write_to(&mut serialized).unwrap();
    let reparsed = Header::read_from(&serialized).unwrap();

    assert_eq!(header, reparsed);

    // Verify byte-level identity with qemu-img output
    assert_eq!(
        serialized,
        &original[..serialized.len()],
        "serialized header should be byte-identical to qemu-img output"
    );
}

#[test]
fn image_with_small_cluster_size() {
    let img = common::TestImage::create_with_cluster_size("1M", 4096);
    let image = Qcow2Image::open(&img.path).unwrap();

    assert_eq!(image.cluster_size(), 4096);
    assert_eq!(image.cluster_bits(), 12);

    // Should still be able to read zeros
    let mut buf = vec![0xFFu8; 1024];
    let mut image = Qcow2Image::open(&img.path).unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn image_with_large_cluster_size() {
    // 256 KiB clusters
    let img = common::TestImage::create_with_cluster_size("10M", 262144);
    let image = Qcow2Image::open(&img.path).unwrap();

    assert_eq!(image.cluster_size(), 262144);
    assert_eq!(image.cluster_bits(), 18);
}
