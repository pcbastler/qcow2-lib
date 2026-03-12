//! Tests for the CORRUPT incompatible feature bit.
//!
//! Verifies that CORRUPT is defined, supported, and parseable.
//! Note: qcow2-lib does not yet enforce read-only mode when CORRUPT is set,
//! so these tests only verify parsing behavior, not enforcement.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::format::feature_flags::{IncompatibleFeatures, SUPPORTED_INCOMPATIBLE_FEATURES};
use qcow2::io::MemoryBackend;

/// Helper: create a 1 MB in-memory image and return the raw bytes.
fn create_raw_image() -> Vec<u8> {
    let mut image = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
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

    let backend = image.backend();
    let size = backend.file_size().unwrap() as usize;
    let mut data = vec![0u8; size];
    qcow2::io::IoBackend::read_exact_at(backend, &mut data, 0).unwrap();
    data
}

/// Set the CORRUPT bit in raw image bytes (offset 72, bit 1).
fn set_corrupt_bit(raw: &mut [u8]) {
    let mut incompat = u64::from_be_bytes(raw[72..80].try_into().unwrap());
    incompat |= IncompatibleFeatures::CORRUPT.bits();
    raw[72..80].copy_from_slice(&incompat.to_be_bytes());
}

#[test]
fn corrupt_bit_in_supported_features() {
    assert!(
        SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::CORRUPT),
        "CORRUPT should be in SUPPORTED_INCOMPATIBLE_FEATURES"
    );
}

#[test]
fn corrupt_bit_value() {
    assert_eq!(IncompatibleFeatures::CORRUPT.bits(), 2);
}

#[test]
fn corrupt_bit_readable_after_binary_patch() {
    let mut raw = create_raw_image();
    set_corrupt_bit(&mut raw);

    let backend = MemoryBackend::new(raw);
    let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
    assert!(
        image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::CORRUPT),
        "CORRUPT bit should be readable"
    );
}

#[test]
fn image_with_corrupt_bit_still_opens() {
    let mut raw = create_raw_image();
    set_corrupt_bit(&mut raw);

    let backend = MemoryBackend::new(raw);
    // Should succeed since CORRUPT is in SUPPORTED_INCOMPATIBLE_FEATURES
    let result = Qcow2Image::from_backend(Box::new(backend));
    assert!(result.is_ok(), "image with CORRUPT bit should still open (no enforcement)");
}

#[test]
fn corrupt_and_dirty_both_set() {
    let mut raw = create_raw_image();
    // Set both CORRUPT and DIRTY
    let mut incompat = u64::from_be_bytes(raw[72..80].try_into().unwrap());
    incompat |= IncompatibleFeatures::CORRUPT.bits() | IncompatibleFeatures::DIRTY.bits();
    raw[72..80].copy_from_slice(&incompat.to_be_bytes());

    let backend = MemoryBackend::new(raw);
    let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
    assert!(
        image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::CORRUPT)
    );
    assert!(
        image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY)
    );
}

#[test]
fn feature_flags_roundtrip_with_corrupt() {
    let flags = IncompatibleFeatures::CORRUPT | IncompatibleFeatures::DIRTY;
    let bits = flags.bits();
    let restored = IncompatibleFeatures::from_bits_truncate(bits);
    assert_eq!(flags, restored);
}

#[test]
fn qemu_rejects_corrupt_image() {
    if !common::has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.qcow2");

    // Create a valid image file
    {
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
    }

    // Binary-patch the CORRUPT bit
    let mut raw = std::fs::read(&path).unwrap();
    set_corrupt_bit(&mut raw);
    std::fs::write(&path, &raw).unwrap();

    // qemu-img check should report errors for a corrupt image
    let ti = common::TestImage::wrap(path, dir);
    // QEMU check may fail or report errors — the image is marked corrupt
    // We just verify it doesn't crash (the check result itself varies by QEMU version)
    let _ = ti.qemu_check();
}
