//! Tests for the dirty-bit lifecycle and autoclear bit interactions.
//!
//! Verifies that DIRTY is set on first write, cleared on flush,
//! and that autoclear bits (BITMAPS, BLAKE3_HASHES) are managed correctly.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use qcow2::io::MemoryBackend;


/// Helper: create a 1 MB in-memory image.
fn mem_image() -> Qcow2Image {
    Qcow2Image::create_on_backend(
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
    .unwrap()
}

/// Helper: create a 1 MB file-based image, returns (image, path, _tempdir-guard).
fn file_image() -> (Qcow2Image, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.qcow2");
    let image = Qcow2Image::create(
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
    (image, path, dir)
}

/// Helper: extract raw bytes from a MemoryBackend-based image.
fn extract_raw(image: &Qcow2Image) -> Vec<u8> {
    let backend = image.backend();
    let size = backend.file_size().unwrap() as usize;
    let mut data = vec![0u8; size];
    qcow2::io::IoBackend::read_exact_at(backend, &mut data, 0).unwrap();
    data
}

// ---- Basic dirty-bit lifecycle ----

#[test]
fn fresh_image_not_dirty() {
    let image = mem_image();
    assert!(!image.is_dirty());
    assert!(
        !image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY)
    );
}

#[test]
fn write_sets_dirty() {
    let mut image = mem_image();
    image.write_at(&[0xAA; 64], 0).unwrap();
    assert!(image.is_dirty());
    assert!(
        image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY)
    );
}

#[test]
fn flush_clears_dirty() {
    let mut image = mem_image();
    image.write_at(&[0xAA; 64], 0).unwrap();
    assert!(image.is_dirty());
    image.flush().unwrap();
    assert!(!image.is_dirty());
    assert!(
        !image
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY)
    );
}

#[test]
fn multiple_writes_single_dirty() {
    let mut image = mem_image();
    image.write_at(&[0x11; 64], 0).unwrap();
    image.write_at(&[0x22; 64], 4096).unwrap();
    image.write_at(&[0x33; 64], 8192).unwrap();
    // Still dirty (just once), data still readable
    assert!(image.is_dirty());
    let mut buf = [0u8; 64];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));
}

#[test]
fn dirty_persisted_on_disk_in_memory() {
    let mut image = mem_image();
    image.write_at(&[0xAA; 64], 0).unwrap();

    // Read back raw header from backend and check DIRTY bit at offset 72
    let raw = extract_raw(&image);
    let incompat = u64::from_be_bytes(raw[72..80].try_into().unwrap());
    assert_ne!(incompat & 1, 0, "DIRTY bit should be set on disk");
}

#[test]
fn flush_clears_dirty_on_disk_in_memory() {
    let mut image = mem_image();
    image.write_at(&[0xAA; 64], 0).unwrap();
    image.flush().unwrap();

    let raw = extract_raw(&image);
    let incompat = u64::from_be_bytes(raw[72..80].try_into().unwrap());
    assert_eq!(incompat & 1, 0, "DIRTY bit should be cleared on disk after flush");
}

// ---- File-based dirty persistence ----

#[test]
fn write_sets_dirty_on_disk_file() {
    let (mut image, path, _dir) = file_image();
    image.write_at(&[0xBB; 512], 0).unwrap();
    // Don't flush — just drop and reopen
    drop(image);

    let reopened = Qcow2Image::open(&path).unwrap();
    assert!(
        reopened
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY),
        "reopened image should have DIRTY set"
    );
}

#[test]
fn flush_clears_dirty_on_disk_file() {
    let (mut image, path, _dir) = file_image();
    image.write_at(&[0xCC; 512], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    let reopened = Qcow2Image::open(&path).unwrap();
    assert!(
        !reopened
            .header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY),
        "reopened image should NOT have DIRTY after flush"
    );
}

#[test]
fn dirty_image_data_readable_after_reopen_rw() {
    let (mut image, path, _dir) = file_image();
    image.write_at(&[0xDD; 256], 0).unwrap();
    // No flush — dirty close
    drop(image);

    let mut reopened = Qcow2Image::open_rw(&path).unwrap();
    let mut buf = [0u8; 256];
    reopened.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD), "data should survive dirty close");
}

#[test]
fn read_only_open_does_not_set_dirty() {
    let (mut image, path, _dir) = file_image();
    image.write_at(&[0xEE; 512], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    let mut ro = Qcow2Image::open(&path).unwrap();
    let mut buf = [0u8; 512];
    ro.read_at(&mut buf, 0).unwrap();

    assert!(
        !ro.header()
            .incompatible_features
            .contains(IncompatibleFeatures::DIRTY),
        "read-only open + read should not set DIRTY"
    );
}

// ---- Autoclear bit interactions ----

#[test]
fn autoclear_bitmaps_cleared_while_dirty() {
    let mut image = mem_image();
    // Create a bitmap to set BITMAPS autoclear bit
    image.bitmap_create("test-bm", None, true).unwrap();
    assert!(
        image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BITMAPS),
        "BITMAPS autoclear should be set after bitmap_create"
    );

    // Write → dirty → BITMAPS should be cleared
    image.write_at(&[0xAA; 64], 0).unwrap();
    assert!(image.is_dirty());
    assert!(
        !image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BITMAPS),
        "BITMAPS autoclear should be cleared while dirty"
    );
}

#[test]
fn autoclear_bitmaps_restored_on_flush() {
    let mut image = mem_image();
    image.bitmap_create("test-bm", None, true).unwrap();
    image.write_at(&[0xAA; 64], 0).unwrap();

    // Before flush: BITMAPS should be cleared
    assert!(
        !image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BITMAPS)
    );

    // After flush: BITMAPS should be restored
    image.flush().unwrap();
    assert!(
        image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BITMAPS),
        "BITMAPS autoclear should be restored after flush"
    );
}

#[test]
fn autoclear_hashes_cleared_while_dirty() {
    let mut image = mem_image();
    image.hash_init(None, None).unwrap();
    assert!(
        image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BLAKE3_HASHES),
        "BLAKE3_HASHES autoclear should be set after hash_init"
    );

    image.write_at(&[0xBB; 64], 0).unwrap();
    assert!(
        !image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BLAKE3_HASHES),
        "BLAKE3_HASHES autoclear should be cleared while dirty"
    );
}

#[test]
fn autoclear_hashes_restored_on_flush() {
    let mut image = mem_image();
    image.hash_init(None, None).unwrap();
    image.write_at(&[0xCC; 64], 0).unwrap();
    image.flush().unwrap();
    assert!(
        image
            .header()
            .autoclear_features
            .contains(AutoclearFeatures::BLAKE3_HASHES),
        "BLAKE3_HASHES autoclear should be restored after flush"
    );
}

// ---- QEMU interop ----

#[test]
fn qemu_check_after_clean_close() {
    if !common::has_qemu_img() {
        return;
    }
    let (mut image, path, _dir) = file_image();
    image.write_at(&[0xFF; 4096], 0).unwrap();
    image.flush().unwrap();
    drop(image);

    let ti = common::TestImage::wrap(path, _dir);
    assert!(ti.qemu_check(), "qemu-img check should pass after clean close");
}
