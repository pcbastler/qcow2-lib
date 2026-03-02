//! Integration tests: backing file chain handling.
//!
//! Tests that our library correctly detects and handles images
//! with backing files.

mod common;

use qcow2_lib::engine::image::Qcow2Image;

#[test]
fn detect_backing_file() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    // Create base image with data
    let base = common::TestImage::create("1M");
    base.write_pattern(0xBB, 0, 4096);

    // Create overlay with backing
    let overlay = common::TestImage::create_with_backing("1M", &base.path);

    let image = Qcow2Image::open(&overlay.path).unwrap();
    assert!(image.header().has_backing_file());
    assert!(image.backing_chain().is_some());
    assert_eq!(image.backing_chain().unwrap().depth(), 1);
}

#[test]
fn open_image_without_backing() {
    let img = common::TestImage::create("1M");
    let image = Qcow2Image::open(&img.path).unwrap();

    assert!(!image.header().has_backing_file());
    assert!(image.backing_chain().is_none());
}
