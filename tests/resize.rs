//! Integration tests: image resize with qemu cross-validation.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};

/// Helper: run `qemu-img check` and assert success.
fn assert_qemu_check(path: &std::path::Path) {
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "qemu-img check failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Helper: get the virtual size reported by `qemu-img info`.
///
/// Parses the text output line: `virtual size: 50 MiB (52428800 bytes)`
fn qemu_virtual_size(path: &std::path::Path) -> u64 {
    let output = std::process::Command::new("qemu-img")
        .args(["info"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img info");

    assert!(
        output.status.success(),
        "qemu-img info failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Format: "virtual size: 50 MiB (52428800 bytes)"
        if let Some(rest) = line.strip_prefix("virtual size:") {
            if let Some(start) = rest.find('(') {
                if let Some(end) = rest.find(" bytes)") {
                    let num_str = &rest[start + 1..end];
                    return num_str.trim().parse().expect("failed to parse virtual size bytes");
                }
            }
        }
    }
    panic!("could not find virtual size in qemu-img info output:\n{stdout}");
}

/// Helper: create an image with data, flush, and drop.
fn create_image_with_data(
    dir: &std::path::Path,
    name: &str,
    virtual_size: u64,
    data: &[(u64, &[u8])],
) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    for &(offset, buf) in data {
        image.write_at(buf, offset).unwrap();
    }
    image.flush().unwrap();
    drop(image);
    path
}

// ---- Resize: qemu-img check ----

#[test]
fn resize_grow_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "grow.qcow2", 10 * 1024 * 1024, &[]);

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(20 * 1024 * 1024).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

#[test]
fn resize_grow_l1_relocation_passes_qemu_check() {
    let dir = tempfile::tempdir().unwrap();
    // Start small so L1 table needs to grow significantly.
    let path = create_image_with_data(
        dir.path(),
        "grow-big.qcow2",
        1024 * 1024, // 1 MB
        &[(0, &[0xAA; 512])],
    );

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    // Grow to 4 GB — requires many more L1 entries.
    image.resize(4 * 1024 * 1024 * 1024).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);
}

// ---- Resize: qemu-img info validates new size ----

#[test]
fn resize_grow_qemu_reports_correct_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "size.qcow2", 10 * 1024 * 1024, &[]);

    let new_size = 50 * 1024 * 1024;
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(new_size).unwrap();
    image.flush().unwrap();
    drop(image);

    let reported = qemu_virtual_size(&path);
    assert_eq!(
        reported, new_size,
        "qemu-img info should report the resized virtual size"
    );
}

// ---- Resize: data integrity ----

#[test]
fn resize_preserves_existing_data() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(
        dir.path(),
        "preserve.qcow2",
        10 * 1024 * 1024,
        &[(0, &[0xDD; 4096]), (65536, &[0xEE; 512])],
    );

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(20 * 1024 * 1024).unwrap();
    image.flush().unwrap();
    drop(image);

    // Verify data via qemu-io
    let img = common::TestImage {
        path: path.clone(),
        _dir: dir,
    };
    let data0 = img.read_via_qemu(0, 4096);
    assert!(
        data0.iter().all(|&b| b == 0xDD),
        "existing data at offset 0 should survive resize"
    );

    let data1 = img.read_via_qemu(65536, 512);
    assert!(
        data1.iter().all(|&b| b == 0xEE),
        "existing data at offset 65536 should survive resize"
    );
}

#[test]
fn resize_new_area_reads_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "zeros.qcow2", 1024 * 1024, &[]);

    let new_size = 2 * 1024 * 1024;
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(new_size).unwrap();
    image.flush().unwrap();
    drop(image);

    // Read from the newly grown area with our library
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0xFFu8; 4096];
    image.read_at(&mut buf, 1024 * 1024).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0),
        "new area after resize should read as zeros"
    );
}

// ---- Resize: write to new area ----

#[test]
fn resize_write_to_new_area_passes_qemu_check() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = create_image_with_data(dir.path(), "newarea.qcow2", 1024 * 1024, &[]);

    let new_size = 2 * 1024 * 1024;
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    image.resize(new_size).unwrap();
    // Write into the newly available area
    image.write_at(&[0xFA; 512], 1024 * 1024).unwrap();
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);

    // Verify data via qemu-io
    let img = common::TestImage {
        path: path.clone(),
        _dir: dir,
    };
    let data = img.read_via_qemu(1024 * 1024, 512);
    assert!(
        data.iter().all(|&b| b == 0xFA),
        "data written to new area should be readable by qemu-io"
    );
}
