//! Integration tests for Extended L2 Entries (subclusters).
//!
//! Tests create QCOW2 images with extended_l2=true and verify correct behavior
//! of subcluster-granular reads and writes.

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const KB: u64 = 1024;
const MB: u64 = 1024 * 1024;

fn create_extended_l2_image(virtual_size: u64, cluster_bits: u32) -> Qcow2Image {
    let backend = Box::new(MemoryBackend::zeroed(0));
    Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: true, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap()
}

// ---- Basic creation and header ----

#[test]
fn create_extended_l2_image_valid_header() {
    let image = create_extended_l2_image(1 * MB, 16);
    assert!(image.header().has_extended_l2());
    assert_eq!(image.header().l2_entry_size(), 16);
    assert_eq!(image.header().subcluster_size(), Some(2048)); // 64KB / 32
}

#[test]
fn create_extended_l2_image_cluster_bits_14() {
    // Minimum cluster_bits for extended L2
    let image = create_extended_l2_image(1 * MB, 14);
    assert!(image.header().has_extended_l2());
    assert_eq!(image.cluster_size(), 16384);
    assert_eq!(image.header().subcluster_size(), Some(512)); // 16KB / 32
}

#[test]
fn create_extended_l2_rejects_small_clusters() {
    let backend = Box::new(MemoryBackend::zeroed(0));
    let result = Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size: 1 * MB,
            cluster_bits: Some(12), // 4KB — too small for extended L2
            extended_l2: true, compression_type: None,
            data_file: None, encryption: None,
        },
    );
    assert!(result.is_err(), "should reject cluster_bits < 14 for extended L2");
}

// ---- Write and read ----

#[test]
fn write_full_cluster_and_read_back() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let cluster_size = image.cluster_size() as usize;

    let data: Vec<u8> = (0..cluster_size).map(|i| (i % 256) as u8).collect();
    image.write_at(&data, 0).unwrap();

    let mut read_buf = vec![0u8; cluster_size];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, data);
}

#[test]
fn write_partial_cluster_reads_zeros_outside() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let sc_size = image.header().subcluster_size().unwrap() as usize; // 2048

    // Write to the first subcluster only
    let data = vec![0xAA; sc_size];
    image.write_at(&data, 0).unwrap();

    // Read back the written subcluster
    let mut read_buf = vec![0u8; sc_size];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, data, "written subcluster should read back correctly");

    // Read the second subcluster — should be zeros (unallocated)
    let mut read_buf2 = vec![0xFF; sc_size];
    image.read_at(&mut read_buf2, sc_size as u64).unwrap();
    assert!(
        read_buf2.iter().all(|&b| b == 0),
        "unallocated subcluster should read as zeros"
    );
}

#[test]
fn write_multiple_subclusters_separately() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let sc_size = image.header().subcluster_size().unwrap() as usize;

    // Write to SC 0
    let data0 = vec![0x11; sc_size];
    image.write_at(&data0, 0).unwrap();

    // Write to SC 5
    let data5 = vec![0x55; sc_size];
    image.write_at(&data5, 5 * sc_size as u64).unwrap();

    // Write to SC 31 (last)
    let data31 = vec![0xFF; sc_size];
    image.write_at(&data31, 31 * sc_size as u64).unwrap();

    // Verify SC 0
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data0);

    // Verify SC 5
    image.read_at(&mut buf, 5 * sc_size as u64).unwrap();
    assert_eq!(buf, data5);

    // Verify SC 31
    image.read_at(&mut buf, 31 * sc_size as u64).unwrap();
    assert_eq!(buf, data31);

    // Verify SC 1 is zeros (not written)
    image.read_at(&mut buf, sc_size as u64).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn write_spanning_subcluster_boundary() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let sc_size = image.header().subcluster_size().unwrap() as usize;

    // Write data spanning SC 2 and SC 3
    let write_offset = 2 * sc_size as u64 + sc_size as u64 / 2; // middle of SC 2
    let data = vec![0xBB; sc_size]; // spans into SC 3
    image.write_at(&data, write_offset).unwrap();

    // Read back
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, write_offset).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn overwrite_subcluster_in_place() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let sc_size = image.header().subcluster_size().unwrap() as usize;

    // First write
    let data1 = vec![0xAA; sc_size];
    image.write_at(&data1, 0).unwrap();

    // Overwrite same location
    let data2 = vec![0xBB; sc_size];
    image.write_at(&data2, 0).unwrap();

    // Read back — should see second write
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data2);
}

// ---- Multi-cluster reads ----

#[test]
fn read_spanning_two_clusters() {
    let mut image = create_extended_l2_image(2 * MB, 16);
    let cluster_size = image.cluster_size() as usize;

    // Write to last subcluster of cluster 0
    let sc_size = image.header().subcluster_size().unwrap() as usize;
    let data1 = vec![0x11; sc_size];
    let offset1 = cluster_size as u64 - sc_size as u64;
    image.write_at(&data1, offset1).unwrap();

    // Write to first subcluster of cluster 1
    let data2 = vec![0x22; sc_size];
    image.write_at(&data2, cluster_size as u64).unwrap();

    // Read spanning the cluster boundary
    let mut buf = vec![0u8; 2 * sc_size];
    image.read_at(&mut buf, offset1).unwrap();
    assert_eq!(&buf[..sc_size], &data1[..]);
    assert_eq!(&buf[sc_size..], &data2[..]);
}

// ---- Unallocated reads ----

#[test]
fn unallocated_cluster_reads_zeros() {
    let image = create_extended_l2_image(1 * MB, 16);
    let mut buf = vec![0xFF; 4096];
    // Use a const binding for the image
    let mut image = image;
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

// ---- Large write then verify all subclusters ----

#[test]
fn write_entire_cluster_verify_all_subclusters() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let cluster_size = image.cluster_size() as usize;
    let sc_size = image.header().subcluster_size().unwrap() as usize;

    // Write the full cluster with a pattern
    let data: Vec<u8> = (0..cluster_size).map(|i| ((i / sc_size) & 0xFF) as u8).collect();
    image.write_at(&data, 0).unwrap();

    // Read back each subcluster individually
    for sc in 0..32u64 {
        let mut buf = vec![0u8; sc_size];
        image.read_at(&mut buf, sc * sc_size as u64).unwrap();
        let expected = (sc & 0xFF) as u8;
        assert!(
            buf.iter().all(|&b| b == expected),
            "subcluster {sc} should be {expected:#x}"
        );
    }
}

// ---- Snapshot + COW with extended L2 ----

#[test]
fn snapshot_cow_preserves_subclusters() {
    let mut image = create_extended_l2_image(1 * MB, 16);
    let sc_size = image.header().subcluster_size().unwrap() as usize;

    // Write to SC 0 and SC 10
    let data0 = vec![0xAA; sc_size];
    image.write_at(&data0, 0).unwrap();
    let data10 = vec![0xBB; sc_size];
    image.write_at(&data10, 10 * sc_size as u64).unwrap();

    // Create snapshot
    image.snapshot_create("snap1").unwrap();

    // Write to SC 5 (triggers COW)
    let data5 = vec![0xCC; sc_size];
    image.write_at(&data5, 5 * sc_size as u64).unwrap();

    // Verify SC 0 data survived COW
    let mut buf = vec![0u8; sc_size];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data0, "SC 0 should survive COW");

    // Verify SC 10 data survived COW
    image.read_at(&mut buf, 10 * sc_size as u64).unwrap();
    assert_eq!(buf, data10, "SC 10 should survive COW");

    // Verify SC 5 has new data
    image.read_at(&mut buf, 5 * sc_size as u64).unwrap();
    assert_eq!(buf, data5, "SC 5 should have new data");

    // Verify unwritten SCs are still zeros
    image.read_at(&mut buf, sc_size as u64).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "SC 1 should be zeros");
}

// ---- QEMU interop ----

#[cfg(test)]
mod qemu_interop {
    use super::*;
    use std::process::Command;

    fn has_qemu_img() -> bool {
        Command::new("qemu-img")
            .arg("--version")
            .output()
            .is_ok()
    }

    #[test]
    fn qemu_check_our_extended_l2_image() {
        if !has_qemu_img() {
            eprintln!("skipping: qemu-img not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_ext_l2.qcow2");

        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 * MB,
                cluster_bits: Some(16),
                extended_l2: true, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();

        // Write some data
        let sc_size = image.header().subcluster_size().unwrap() as usize;
        image.write_at(&vec![0xAA; sc_size], 0).unwrap();
        image.write_at(&vec![0xBB; sc_size], 5 * sc_size as u64).unwrap();
        image.flush().unwrap();
        drop(image);

        // qemu-img check should pass
        let output = Command::new("qemu-img")
            .args(["check", path.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "qemu-img check failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    fn qemu_info_shows_extended_l2() {
        if !has_qemu_img() {
            eprintln!("skipping: qemu-img not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_ext_l2_info.qcow2");

        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 * MB,
                cluster_bits: Some(16),
                extended_l2: true, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();
        image.flush().unwrap();
        drop(image);

        let output = Command::new("qemu-img")
            .args(["info", path.to_str().unwrap()])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("extended l2") || stdout.contains("subclusters"),
            "qemu-img info should mention extended l2 or subclusters.\nOutput:\n{stdout}"
        );
    }

    #[test]
    fn read_qemu_created_extended_l2() {
        if !has_qemu_img() {
            eprintln!("skipping: qemu-img not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qemu_ext_l2.qcow2");

        // Create extended L2 image with QEMU
        let status = Command::new("qemu-img")
            .args([
                "create",
                "-f", "qcow2",
                "-o", "extended_l2=on,cluster_size=65536",
                path.to_str().unwrap(),
                "1M",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "qemu-img create failed");

        // Write data with qemu-io
        let status = Command::new("qemu-io")
            .args([
                "-f", "qcow2",
                "-c", "write -P 0xAA 0 2048",
                "-c", "write -P 0xBB 4096 2048",
                path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "qemu-io write failed");

        // Read with our library
        let mut image = Qcow2Image::open(&path).unwrap();
        assert!(image.header().has_extended_l2());

        let mut buf = vec![0u8; 2048];
        image.read_at(&mut buf, 0).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "first subcluster should be 0xAA"
        );

        image.read_at(&mut buf, 4096).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "third subcluster should be 0xBB"
        );

        // Unwritten subclusters should be zero
        image.read_at(&mut buf, 2048).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "unwritten subcluster should be zeros"
        );
    }

    #[test]
    fn roundtrip_write_ours_read_qemu() {
        if !has_qemu_img() {
            eprintln!("skipping: qemu-img not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip_ext_l2.qcow2");

        // Create and write with our library
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 * MB,
                cluster_bits: Some(16),
                extended_l2: true, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();

        let sc_size = image.header().subcluster_size().unwrap() as usize;
        image.write_at(&vec![0x42; sc_size], 0).unwrap();
        image.write_at(&vec![0x43; sc_size], 10 * sc_size as u64).unwrap();
        image.flush().unwrap();
        drop(image);

        // Verify with qemu-img check
        let output = Command::new("qemu-img")
            .args(["check", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "qemu-img check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Read with qemu-io and verify
        let output = Command::new("qemu-io")
            .args([
                "-f", "qcow2",
                "-c", &format!("read -P 0x42 0 {sc_size}"),
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("verification failed"),
            "qemu-io read verification failed for SC 0: {stdout}"
        );

        let output = Command::new("qemu-io")
            .args([
                "-f", "qcow2",
                "-c", &format!("read -P 0x43 {} {sc_size}", 10 * sc_size),
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("verification failed"),
            "qemu-io read verification failed for SC 10: {stdout}"
        );
    }
}
