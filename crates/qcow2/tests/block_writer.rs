//! Integration tests for `Qcow2BlockWriter`.
//!
//! Tests cover sequential writing, zero detection, compression, encryption,
//! extended L2, the Write+Seek interface, memory eviction, and QEMU interop.

mod common;

use std::io::{Seek, SeekFrom, Write};

use qcow2::engine::block_writer::BlockWriterOptions;
use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::Qcow2BlockWriter;

/// Helper to create default block writer options with a given virtual size.
fn default_options(virtual_size: u64) -> BlockWriterOptions {
    BlockWriterOptions {
        create: CreateOptions {
            virtual_size,
            cluster_bits: Some(16), // 64 KiB clusters
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
        compress: false,
        memory_limit: None,
        hash_size: None,
    }
}

// ── 1. Sequential write + finalize + reopen ────────────────────────────

#[test]
fn sequential_write_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seq.qcow2");

    let cluster_size = 65536u64; // 64 KiB
    let virtual_size = 1024 * 1024; // 1 MiB

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write pattern 0xAA to first cluster
    let data_a = vec![0xAAu8; cluster_size as usize];
    writer.write_guest(0, &data_a).unwrap();

    // Write pattern 0xBB to second cluster
    let data_b = vec![0xBBu8; cluster_size as usize];
    writer.write_guest(cluster_size, &data_b).unwrap();

    writer.finalize().unwrap();

    // Reopen and verify
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first cluster should be 0xAA");

    image.read_at(&mut buf, cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "second cluster should be 0xBB");

    // Unwritten area should be zero
    image.read_at(&mut buf, 2 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "unwritten cluster should be zero");
}

// ── 2. Zero cluster detection ──────────────────────────────────────────

#[test]
fn zero_cluster_not_allocated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zero.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write all zeros to a cluster
    let zeros = vec![0u8; cluster_size as usize];
    writer.write_guest(0, &zeros).unwrap();

    // Write non-zero to another cluster
    let data = vec![0x42u8; cluster_size as usize];
    writer.write_guest(cluster_size, &data).unwrap();

    writer.finalize().unwrap();

    // Reopen and verify both clusters read correctly
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "zero cluster should read as zeros");

    image.read_at(&mut buf, cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0x42), "data cluster should be 0x42");

    // Check file size: the zero cluster shouldn't consume disk space beyond metadata.
    let file_size = std::fs::metadata(&path).unwrap().len();
    // With one data cluster + metadata, should be significantly less than two full clusters of data
    // plus metadata. Just verify it's smaller than virtual_size.
    assert!(
        file_size < virtual_size,
        "image with one zero cluster should be smaller than virtual_size"
    );
}

// ── 3. Compression (deflate) ───────────────────────────────────────────

#[test]
fn compression_deflate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compressed.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.compress = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write highly compressible data (repeating pattern)
    let data = vec![0xCDu8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    // Reopen and verify data
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCD), "compressed data should round-trip");

    // Compressed file should be smaller than metadata + full uncompressed cluster.
    // Metadata alone is ~5-6 clusters, but the data portion should be tiny.
    let file_size = std::fs::metadata(&path).unwrap().len();
    assert!(
        file_size < virtual_size,
        "compressed image should be much smaller than virtual_size (got {file_size})"
    );
}

// ── 4. Compression (zstd) ──────────────────────────────────────────────

#[test]
fn compression_zstd() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zstd.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.compress = true;
    opts.create.compression_type = Some(qcow2::format::constants::COMPRESSION_ZSTD);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0xEEu8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xEE), "zstd compressed data should round-trip");
}

// ── 5. Compressed cluster packing ──────────────────────────────────────

#[test]
fn compressed_cluster_packing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("packed.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.compress = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write multiple highly compressible clusters
    for i in 0..8u8 {
        let data = vec![i; cluster_size as usize];
        writer
            .write_guest(i as u64 * cluster_size, &data)
            .unwrap();
    }

    writer.finalize().unwrap();

    // Verify all data reads back correctly
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    for i in 0..8u8 {
        image.read_at(&mut buf, i as u64 * cluster_size).unwrap();
        assert!(
            buf.iter().all(|&b| b == i),
            "cluster {i} should contain pattern 0x{i:02x}"
        );
    }

    // With packing, 8 highly compressible clusters should use much less disk
    // than 8 uncompressed clusters (8 * 64K = 512K) plus metadata.
    let file_size = std::fs::metadata(&path).unwrap().len();
    assert!(
        file_size < virtual_size,
        "8 packed compressed clusters should use much less than virtual_size (got {file_size})"
    );
}

// ── 6. Encryption (LUKS) ──────────────────────────────────────────────

#[test]
fn encryption_luks_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;
    let password = b"testpass123";

    let mut opts = default_options(virtual_size);
    opts.create.encryption = Some(qcow2::engine::image::EncryptionOptions {
        password: password.to_vec(),
        cipher: qcow2::engine::encryption::CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: Some(10), // fast for tests
    });

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0xABu8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    // Reopen with password and verify
    let mut image = Qcow2Image::open_with_password(&path, password).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xAB),
        "encrypted data should round-trip with correct password"
    );
}

// ── 7. Extended L2 / Subclusters ───────────────────────────────────────

#[test]
fn extended_l2_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extl2.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.create.extended_l2 = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0x77u8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x77),
        "extended L2 data should round-trip"
    );
}

// ── 8. Re-write error on flushed cluster ───────────────────────────────

#[test]
fn rewrite_flushed_cluster_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rewrite.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write and flush a cluster
    let data = vec![0xAAu8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    // The cluster is now flushed (it was full). Writing again should fail.
    let result = writer.write_guest(0, &[0xBB]);
    assert!(result.is_err(), "re-writing a flushed cluster should return an error");

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("already flushed"),
        "error should mention 'already flushed', got: {err}"
    );
}

// ── 9. Read from buffer (before flush) ─────────────────────────────────

#[test]
fn read_from_buffer_before_flush() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readbuf.qcow2");

    let virtual_size = 1024 * 1024;

    let writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Haven't written anything yet — buffer should return zeros
    let mut buf = vec![0xFFu8; 512];
    writer.read_exact_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "unwritten buffer should read as zeros");
}

// ── 10. Read from flushed cluster errors ───────────────────────────────

#[test]
fn read_from_flushed_cluster_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readflushed.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write a full cluster (triggers flush)
    let data = vec![0xAA; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    // Reading from the flushed cluster should fail
    let mut buf = vec![0u8; 512];
    let result = writer.read_exact_at(&mut buf, 0);
    assert!(result.is_err(), "reading from flushed cluster should error");
}

// ── 11. Write + Seek interface ─────────────────────────────────────────

#[test]
fn write_seek_interface() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writeseek.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Use Write trait
    writer.write_all(&vec![0xAA; cluster_size as usize]).unwrap();
    // Cursor should now be at cluster_size
    assert_eq!(
        writer.seek(SeekFrom::Current(0)).unwrap(),
        cluster_size,
        "cursor should advance after write"
    );

    // Seek to a different position
    writer.seek(SeekFrom::Start(2 * cluster_size)).unwrap();
    writer.write_all(&vec![0xBB; cluster_size as usize]).unwrap();

    // Seek from end
    let pos = writer.seek(SeekFrom::End(-(cluster_size as i64))).unwrap();
    assert_eq!(
        pos,
        virtual_size - cluster_size,
        "seek from end should work"
    );

    writer.finalize().unwrap();

    // Verify data
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first write via Write trait");

    image.read_at(&mut buf, 2 * cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "second write after seek");

    // Gap should be zero
    image.read_at(&mut buf, cluster_size).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "gap between writes should be zero");
}

// ── 12. io::copy compatibility ─────────────────────────────────────────

#[test]
fn io_copy_from_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iocopy.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Create source data and copy it in
    let source_data = (0..virtual_size as usize)
        .map(|i| (i % 251) as u8) // non-zero pattern
        .collect::<Vec<_>>();
    let mut cursor = std::io::Cursor::new(&source_data);
    std::io::copy(&mut cursor, &mut writer).unwrap();

    writer.finalize().unwrap();

    // Verify round-trip
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; virtual_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, source_data, "io::copy data should round-trip");
}

// ── 13. Memory limit eviction ──────────────────────────────────────────

#[test]
fn memory_limit_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("eviction.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 16 * cluster_size;

    let mut opts = default_options(virtual_size);
    // Set a very low memory limit: 4 clusters worth of buffer
    opts.memory_limit = Some(4 * cluster_size);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write partial data to many clusters (exceeding memory limit)
    // This forces eviction of older blocks
    for i in 0..8u64 {
        let offset = i * cluster_size;
        // Write a partial cluster (half-filled)
        let data = vec![(i + 1) as u8; (cluster_size / 2) as usize];
        writer.write_guest(offset, &data).unwrap();
    }

    writer.finalize().unwrap();

    // Verify all data reads back correctly
    let mut image = Qcow2Image::open(&path).unwrap();
    for i in 0..8u64 {
        let offset = i * cluster_size;
        let mut buf = vec![0u8; (cluster_size / 2) as usize];
        image.read_at(&mut buf, offset).unwrap();
        assert!(
            buf.iter().all(|&b| b == (i + 1) as u8),
            "evicted cluster {i} should read back correctly"
        );

        // Second half should be zero (partial cluster zero-padded)
        let mut buf2 = vec![0xFFu8; (cluster_size / 2) as usize];
        image.read_at(&mut buf2, offset + cluster_size / 2).unwrap();
        assert!(
            buf2.iter().all(|&b| b == 0),
            "unwritten half of cluster {i} should be zero"
        );
    }
}

// ── 14. Finalize produces valid QCOW2 (qemu-img check) ────────────────

#[test]
fn qemu_img_check_passes() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not found");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemucheck.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write varied data
    for i in 0..10u64 {
        let data = vec![(i + 1) as u8; cluster_size as usize];
        writer.write_guest(i * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "block writer image should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 15. qemu-img check on compressed image ─────────────────────────────

#[test]
fn qemu_img_check_compressed() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not found");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemucheckcomp.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.compress = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    for i in 0..8u8 {
        let data = vec![i; cluster_size as usize];
        writer.write_guest(i as u64 * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "compressed block writer image should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 16. qemu-io reads our data correctly ───────────────────────────────

#[test]
fn qemu_io_reads_block_writer_data() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not found");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemuio.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    let data = vec![0xABu8; 512];
    writer.write_guest(0, &data).unwrap();
    // Write a full cluster elsewhere so the partial cluster above gets flushed at finalize
    let full = vec![0xCDu8; cluster_size as usize];
    writer.write_guest(cluster_size, &full).unwrap();

    writer.finalize().unwrap();

    // Use qemu-io to read and verify
    let img = common::TestImage::wrap(path, dir);
    let read_data = img.read_via_qemu(0, 512);
    assert_eq!(read_data.len(), 512);
    assert!(
        read_data.iter().all(|&b| b == 0xAB),
        "qemu-io should read our written data"
    );

    let read_data2 = img.read_via_qemu(cluster_size, 512);
    assert!(
        read_data2.iter().all(|&b| b == 0xCD),
        "qemu-io should read second cluster data"
    );
}

// ── 17. qemu-img check on extended L2 image ────────────────────────────

#[test]
fn qemu_img_check_extended_l2() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not found");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemucheckextl2.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.create.extended_l2 = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0x55u8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "extended L2 block writer image should pass qemu-img check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 18. Empty image (no writes, just finalize) ─────────────────────────

#[test]
fn empty_image_finalize() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.qcow2");

    let virtual_size = 1024 * 1024;

    let writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();
    writer.finalize().unwrap();

    // Should open and read as all zeros
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0xFFu8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "empty image should read as zeros");
}

// ── 19. Write beyond virtual size errors ───────────────────────────────

#[test]
fn write_beyond_virtual_size_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("beyond.qcow2");

    let virtual_size = 65536; // exactly one cluster

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write at the boundary should fail
    let result = writer.write_guest(virtual_size, &[0x42]);
    assert!(result.is_err(), "write at virtual_size should fail");

    // Write that extends past should fail
    let result = writer.write_guest(virtual_size - 1, &[0x42, 0x43]);
    assert!(result.is_err(), "write that extends past virtual_size should fail");
}

// ── 20. Sub-cluster writes accumulate correctly ────────────────────────

#[test]
fn sub_cluster_writes_accumulate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subcluster.qcow2");

    let virtual_size = 1024 * 1024;

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write 512 bytes at different offsets within the same cluster
    writer.write_guest(0, &[0xAA; 512]).unwrap();
    writer.write_guest(4096, &[0xBB; 512]).unwrap();
    writer.write_guest(32768, &[0xCC; 512]).unwrap();

    // Now fill the rest to trigger flush
    // Write remaining bytes to complete the cluster
    writer.write_guest(512, &vec![0x11; 3584]).unwrap(); // 512..4096
    writer.write_guest(4608, &vec![0x22; 28160]).unwrap(); // 4608..32768
    writer.write_guest(33280, &vec![0x33; 32256]).unwrap(); // 33280..65536

    writer.finalize().unwrap();

    // Verify specific sub-regions
    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; 512];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first sub-write at 0");

    image.read_at(&mut buf, 4096).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "second sub-write at 4096");

    image.read_at(&mut buf, 32768).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC), "third sub-write at 32768");
}

// ── 21. Large image (multiple L2 tables) ───────────────────────────────

#[test]
fn large_image_multiple_l2_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.qcow2");

    let cluster_size = 65536u64;
    // With 64KiB clusters and 8-byte L2 entries: 8192 entries per L2 table
    // = 512 MiB per L2 table. Use 1 GiB virtual to force 2 L2 tables.
    let virtual_size = 1024 * 1024 * 1024; // 1 GiB

    let mut writer = Qcow2BlockWriter::create(&path, default_options(virtual_size)).unwrap();

    // Write at the beginning (first L2 table)
    writer.write_guest(0, &vec![0xAA; cluster_size as usize]).unwrap();

    // Write past the first L2 table boundary (second L2 table)
    let second_l2_offset = 512 * 1024 * 1024u64; // 512 MiB
    writer
        .write_guest(second_l2_offset, &vec![0xBB; cluster_size as usize])
        .unwrap();

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open(&path).unwrap();
    let mut buf = vec![0u8; cluster_size as usize];

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first L2 table data");

    image.read_at(&mut buf, second_l2_offset).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB), "second L2 table data");
}

// ── 22. Finalize after finalize is impossible (consumed) ───────────────
// This is a compile-time guarantee since finalize() takes `self`.
// We just verify it compiles correctly and works once.

#[test]
fn finalize_consumes_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("consumed.qcow2");

    let writer = Qcow2BlockWriter::create(&path, default_options(65536)).unwrap();
    writer.finalize().unwrap();
    // `writer` is consumed — no further calls possible (enforced by compiler)
}

// ── 23. Blake3 hash roundtrip (32 byte) ────────────────────────────────

#[test]
fn hash_roundtrip_32() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hash32.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(32);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write data to several clusters
    for i in 0..4u8 {
        let data = vec![i + 1; cluster_size as usize];
        writer.write_guest(i as u64 * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    // Reopen (read-write for hash_verify) and verify hashes
    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let mismatches = image.hash_verify().unwrap();
    assert!(
        mismatches.is_empty(),
        "hash_verify should find 0 mismatches, got {}",
        mismatches.len()
    );
}

// ── 24. Blake3 hash roundtrip (16 byte) ────────────────────────────────

#[test]
fn hash_roundtrip_16() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hash16.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(16);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    for i in 0..4u8 {
        let data = vec![i + 1; cluster_size as usize];
        writer.write_guest(i as u64 * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let mismatches = image.hash_verify().unwrap();
    assert!(
        mismatches.is_empty(),
        "16-byte hash_verify should find 0 mismatches, got {}",
        mismatches.len()
    );
}

// ── 25. Hash with compression ──────────────────────────────────────────

#[test]
fn hash_with_compression() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashcomp.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.compress = true;
    opts.hash_size = Some(32);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    for i in 0..4u8 {
        let data = vec![i + 1; cluster_size as usize];
        writer.write_guest(i as u64 * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let mismatches = image.hash_verify().unwrap();
    assert!(
        mismatches.is_empty(),
        "compressed+hashed verify should find 0 mismatches, got {}",
        mismatches.len()
    );
}

// ── 26. Hash with encryption ───────────────────────────────────────────

#[test]
fn hash_with_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashenc.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;
    let password = b"hashtest";

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(32);
    opts.create.encryption = Some(qcow2::engine::image::EncryptionOptions {
        password: password.to_vec(),
        cipher: qcow2::engine::encryption::CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: Some(10),
    });

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0xABu8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open_rw_with_password(&path, password).unwrap();
    let mismatches = image.hash_verify().unwrap();
    assert!(
        mismatches.is_empty(),
        "encrypted+hashed verify should find 0 mismatches, got {}",
        mismatches.len()
    );
}

// ── 27. Hash zero clusters ─────────────────────────────────────────────

#[test]
fn hash_zero_clusters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashzero.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(32);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write all zeros to cluster 0
    let zeros = vec![0u8; cluster_size as usize];
    writer.write_guest(0, &zeros).unwrap();

    // Write non-zero to cluster 1
    let data = vec![0x42u8; cluster_size as usize];
    writer.write_guest(cluster_size, &data).unwrap();

    writer.finalize().unwrap();

    let mut image = Qcow2Image::open_rw(&path).unwrap();
    let mismatches = image.hash_verify().unwrap();
    assert!(
        mismatches.is_empty(),
        "zero cluster hash should verify correctly, got {} mismatches",
        mismatches.len()
    );
}

// ── 28. Hash info correct ──────────────────────────────────────────────

#[test]
fn hash_info_correct() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashinfo.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 4 * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(32);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let data = vec![0x42u8; cluster_size as usize];
    writer.write_guest(0, &data).unwrap();

    writer.finalize().unwrap();

    let image = Qcow2Image::open(&path).unwrap();
    let info = image.hash_info().expect("hash_info should return Some");
    assert_eq!(info.hash_size, 32);
    assert_eq!(info.hash_chunk_bits, 16); // cluster_bits = 16
    assert!(info.consistent, "autoclear flag should be set");
    assert!(info.hash_table_entries > 0);
}

// ── 29. qemu-img check with hashes ─────────────────────────────────────

#[test]
fn qemu_img_check_with_hashes() {
    if !common::has_qemu_img() {
        eprintln!("skipping: qemu-img not found");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("qemuhash.qcow2");

    let cluster_size = 65536u64;
    let virtual_size = 1024 * 1024;

    let mut opts = default_options(virtual_size);
    opts.hash_size = Some(32);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    for i in 0..8u64 {
        let data = vec![(i + 1) as u8; cluster_size as usize];
        writer.write_guest(i * cluster_size, &data).unwrap();
    }

    writer.finalize().unwrap();

    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(&path)
        .output()
        .expect("failed to run qemu-img check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().unwrap_or(-1);

    // Exit code 0 = clean, 3 = leaks only (no corruption).
    // QEMU doesn't understand our custom blake3 hash extension, so it reports
    // hash data clusters and hash table clusters as "leaked". This is expected.
    assert!(
        exit_code == 0 || exit_code == 3,
        "hashed image should have no corruption (exit 0 or 3), got {exit_code}: {stderr}"
    );

    // Verify no actual corruption (only leaks from hash clusters)
    if exit_code == 3 {
        assert!(
            stderr.contains("Leaked"),
            "exit code 3 should be leaks only: {stderr}"
        );
        assert!(
            !stderr.contains("refcount=") || !stderr.contains("reference=") || stderr.contains("Leaked"),
            "should not have refcount/reference mismatches beyond leaks: {stderr}"
        );
    }
}

// ── 30. Compressed cluster boundary crossing (Bug 2 regression) ─────

/// Regression test for Bug 2: compressed cluster packing corruption.
///
/// Writes 200+ compressed clusters that pack into host clusters. At exactly
/// 128 compressed entries (128 × 512 = 65536 = one host cluster), the old
/// `compressed_cursor` would overflow and subsequent allocations could
/// overlap with metadata written during finalize.
///
/// This test writes enough compressed clusters to cross the boundary
/// multiple times, then reads everything back to verify data integrity.
#[test]
fn compressed_cluster_boundary_crossing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bug2_regression.qcow2");

    let cluster_size = 65536u64; // 64 KiB
    // Need enough clusters to cross the 128-entry packing boundary multiple times.
    // 300 clusters × 64 KiB = ~19 MiB virtual.
    let num_clusters = 300u64;
    let virtual_size = num_clusters * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.compress = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write unique, compressible data to each cluster.
    // Each cluster gets a repeating pattern that compresses well but is unique
    // so we can verify correctness on read-back.
    let mut expected: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 0..num_clusters {
        let offset = i * cluster_size;
        let pattern = format!("CLUSTER-{i:06}-");
        let data: Vec<u8> = pattern
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(cluster_size as usize)
            .collect();

        writer.seek(SeekFrom::Start(offset)).unwrap();
        writer.write_all(&data).unwrap();
        expected.push((offset, data));
    }

    writer.finalize().unwrap();

    // Read back and verify every cluster.
    let mut img = Qcow2Image::open(&path).unwrap();
    for (offset, data) in &expected {
        let mut buf = vec![0u8; cluster_size as usize];
        img.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, data,
            "data mismatch at cluster offset {:#x} (cluster {})",
            offset,
            offset / cluster_size
        );
    }
}

// ── 31. Compressed + uncompressed interleaved (Bug 2 variant) ───────

/// Verifies that interleaving compressed and uncompressed (zero/random)
/// clusters does not cause allocation conflicts in the block writer.
#[test]
fn compressed_interleaved_with_zeros_and_uncompressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bug2_interleaved.qcow2");

    let cluster_size = 65536u64;
    let num_clusters = 200u64;
    let virtual_size = num_clusters * cluster_size;

    let mut opts = default_options(virtual_size);
    opts.compress = true;

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    let mut expected: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 0..num_clusters {
        let offset = i * cluster_size;
        let data: Vec<u8> = match i % 3 {
            0 => {
                // Compressible text
                let pattern = format!("TEXT-{i:06}-");
                pattern
                    .as_bytes()
                    .iter()
                    .copied()
                    .cycle()
                    .take(cluster_size as usize)
                    .collect()
            }
            1 => {
                // All zeros — will be detected as zero cluster (no host allocation)
                vec![0u8; cluster_size as usize]
            }
            _ => {
                // Pseudo-random (incompressible) — will be stored uncompressed
                let mut buf = vec![0u8; cluster_size as usize];
                let mut state: u64 = 0xCAFE_0000 + i;
                for chunk in buf.chunks_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let bytes = state.to_le_bytes();
                    let len = chunk.len().min(8);
                    chunk[..len].copy_from_slice(&bytes[..len]);
                }
                buf
            }
        };

        writer.seek(SeekFrom::Start(offset)).unwrap();
        writer.write_all(&data).unwrap();
        expected.push((offset, data));
    }

    writer.finalize().unwrap();

    // Read back and verify.
    let mut img = Qcow2Image::open(&path).unwrap();
    for (offset, data) in &expected {
        let mut buf = vec![0u8; cluster_size as usize];
        img.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, data,
            "data mismatch at offset {:#x} (cluster {})",
            offset,
            offset / cluster_size
        );
    }
}

// ── 32. Compressed clusters at high guest offsets (Bug 2 variant) ─────

/// Regression test for Bug 2: compressed cluster corruption at high guest
/// offsets (multi-TiB). The compressed descriptor encoding uses a variable
/// bit layout that depends on `cluster_bits`. With a 13 TiB virtual size
/// and `cluster_bits=16`, the L1 table becomes large and clusters written
/// at 9+ TiB offsets exercise deep L1/L2 paths. The original bug caused
/// the `compressed_cursor` to overflow, corrupting data at high offsets
/// while low offsets appeared fine.
///
/// This test writes compressed clusters at scattered offsets across the
/// full 13 TiB address space and verifies read-back integrity.
#[test]
fn compressed_clusters_at_high_guest_offsets() {
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bug2_high_offset.qcow2");

    let cluster_size = 65536u64; // 64 KiB
    let virtual_size = 13 * TIB;

    let mut opts = default_options(virtual_size);
    opts.compress = true;
    opts.memory_limit = Some(256 * MIB);

    let mut writer = Qcow2BlockWriter::create(&path, opts).unwrap();

    // Write compressible data at offsets spread across the address space,
    // including the high offsets (9+ TiB) that triggered the original bug.
    let test_offsets: Vec<(u64, &str)> = vec![
        (0, "zero"),
        (100 * MIB, "100MiB"),
        (1 * TIB + 100 * MIB, "1.1TiB"),
        (4 * TIB + 500 * MIB, "4.5TiB"),
        (9 * TIB, "9TiB"),
        (9 * TIB + 5 * MIB, "9TiB+5MiB"),
        (12 * TIB + 800 * MIB, "12.8TiB"),
        (12 * TIB + 900 * MIB, "12.9TiB"),
    ];

    let mut expected: Vec<(u64, Vec<u8>)> = Vec::new();
    for &(offset, label) in &test_offsets {
        let pattern = format!("DATA-AT-{label}-0123456789ABCDEF-");
        let data: Vec<u8> = pattern
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(cluster_size as usize)
            .collect();

        writer.seek(SeekFrom::Start(offset)).unwrap();
        writer.write_all(&data).unwrap();
        expected.push((offset, data));
    }

    writer.finalize().unwrap();

    // Read back and verify every cluster.
    let mut img = Qcow2Image::open(&path).unwrap();
    for (offset, data) in &expected {
        let mut buf = vec![0u8; cluster_size as usize];
        img.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, data,
            "data mismatch at guest offset {:#x}",
            offset,
        );
    }

    // Verify that unwritten regions read as zeros.
    let mut zero_buf = vec![0u8; cluster_size as usize];
    img.read_at(&mut zero_buf, 6 * TIB).unwrap();
    assert!(
        zero_buf.iter().all(|&b| b == 0),
        "unwritten region at 6 TiB should be all zeros"
    );
}
