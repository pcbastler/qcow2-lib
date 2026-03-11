//! Detailed COW (Copy-On-Write) tests.
//!
//! Exercises partial-cluster writes, snapshot COW, compressed cluster COW,
//! cross-boundary COW, and backing chain COW interactions.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const CLUSTER_SIZE: usize = 65536;
const CS: u64 = CLUSTER_SIZE as u64;

fn create_mem(vs: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

fn create_file(dir: &tempfile::TempDir, name: &str, vs: u64) -> (std::path::PathBuf, Qcow2Image) {
    let path = dir.path().join(name);
    let image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();
    (path, image)
}

// =====================================================================
// 1. Partial-cluster writes (COW within single cluster)
// =====================================================================

#[test]
fn partial_write_beginning_of_cluster() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xBB; 512], 0).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xBB));
    assert!(buf[512..].iter().all(|&b| b == 0xAA));
}

#[test]
fn partial_write_end_of_cluster() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    let offset = CS - 512;
    image.write_at(&vec![0xCC; 512], offset).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..CLUSTER_SIZE - 512].iter().all(|&b| b == 0xAA));
    assert!(buf[CLUSTER_SIZE - 512..].iter().all(|&b| b == 0xCC));
}

#[test]
fn partial_write_middle_of_cluster() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xDD; 1024], 4096).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..4096].iter().all(|&b| b == 0xAA));
    assert!(buf[4096..5120].iter().all(|&b| b == 0xDD));
    assert!(buf[5120..].iter().all(|&b| b == 0xAA));
}

#[test]
fn multiple_partial_writes_same_cluster() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0x11; 512], 0).unwrap();
    image.write_at(&vec![0x22; 512], 1024).unwrap();
    image.write_at(&vec![0x33; 512], 2048).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[0..512].iter().all(|&b| b == 0x11));
    assert!(buf[512..1024].iter().all(|&b| b == 0xAA));
    assert!(buf[1024..1536].iter().all(|&b| b == 0x22));
    assert!(buf[1536..2048].iter().all(|&b| b == 0xAA));
    assert!(buf[2048..2560].iter().all(|&b| b == 0x33));
    assert!(buf[2560..].iter().all(|&b| b == 0xAA));
}

// =====================================================================
// 2. Cross-cluster boundary writes
// =====================================================================

#[test]
fn write_spanning_two_clusters() {
    let mut image = create_mem(4 * CS);
    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xBB; CLUSTER_SIZE], CS).unwrap();

    // Write 1024 bytes spanning the boundary
    let start = CS - 512;
    image.write_at(&vec![0xFF; 1024], start).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..CLUSTER_SIZE - 512].iter().all(|&b| b == 0xAA));
    assert!(buf[CLUSTER_SIZE - 512..].iter().all(|&b| b == 0xFF));

    image.read_at(&mut buf, CS).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xFF));
    assert!(buf[512..].iter().all(|&b| b == 0xBB));
}

#[test]
fn write_spanning_three_clusters() {
    let mut image = create_mem(4 * CS);
    for i in 0..3u64 {
        image.write_at(&vec![(i as u8 + 1) * 0x11; CLUSTER_SIZE], i * CS).unwrap();
    }

    // Write from middle of cluster 0 to middle of cluster 2
    let start = CS / 2;
    let len = 2 * CS;
    image.write_at(&vec![0xEE; len as usize], start).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    // Cluster 0: first half original, second half 0xEE
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..CLUSTER_SIZE / 2].iter().all(|&b| b == 0x11));
    assert!(buf[CLUSTER_SIZE / 2..].iter().all(|&b| b == 0xEE));

    // Cluster 1: all 0xEE
    image.read_at(&mut buf, CS).unwrap();
    assert!(buf.iter().all(|&b| b == 0xEE));

    // Cluster 2: first half 0xEE, second half original
    image.read_at(&mut buf, 2 * CS).unwrap();
    assert!(buf[..CLUSTER_SIZE / 2].iter().all(|&b| b == 0xEE));
    assert!(buf[CLUSTER_SIZE / 2..].iter().all(|&b| b == 0x33));
}

// =====================================================================
// 3. Snapshot COW
// =====================================================================

#[test]
fn snapshot_cow_preserves_old_data() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "snap_cow.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Write after snapshot: triggers COW
    image.write_at(&vec![0xBB; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();

    // Current state: 0xBB
    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));

    // Revert to snapshot: 0xAA
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn snapshot_cow_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "snap_partial.qcow2", 1 << 20);

    image.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Partial write triggers COW
    image.write_at(&vec![0xBB; 512], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xBB));
    assert!(buf[512..].iter().all(|&b| b == 0xAA));

    // Revert restores all to 0xAA
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn multiple_snapshots_cow_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "multi_snap.qcow2", 1 << 20);

    image.write_at(&vec![0x11; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    image.write_at(&vec![0x22; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("s2").unwrap();

    image.write_at(&vec![0x33; CLUSTER_SIZE], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];

    // Current: 0x33
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x33));

    // Revert to s2: 0x22
    image.snapshot_apply("s2").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22));

    // Revert to s1: 0x11
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));
}

// =====================================================================
// 4. Compressed cluster COW
// =====================================================================

#[test]
fn cow_decompresses_on_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "comp_cow.qcow2", 1 << 20);

    image
        .write_cluster_maybe_compressed(&vec![0xAA; CLUSTER_SIZE], 0)
        .unwrap();
    image.flush().unwrap();

    // Partial write into compressed cluster triggers decompress + COW
    image.write_at(&[0xFF; 128], 256).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..256].iter().all(|&b| b == 0xAA));
    assert!(buf[256..384].iter().all(|&b| b == 0xFF));
    assert!(buf[384..].iter().all(|&b| b == 0xAA));
}

#[test]
fn cow_compressed_cluster_with_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "comp_snap_cow.qcow2", 1 << 20);

    image
        .write_cluster_maybe_compressed(&vec![0xDD; CLUSTER_SIZE], 0)
        .unwrap();
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Partial write triggers decompression COW
    image.write_at(&vec![0xEE; 512], 0).unwrap();
    image.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xEE));
    assert!(buf[512..].iter().all(|&b| b == 0xDD));

    // Revert: original compressed data
    image.snapshot_apply("s1").unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

// =====================================================================
// 5. Backing chain COW
// =====================================================================

#[test]
fn overlay_cow_preserves_base_data() {
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
    base_img.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();

    // Partial write to overlay triggers COW from base
    ov.write_at(&vec![0xBB; 512], 0).unwrap();
    ov.flush().unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xBB));
    assert!(buf[512..].iter().all(|&b| b == 0xAA));

    // Base should be unchanged
    let mut base_img = Qcow2Image::open(&base).unwrap();
    base_img.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn overlay_cow_unallocated_base_reads_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");

    Qcow2Image::create(
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
    .unwrap()
    .flush()
    .unwrap();

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();

    // Partial write to cluster 0 (unallocated in base)
    ov.write_at(&vec![0xCC; 512], 0).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    ov.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xCC));
    assert!(buf[512..].iter().all(|&b| b == 0x00));
}

// =====================================================================
// 6. COW with zero clusters
// =====================================================================

#[test]
fn partial_write_to_zero_cluster() {
    let mut image = create_mem(1 << 20);
    // Unallocated cluster reads as zeros
    // Partial write should allocate and COW zeros for untouched part
    image.write_at(&vec![0xAA; 512], 100).unwrap();

    let mut buf = vec![0u8; CLUSTER_SIZE];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..100].iter().all(|&b| b == 0x00));
    assert!(buf[100..612].iter().all(|&b| b == 0xAA));
    assert!(buf[612..].iter().all(|&b| b == 0x00));
}

// =====================================================================
// 7. Integrity after COW operations
// =====================================================================

#[test]
fn integrity_clean_after_snapshot_cow() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, mut image) = create_file(&dir, "cow_integrity.qcow2", 4 * CS);

    for i in 0..4u64 {
        image.write_at(&vec![(i as u8 + 1) * 0x11; CLUSTER_SIZE], i * CS).unwrap();
    }
    image.flush().unwrap();
    image.snapshot_create("s1").unwrap();

    // Write after snapshot (triggers COW)
    image.write_at(&vec![0xFF; CLUSTER_SIZE], 0).unwrap();
    image.write_at(&vec![0xEE; 512], CS + 100).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean(), "should be clean after COW: {report:?}");
}

#[test]
fn integrity_clean_after_backing_cow() {
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
    base_img.write_at(&vec![0xAA; CLUSTER_SIZE], 0).unwrap();
    base_img.flush().unwrap();
    drop(base_img);

    let mut ov = Qcow2Image::create_overlay(&overlay, &base, 1 << 20).unwrap();
    ov.write_at(&vec![0xBB; 512], 0).unwrap();
    ov.flush().unwrap();

    let report = ov.check_integrity().unwrap();
    assert!(report.is_clean(), "overlay should be clean: {report:?}");
}
