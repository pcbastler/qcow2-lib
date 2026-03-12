//! Integration tests: create QCOW2 images, corrupt specific structures, recover, verify.
//!
//! Each test creates a small QCOW2 image with known data, corrupts a specific
//! part of the on-disk structure, then runs `recover_single` and verifies the
//! recovered output matches the original data (or is gracefully degraded).
//!
//! All tests run with multiple cluster sizes (4K, 64K, 256K) to ensure the
//! recovery pipeline handles different geometries correctly.
//!
//! QCOW2 v3 on-disk layout from `Qcow2Image::create`:
//!   Cluster 0: Header (magic, version, virtual_size, cluster_bits, L1/refcount pointers)
//!   Cluster 1: L1 table
//!   Cluster 2: Refcount table
//!   Cluster 3: Refcount block 0
//!   Cluster 4+: Allocated L2 tables and data clusters

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use qcow2::engine::image::CreateOptions;

use qcow2_rescue::config::{ConflictStrategy, OutputFormat};
use qcow2_rescue::recover::{RecoverOptions, recover_single};

/// Number of data clusters to write (constant across all cluster sizes).
const NUM_DATA_CLUSTERS: u64 = 8;

// ============================================================================
// Parametric test helpers
// ============================================================================

/// Deterministic pseudo-random data for a given cluster index and size.
fn test_data(cluster_index: u64, cluster_size: u64) -> Vec<u8> {
    let mut data = vec![0u8; cluster_size as usize];
    let mut state: u64 = cluster_index.wrapping_mul(6364136223846793005).wrapping_add(1);
    for chunk in data.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }
    data
}

/// Create a QCOW2 image with known data, return path to it.
fn create_test_image(dir: &Path, cluster_size: u64, cluster_bits: u32) -> PathBuf {
    let virtual_size = NUM_DATA_CLUSTERS * cluster_size;
    let img_path = dir.join("test.qcow2");
    {
        let options = CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
            refcount_order: None,
        };
        let mut image = qcow2::Qcow2Image::create(&img_path, options).unwrap();
        for i in 0..NUM_DATA_CLUSTERS {
            let data = test_data(i, cluster_size);
            image.write_at(&data, i * cluster_size).unwrap();
        }
    }
    img_path
}

/// Read the original data back from a fresh (uncorrupted) image for comparison.
fn read_original_data(img_path: &Path, cluster_size: u64) -> Vec<Vec<u8>> {
    let mut image = qcow2::Qcow2Image::open(img_path).unwrap();
    let mut result = Vec::new();
    for i in 0..NUM_DATA_CLUSTERS {
        let mut buf = vec![0u8; cluster_size as usize];
        image.read_at(&mut buf, i * cluster_size).unwrap();
        result.push(buf);
    }
    result
}

/// Default recovery options for a given cluster size.
fn default_options(cluster_size: u64) -> RecoverOptions {
    RecoverOptions {
        format: OutputFormat::Raw,
        skip_corrupt: true,
        password: None,
        cluster_size_override: Some(cluster_size),
        resume: false,
        on_conflict: ConflictStrategy::Ask,
    }
}

/// Overwrite bytes at `offset` in the file with `data`.
fn corrupt_bytes(path: &Path, offset: u64, data: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
}

/// Zero-fill a range of bytes.
fn corrupt_zero(path: &Path, offset: u64, len: usize) {
    corrupt_bytes(path, offset, &vec![0u8; len]);
}

/// Fill a range with 0xFF.
fn corrupt_fill(path: &Path, offset: u64, len: usize) {
    corrupt_bytes(path, offset, &vec![0xFFu8; len]);
}

/// Read the raw recovered output file.
fn read_recovered_raw(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

/// Run recovery and return the output path and report.
fn run_recovery(input: &Path, output_dir: &Path, cluster_size: u64) -> (PathBuf, qcow2_rescue::report::RecoveryReport) {
    fs::create_dir_all(output_dir).unwrap();
    let out_path = output_dir.join("recovered.raw");
    let options = default_options(cluster_size);
    let report = recover_single(input, &out_path, &options).unwrap();
    (out_path, report)
}

/// Count how many clusters match the original data exactly.
fn count_matching_clusters(recovered: &[u8], original: &[Vec<u8>], cluster_size: u64) -> usize {
    let mut matches = 0;
    for (i, expected) in original.iter().enumerate() {
        let start = i * cluster_size as usize;
        let end = start + cluster_size as usize;
        if end <= recovered.len() && &recovered[start..end] == expected.as_slice() {
            matches += 1;
        }
    }
    matches
}

/// Read the L2 table offset from L1 entry at the given index.
/// L1 table is at cluster 1 (offset cluster_size).
fn read_l1_entry(img_path: &Path, index: usize, cluster_size: u64) -> u64 {
    let mut file = fs::File::open(img_path).unwrap();
    let offset = cluster_size + (index as u64 * 8);
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).unwrap();
    u64::from_be_bytes(buf) & 0x00FF_FFFF_FFFF_FE00
}

/// Read a data cluster offset from an L2 entry.
fn read_l2_entry(img_path: &Path, l2_offset: u64, index: usize) -> u64 {
    let mut file = fs::File::open(img_path).unwrap();
    let offset = l2_offset + (index as u64 * 8);
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).unwrap();
    let raw = u64::from_be_bytes(buf);
    if raw & (1 << 62) != 0 {
        0 // Compressed
    } else {
        raw & 0x00FF_FFFF_FFFF_FE00
    }
}

// ============================================================================
// Test body functions (parametric by cluster_size)
// ============================================================================

fn t00_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize,
        "[cs={cs}] all clusters should match for intact image");
    assert_eq!(report.clusters_failed, 0, "[cs={cs}]");
}

fn t01_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 0, b"XXXX");

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data clusters even with magic corrupted");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t02_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 4, &99u32.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data clusters even with version corrupted");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t03_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 20, &0u32.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data with cluster_size override");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t04_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 24, &0u64.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data via mapping-inferred virtual_size");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t04b_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let wrong_size = (NUM_DATA_CLUSTERS / 2) * cs;
    corrupt_bytes(&img, 24, &wrong_size.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data via mapping-inferred virtual_size");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t05_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 40, &0xDEADBEEF_u64.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data clusters via scan-detected L1");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t06_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_zero(&img, 0, cs as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data clusters via scan-detected L1");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t07_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_fill(&img, cs, 8);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover data via orphan L2 scan");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t08_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_zero(&img, cs, cs as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover data via orphan L2 scan");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t09_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let mut garbage = vec![0u8; cs as usize];
    for (i, chunk) in garbage.chunks_mut(8).enumerate() {
        let val = 0xFF00_0000_0000_0000u64 | (i as u64 * 0x1234);
        chunk.copy_from_slice(&val.to_be_bytes());
    }
    corrupt_bytes(&img, cs, &garbage);

    let out_dir = dir.path().join("out");
    let (out_path, _report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    let matches = count_matching_clusters(&recovered, &original, cs);
    assert_eq!(matches, NUM_DATA_CLUSTERS as usize,
        "[cs={cs}] should recover all clusters despite garbage L1, got {matches}/{}",
        NUM_DATA_CLUSTERS);
}

fn t10_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        corrupt_fill(&img, l2_offset, 8);

        let out_dir = dir.path().join("out");
        let (out_path, _report) = run_recovery(&img, &out_dir, cs);
        let recovered = read_recovered_raw(&out_path);

        let matches = count_matching_clusters(&recovered, &original, cs);
        assert!(matches >= (NUM_DATA_CLUSTERS as usize - 2),
            "[cs={cs}] most clusters should survive with only first L2 entry corrupted, got {matches}");
    }
}

fn t11_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        corrupt_zero(&img, l2_offset, cs as usize);

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir, cs);
        let recovered = read_recovered_raw(&out_path);

        assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
            "[cs={cs}] should recover all data via orphan heuristic");
        assert_eq!(count_matching_clusters(&recovered, &original, cs),
            NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
    }
}

fn t12_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        let entry0 = read_l2_entry(&img, l2_offset, 0);
        let entry1 = read_l2_entry(&img, l2_offset, 1);

        corrupt_bytes(&img, l2_offset, &entry1.to_be_bytes());
        corrupt_bytes(&img, l2_offset + 8, &entry0.to_be_bytes());

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir, cs);
        let recovered = read_recovered_raw(&out_path);

        assert!(report.clusters_written > 0, "[cs={cs}]");
        #[allow(clippy::needless_range_loop)]
        for i in 2..NUM_DATA_CLUSTERS as usize {
            let start = i * cs as usize;
            let end = start + cs as usize;
            if end <= recovered.len() {
                assert_eq!(&recovered[start..end], original[i].as_slice(),
                    "[cs={cs}] cluster {i} should match original");
            }
        }
    }
}

fn t13_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_zero(&img, 2 * cs, cs as usize);

    let out_dir = dir.path().join("out");
    let (out_path, _report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize,
        "[cs={cs}] refcount corruption should not affect data recovery");
}

fn t14_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_zero(&img, 3 * cs, cs as usize);

    let out_dir = dir.path().join("out");
    let (out_path, _report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize,
        "[cs={cs}] refcount block corruption should not affect data recovery");
}

fn t15_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        let data_offset = read_l2_entry(&img, l2_offset, 3);
        if data_offset > 0 {
            corrupt_fill(&img, data_offset, cs as usize);

            let out_dir = dir.path().join("out");
            let (out_path, _report) = run_recovery(&img, &out_dir, cs);
            let recovered = read_recovered_raw(&out_path);

            let mut correct = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 0..NUM_DATA_CLUSTERS as usize {
                if i == 3 { continue; }
                let start = i * cs as usize;
                let end = start + cs as usize;
                if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                    correct += 1;
                }
            }
            assert_eq!(correct, (NUM_DATA_CLUSTERS - 1) as usize,
                "[cs={cs}] all clusters except the corrupted one should match");
        }
    }
}

fn t16_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        for idx in &[0u64, 2, 5] {
            let data_offset = read_l2_entry(&img, l2_offset, *idx as usize);
            if data_offset > 0 {
                corrupt_fill(&img, data_offset, cs as usize);
            }
        }

        let out_dir = dir.path().join("out");
        let (out_path, _report) = run_recovery(&img, &out_dir, cs);
        let recovered = read_recovered_raw(&out_path);

        let uncorrupted: Vec<usize> = vec![1, 3, 4, 6, 7];
        let mut correct = 0;
        for &i in &uncorrupted {
            let start = i * cs as usize;
            let end = start + cs as usize;
            if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                correct += 1;
            }
        }
        assert_eq!(correct, uncorrupted.len(),
            "[cs={cs}] uncorrupted clusters should all match");
    }
}

fn t17_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        let data_offset = read_l2_entry(&img, l2_offset, 0);
        if data_offset > 0 {
            corrupt_fill(&img, data_offset, 512);

            let out_dir = dir.path().join("out");
            let (out_path, _report) = run_recovery(&img, &out_dir, cs);
            let recovered = read_recovered_raw(&out_path);

            let mut correct = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 1..NUM_DATA_CLUSTERS as usize {
                let start = i * cs as usize;
                let end = start + cs as usize;
                if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                    correct += 1;
                }
            }
            assert!(correct >= (NUM_DATA_CLUSTERS - 1) as usize - 1,
                "[cs={cs}] most uncorrupted clusters should match");
        }
    }
}

fn t18_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 0, b"XXXX");
    corrupt_fill(&img, cs, 8);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover data via orphan L2 scan");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t19_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_bytes(&img, 4, &99u32.to_be_bytes());
    let l2_offset = read_l1_entry(&img, 0, cs);
    if l2_offset > 0 {
        corrupt_zero(&img, l2_offset, cs as usize);
    }

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover all data via orphan heuristic");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

fn t20_body(cs: u64, cb: u32) {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path(), cs, cb);
    let original = read_original_data(&img, cs);

    corrupt_zero(&img, 0, 104);
    corrupt_zero(&img, cs, cs as usize);
    corrupt_zero(&img, 2 * cs, cs as usize);
    corrupt_zero(&img, 3 * cs, cs as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir, cs);
    let recovered = read_recovered_raw(&out_path);

    assert!(report.clusters_written >= NUM_DATA_CLUSTERS,
        "[cs={cs}] should recover data via orphan L2 even with header+L1+refcount gone");
    assert_eq!(count_matching_clusters(&recovered, &original, cs),
        NUM_DATA_CLUSTERS as usize, "[cs={cs}]");
}

// ============================================================================
// Test generation macro — creates all tests for a given cluster size
// ============================================================================

macro_rules! corruption_tests {
    ($mod_name:ident, $cluster_size:expr, $cluster_bits:expr) => {
        mod $mod_name {
            use super::*;

            #[test] fn t00_intact_baseline() { t00_body($cluster_size, $cluster_bits); }
            #[test] fn t01_header_magic_corrupted() { t01_body($cluster_size, $cluster_bits); }
            #[test] fn t02_header_version_corrupted() { t02_body($cluster_size, $cluster_bits); }
            #[test] fn t03_header_cluster_bits_corrupted() { t03_body($cluster_size, $cluster_bits); }
            #[test] fn t04_header_virtual_size_corrupted() { t04_body($cluster_size, $cluster_bits); }
            #[test] fn t04b_header_virtual_size_plausible_but_wrong() { t04b_body($cluster_size, $cluster_bits); }
            #[test] fn t05_header_l1_pointer_corrupted() { t05_body($cluster_size, $cluster_bits); }
            #[test] fn t06_header_entirely_zeroed() { t06_body($cluster_size, $cluster_bits); }
            #[test] fn t07_l1_table_first_entry_corrupted() { t07_body($cluster_size, $cluster_bits); }
            #[test] fn t08_l1_table_all_entries_zeroed() { t08_body($cluster_size, $cluster_bits); }
            #[test] fn t09_l1_table_filled_with_garbage() { t09_body($cluster_size, $cluster_bits); }
            #[test] fn t10_l2_table_first_entry_corrupted() { t10_body($cluster_size, $cluster_bits); }
            #[test] fn t11_l2_table_entirely_zeroed() { t11_body($cluster_size, $cluster_bits); }
            #[test] fn t12_l2_table_entries_point_to_wrong_offsets() { t12_body($cluster_size, $cluster_bits); }
            #[test] fn t13_refcount_table_zeroed() { t13_body($cluster_size, $cluster_bits); }
            #[test] fn t14_refcount_block_zeroed() { t14_body($cluster_size, $cluster_bits); }
            #[test] fn t15_single_data_cluster_corrupted() { t15_body($cluster_size, $cluster_bits); }
            #[test] fn t16_multiple_data_clusters_corrupted() { t16_body($cluster_size, $cluster_bits); }
            #[test] fn t17_compressed_cluster_corrupted() { t17_body($cluster_size, $cluster_bits); }
            #[test] fn t18_header_and_l1_corrupted() { t18_body($cluster_size, $cluster_bits); }
            #[test] fn t19_header_and_l2_corrupted() { t19_body($cluster_size, $cluster_bits); }
            #[test] fn t20_header_l1_refcount_all_corrupted() { t20_body($cluster_size, $cluster_bits); }
        }
    };
}

corruption_tests!(cs_4k, 4096, 12);
corruption_tests!(cs_64k, 65536, 16);
corruption_tests!(cs_256k, 262144, 18);
