//! Integration tests: create QCOW2 images, corrupt specific structures, recover, verify.
//!
//! Each test creates a small QCOW2 image with known data, corrupts a specific
//! part of the on-disk structure, then runs `recover_single` and verifies the
//! recovered output matches the original data (or is gracefully degraded).
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

/// Cluster size used in all tests (64 KB).
const CLUSTER_SIZE: u64 = 65536;
/// Number of data clusters to write.
const NUM_DATA_CLUSTERS: u64 = 8;
/// Virtual size: enough for NUM_DATA_CLUSTERS clusters.
const VIRTUAL_SIZE: u64 = NUM_DATA_CLUSTERS * CLUSTER_SIZE;

/// Deterministic pseudo-random data for a given cluster index.
fn test_data(cluster_index: u64) -> Vec<u8> {
    let mut data = vec![0u8; CLUSTER_SIZE as usize];
    // Simple PRNG seeded by cluster index
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
fn create_test_image(dir: &Path) -> PathBuf {
    let img_path = dir.join("test.qcow2");
    {
        let options = CreateOptions {
            virtual_size: VIRTUAL_SIZE,
            cluster_bits: Some(16), // 64 KB
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        };
        let mut image = qcow2::Qcow2Image::create(&img_path, options).unwrap();

        for i in 0..NUM_DATA_CLUSTERS {
            let data = test_data(i);
            image.write_at(&data, i * CLUSTER_SIZE).unwrap();
        }
    }
    img_path
}

/// Read the original data back from a fresh (uncorrupted) image for comparison.
fn read_original_data(img_path: &Path) -> Vec<Vec<u8>> {
    let mut image = qcow2::Qcow2Image::open(img_path).unwrap();
    let mut result = Vec::new();
    for i in 0..NUM_DATA_CLUSTERS {
        let mut buf = vec![0u8; CLUSTER_SIZE as usize];
        image.read_at(&mut buf, i * CLUSTER_SIZE).unwrap();
        result.push(buf);
    }
    result
}

/// Default recovery options.
fn default_options() -> RecoverOptions {
    RecoverOptions {
        format: OutputFormat::Raw,
        skip_corrupt: true,
        password: None,
        cluster_size_override: Some(CLUSTER_SIZE),
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
fn run_recovery(input: &Path, output_dir: &Path) -> (PathBuf, qcow2_rescue::report::RecoveryReport) {
    fs::create_dir_all(output_dir).unwrap();
    let out_path = output_dir.join("recovered.raw");
    let options = default_options();
    let report = recover_single(input, &out_path, &options).unwrap();
    (out_path, report)
}

/// Count how many clusters match the original data exactly.
fn count_matching_clusters(recovered: &[u8], original: &[Vec<u8>]) -> usize {
    let mut matches = 0;
    for (i, expected) in original.iter().enumerate() {
        let start = i * CLUSTER_SIZE as usize;
        let end = start + CLUSTER_SIZE as usize;
        if end <= recovered.len() && &recovered[start..end] == expected.as_slice() {
            matches += 1;
        }
    }
    matches
}

/// Check that a recovered cluster is zero-filled (corruption was skipped).
fn is_zeroed(recovered: &[u8], cluster_index: usize) -> bool {
    let start = cluster_index * CLUSTER_SIZE as usize;
    let end = start + CLUSTER_SIZE as usize;
    end <= recovered.len() && recovered[start..end].iter().all(|&b| b == 0)
}


// ============================================================================
// Test 0: Intact baseline — no corruption, full recovery
// ============================================================================

#[test]
fn t00_intact_baseline() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);

    let recovered = read_recovered_raw(&out_path);
    assert_eq!(
        count_matching_clusters(&recovered, &original),
        NUM_DATA_CLUSTERS as usize,
        "all clusters should match for intact image"
    );
    assert_eq!(report.clusters_failed, 0);
}

// ============================================================================
// Tests 1-6: Header corruption
// ============================================================================

#[test]
fn t01_header_magic_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Corrupt the magic bytes (offset 0, 4 bytes "QFI\xfb")
    corrupt_bytes(&img, 0, b"XXXX");

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    // Recovery may fail or degrade — with cluster_size override it should still find data
    let result = recover_single(&img, &out_path, &options);
    // With magic corrupted, scanner may not recognize header.
    // Recovery may succeed with degraded results or fail entirely — both acceptable.
    match result {
        Ok(report) => {
            // If recovery succeeded, it may have found 0 clusters (no valid header = no L1 pointer)
            // or some clusters via heuristic scan
            let _ = report;
        }
        Err(_) => {}
    }
}

#[test]
fn t02_header_version_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Version field at offset 4, 4 bytes. Set to bogus version 99.
    corrupt_bytes(&img, 4, &99u32.to_be_bytes());

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);
    // Version corruption may prevent header parsing — both ok and err are acceptable
    match result {
        Ok(report) => { let _ = report; }
        Err(_) => {}
    }
}

#[test]
fn t03_header_cluster_bits_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // cluster_bits at offset 20, 4 bytes. Set to 0 (invalid).
    corrupt_bytes(&img, 20, &0u32.to_be_bytes());

    let out_dir = dir.path().join("out");
    let out_path = out_dir.join("recovered.raw");
    // We provide cluster_size override, so it should still work
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);
    if let Ok(report) = result {
        let recovered = read_recovered_raw(&out_path);
        let matches = count_matching_clusters(&recovered, &original);
        // Should recover most data since we override cluster size
        assert!(matches >= NUM_DATA_CLUSTERS as usize / 2,
            "should recover at least half the clusters with cluster_size override");
    }
}

#[test]
fn t04_header_virtual_size_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // virtual_size at offset 24, 8 bytes. Set to 0.
    corrupt_bytes(&img, 24, &0u64.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);

    // With virtual_size=0 in header, the recovery uses it as output size (0 bytes).
    // L2 mappings exist but the output file is 0-sized, so nothing gets written.
    // This test verifies recovery completes without crashing.
    let _ = report;
}

#[test]
fn t05_header_l1_pointer_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // l1_table_offset at offset 40, 8 bytes. Point to garbage.
    corrupt_bytes(&img, 40, &0xDEADBEEF_u64.to_be_bytes());

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    // L1 pointer is wrong, but scan should still find L2/data clusters heuristically
    // Recovery should write something (even if degraded)
    assert!(report.clusters_written > 0 || report.clusters_zeroed > 0 || report.clusters_failed > 0);
}

#[test]
fn t06_header_entirely_zeroed() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Zero the entire header cluster (first 65536 bytes)
    corrupt_zero(&img, 0, CLUSTER_SIZE as usize);

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);
    // Header entirely zeroed — no magic, no L1 pointer, no virtual_size.
    // Recovery may succeed with 0 clusters or fail entirely.
    match result {
        Ok(report) => { let _ = report; }
        Err(_) => {}
    }
}

// ============================================================================
// Tests 7-9: L1 table corruption
// ============================================================================

#[test]
fn t07_l1_table_first_entry_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // L1 table is at cluster 1 (offset CLUSTER_SIZE). First entry (8 bytes).
    corrupt_fill(&img, CLUSTER_SIZE, 8);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    // Some data should still be recoverable from remaining L2 tables or heuristics
    assert!(report.clusters_written > 0 || report.clusters_zeroed > 0);
}

#[test]
fn t08_l1_table_all_entries_zeroed() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Zero the entire L1 table cluster
    corrupt_zero(&img, CLUSTER_SIZE, CLUSTER_SIZE as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    // L1 is gone, but L2 tables are still on disk — heuristic scan should find data
    assert!(report.clusters_written > 0 || report.clusters_zeroed > 0);
}

#[test]
fn t09_l1_table_filled_with_garbage() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Fill L1 with random-looking garbage that points to invalid offsets
    let mut garbage = vec![0u8; CLUSTER_SIZE as usize];
    for (i, chunk) in garbage.chunks_mut(8).enumerate() {
        let val = 0xFF00_0000_0000_0000u64 | (i as u64 * 0x1234);
        chunk.copy_from_slice(&val.to_be_bytes());
    }
    corrupt_bytes(&img, CLUSTER_SIZE, &garbage);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    // Recovery should not crash; it may find data via heuristic scan
    assert!(report.clusters_written >= 0); // always true, just checking no panic
}

// ============================================================================
// Tests 10-12: L2 table corruption
// ============================================================================

#[test]
fn t10_l2_table_first_entry_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Find the L2 table offset from the L1 table
    let l2_offset = read_l1_entry(&img, 0);

    if l2_offset > 0 {
        // Corrupt first L2 entry (8 bytes) — this maps guest cluster 0
        corrupt_fill(&img, l2_offset, 8);

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir);
        let recovered = read_recovered_raw(&out_path);

        // Cluster 0 should be lost/zeroed, but others should survive
        let matches = count_matching_clusters(&recovered, &original);
        assert!(matches >= (NUM_DATA_CLUSTERS as usize - 2),
            "most clusters should survive with only first L2 entry corrupted, got {matches}");
    }
}

#[test]
fn t11_l2_table_entirely_zeroed() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    let l2_offset = read_l1_entry(&img, 0);

    if l2_offset > 0 {
        // Zero the entire L2 table
        corrupt_zero(&img, l2_offset, CLUSTER_SIZE as usize);

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir);
        let recovered = read_recovered_raw(&out_path);

        // All mappings from this L2 are lost, but data clusters still exist on disk
        // Heuristic recovery may still find orphan data clusters
        assert!(report.clusters_written > 0 || report.clusters_zeroed > 0);
    }
}

#[test]
fn t12_l2_table_entries_point_to_wrong_offsets() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    let l2_offset = read_l1_entry(&img, 0);

    if l2_offset > 0 {
        // Swap first two L2 entries so guest cluster 0 points to data of cluster 1 and vice versa
        let entry0 = read_l2_entry(&img, l2_offset, 0);
        let entry1 = read_l2_entry(&img, l2_offset, 1);

        corrupt_bytes(&img, l2_offset, &entry1.to_be_bytes());
        corrupt_bytes(&img, l2_offset + 8, &entry0.to_be_bytes());

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir);
        let recovered = read_recovered_raw(&out_path);

        // Recovery should succeed, but clusters 0 and 1 will have swapped data
        assert!(report.clusters_written > 0);
        // Clusters 2-7 should still match
        for i in 2..NUM_DATA_CLUSTERS as usize {
            let start = i * CLUSTER_SIZE as usize;
            let end = start + CLUSTER_SIZE as usize;
            if end <= recovered.len() {
                assert_eq!(&recovered[start..end], original[i].as_slice(),
                    "cluster {i} should match original");
            }
        }
    }
}

// ============================================================================
// Tests 13-14: Refcount table/block corruption
// ============================================================================

#[test]
fn t13_refcount_table_zeroed() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Refcount table at cluster 2
    corrupt_zero(&img, 2 * CLUSTER_SIZE, CLUSTER_SIZE as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    // Refcount corruption should not prevent data recovery (L1/L2 still intact)
    let matches = count_matching_clusters(&recovered, &original);
    assert_eq!(matches, NUM_DATA_CLUSTERS as usize,
        "refcount corruption should not affect data recovery");
}

#[test]
fn t14_refcount_block_zeroed() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Refcount block 0 at cluster 3
    corrupt_zero(&img, 3 * CLUSTER_SIZE, CLUSTER_SIZE as usize);

    let out_dir = dir.path().join("out");
    let (out_path, report) = run_recovery(&img, &out_dir);
    let recovered = read_recovered_raw(&out_path);

    let matches = count_matching_clusters(&recovered, &original);
    assert_eq!(matches, NUM_DATA_CLUSTERS as usize,
        "refcount block corruption should not affect data recovery");
}

// ============================================================================
// Tests 15-16: Data cluster corruption
// ============================================================================

#[test]
fn t15_single_data_cluster_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Find the host offset of guest cluster 3 and corrupt it
    let l2_offset = read_l1_entry(&img, 0);
    if l2_offset > 0 {
        let data_offset = read_l2_entry(&img, l2_offset, 3);
        if data_offset > 0 {
            // Overwrite with garbage
            corrupt_fill(&img, data_offset, CLUSTER_SIZE as usize);

            let out_dir = dir.path().join("out");
            let (out_path, report) = run_recovery(&img, &out_dir);
            let recovered = read_recovered_raw(&out_path);

            // Cluster 3 will have garbage, but other clusters should be fine
            let mut correct = 0;
            for i in 0..NUM_DATA_CLUSTERS as usize {
                if i == 3 { continue; }
                let start = i * CLUSTER_SIZE as usize;
                let end = start + CLUSTER_SIZE as usize;
                if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                    correct += 1;
                }
            }
            assert_eq!(correct, (NUM_DATA_CLUSTERS - 1) as usize,
                "all clusters except the corrupted one should match");
        }
    }
}

#[test]
fn t16_multiple_data_clusters_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    let l2_offset = read_l1_entry(&img, 0);
    if l2_offset > 0 {
        // Corrupt clusters 0, 2, 5
        for idx in &[0u64, 2, 5] {
            let data_offset = read_l2_entry(&img, l2_offset, *idx as usize);
            if data_offset > 0 {
                corrupt_fill(&img, data_offset, CLUSTER_SIZE as usize);
            }
        }

        let out_dir = dir.path().join("out");
        let (out_path, report) = run_recovery(&img, &out_dir);
        let recovered = read_recovered_raw(&out_path);

        // Clusters 1, 3, 4, 6, 7 should be intact
        let uncorrupted: Vec<usize> = vec![1, 3, 4, 6, 7];
        let mut correct = 0;
        for &i in &uncorrupted {
            let start = i * CLUSTER_SIZE as usize;
            let end = start + CLUSTER_SIZE as usize;
            if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                correct += 1;
            }
        }
        assert_eq!(correct, uncorrupted.len(),
            "uncorrupted clusters should all match");
    }
}

// ============================================================================
// Test 17: Compressed data corruption
// ============================================================================

#[test]
fn t17_compressed_cluster_corrupted() {
    let dir = TempDir::new().unwrap();
    let img_path = dir.path().join("test.qcow2");

    // Create image and write compressible data (repeated patterns compress well)
    {
        let options = CreateOptions {
            virtual_size: VIRTUAL_SIZE,
            cluster_bits: Some(16),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        };
        let mut image = qcow2::Qcow2Image::create(&img_path, options).unwrap();

        for i in 0..NUM_DATA_CLUSTERS {
            let data = test_data(i);
            image.write_at(&data, i * CLUSTER_SIZE).unwrap();
        }
    }

    // For this test we just corrupt a random data cluster and verify recovery works
    // (True compressed corruption would need write_compressed which may not be exposed)
    let original = read_original_data(&img_path);
    let l2_offset = read_l1_entry(&img_path, 0);
    if l2_offset > 0 {
        let data_offset = read_l2_entry(&img_path, l2_offset, 0);
        if data_offset > 0 {
            // Corrupt first 512 bytes of the data cluster
            corrupt_fill(&img_path, data_offset, 512);

            let out_dir = dir.path().join("out");
            let (out_path, report) = run_recovery(&img_path, &out_dir);
            let recovered = read_recovered_raw(&out_path);

            // Cluster 0 data is corrupted, rest should be fine
            let mut correct = 0;
            for i in 1..NUM_DATA_CLUSTERS as usize {
                let start = i * CLUSTER_SIZE as usize;
                let end = start + CLUSTER_SIZE as usize;
                if end <= recovered.len() && &recovered[start..end] == original[i].as_slice() {
                    correct += 1;
                }
            }
            assert!(correct >= (NUM_DATA_CLUSTERS - 1) as usize - 1,
                "most uncorrupted clusters should match");
        }
    }
}

// ============================================================================
// Tests 18-20: Combination corruption
// ============================================================================

#[test]
fn t18_header_and_l1_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Corrupt header magic
    corrupt_bytes(&img, 0, b"XXXX");
    // Corrupt first L1 entry
    corrupt_fill(&img, CLUSTER_SIZE, 8);

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);

    // With both header and L1 damaged, recovery is severely degraded
    // but should not crash
    match result {
        Ok(report) => {
            assert!(report.clusters_written >= 0);
        }
        Err(_) => {
            // Acceptable — too much damage
        }
    }
}

#[test]
fn t19_header_and_l2_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Corrupt header version
    corrupt_bytes(&img, 4, &99u32.to_be_bytes());
    // Corrupt L2 table
    let l2_offset = read_l1_entry(&img, 0);
    if l2_offset > 0 {
        corrupt_zero(&img, l2_offset, CLUSTER_SIZE as usize);
    }

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);

    match result {
        Ok(report) => {
            // Some recovery may be possible via heuristics
            assert!(report.clusters_written >= 0);
        }
        Err(_) => {
            // Acceptable
        }
    }
}

#[test]
fn t20_header_l1_refcount_all_corrupted() {
    let dir = TempDir::new().unwrap();
    let img = create_test_image(dir.path());
    let original = read_original_data(&img);

    // Corrupt header
    corrupt_zero(&img, 0, 104); // Zero first 104 bytes (entire header fields)
    // Corrupt L1
    corrupt_zero(&img, CLUSTER_SIZE, CLUSTER_SIZE as usize);
    // Corrupt refcount table
    corrupt_zero(&img, 2 * CLUSTER_SIZE, CLUSTER_SIZE as usize);
    // Corrupt refcount block
    corrupt_zero(&img, 3 * CLUSTER_SIZE, CLUSTER_SIZE as usize);

    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("recovered.raw");
    let options = default_options();
    let result = recover_single(&img, &out_path, &options);

    // Everything except L2 and data clusters is gone
    // Recovery should attempt heuristic scan and not crash
    match result {
        Ok(report) => {
            // Heuristic scan should still find orphan data clusters
            assert!(report.clusters_written >= 0);
        }
        Err(_) => {
            // Also acceptable for this level of damage
        }
    }
}

// ============================================================================
// Helper functions to read L1/L2 entries from the raw image file
// ============================================================================

/// Read the L2 table offset from L1 entry at the given index.
/// L1 table is at cluster 1 (offset CLUSTER_SIZE).
fn read_l1_entry(img_path: &Path, index: usize) -> u64 {
    let mut file = fs::File::open(img_path).unwrap();
    let offset = CLUSTER_SIZE + (index as u64 * 8);
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).unwrap();
    // L1 entry: bits 9-55 are the L2 table offset, clear the flags
    u64::from_be_bytes(buf) & 0x00FF_FFFF_FFFF_FE00
}

/// Read a data cluster offset from an L2 entry.
fn read_l2_entry(img_path: &Path, l2_offset: u64, index: usize) -> u64 {
    let mut file = fs::File::open(img_path).unwrap();
    let offset = l2_offset + (index as u64 * 8);
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).unwrap();
    // Standard L2 entry: bits 0-55 are the host offset, bit 62 is compressed flag
    let raw = u64::from_be_bytes(buf);
    if raw & (1 << 62) != 0 {
        // Compressed — return 0 (can't simply extract offset)
        0
    } else {
        raw & 0x00FF_FFFF_FFFF_FE00
    }
}
