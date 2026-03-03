//! Stress tests: complex snapshot trees, heavy write patterns, data integrity
//! verification with diverse bitmasks, and chaos-cycle consistency checks.
//!
//! These tests exercise the engine under realistic workloads that go beyond
//! the basic happy-path integration tests.

mod common;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use std::collections::HashMap;
use std::path::Path;

/// Helper: run `qemu-img check` and assert success.
fn assert_qemu_check(path: &Path) {
    let output = std::process::Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(path)
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "qemu-img check failed for {}: stdout={} stderr={}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Generate a deterministic pattern for a given offset and generation.
/// Each (offset, generation) pair produces unique data, so we can verify
/// exactly which write is visible at any point.
fn make_pattern(offset: u64, generation: u8, len: usize) -> Vec<u8> {
    let seed = offset.wrapping_mul(2654435761)
        ^ (generation as u64).wrapping_mul(0x9E3779B97F4A7C15);
    let mut data = vec![0u8; len];
    let mut state = seed;
    for byte in data.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *byte = (state >> 33) as u8;
    }
    data
}

// ============================================================
// 1. Multi-Snapshot Chain: 8 snapshots with COW writes between each
// ============================================================

#[test]
fn snapshot_chain_8_deep_with_cow_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.qcow2");
    let cluster_size = 65536u64;
    let virtual_size = 8 * 1024 * 1024; // 8 MB

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Track what data should be visible at the active state
    let mut expected: HashMap<u64, Vec<u8>> = HashMap::new();

    // Write initial data across several clusters
    for i in 0..4u64 {
        let offset = i * cluster_size;
        let pattern = make_pattern(offset, 0, cluster_size as usize);
        image.write_at(&pattern, offset).unwrap();
        expected.insert(offset, pattern);
    }
    image.flush().unwrap();

    // Create 8 snapshots, writing new data between each
    for snap_gen in 1..=8u8 {
        image
            .snapshot_create(&format!("snap_{snap_gen}"))
            .unwrap();
        image.flush().unwrap();

        // Each generation writes to 2 clusters: one new, one overwriting old
        let new_offset = (3 + snap_gen as u64) * cluster_size;
        let overwrite_offset = ((snap_gen as u64 - 1) % 4) * cluster_size;

        let new_data = make_pattern(new_offset, snap_gen, cluster_size as usize);
        image.write_at(&new_data, new_offset).unwrap();
        expected.insert(new_offset, new_data);

        let overwrite_data =
            make_pattern(overwrite_offset, snap_gen, cluster_size as usize);
        image.write_at(&overwrite_data, overwrite_offset).unwrap();
        expected.insert(overwrite_offset, overwrite_data);

        image.flush().unwrap();
    }

    // Verify all expected data
    for (&offset, expected_data) in &expected {
        let mut buf = vec![0u8; expected_data.len()];
        image.read_at(&mut buf, offset).unwrap();
        assert_eq!(
            &buf, expected_data,
            "data mismatch at offset 0x{offset:x} after 8 snapshot chain"
        );
    }

    // Verify 8 snapshots exist
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 8, "should have 8 snapshots");

    // Integrity check
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "8-deep snapshot chain should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 2. Snapshot Tree: branch, apply, diverge
// ============================================================

#[test]
fn snapshot_tree_branch_apply_diverge() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 8 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Base state: write to clusters 0 and 1
    let base_c0 = make_pattern(0, 0, cluster_size as usize);
    let base_c1 = make_pattern(cluster_size, 0, cluster_size as usize);
    image.write_at(&base_c0, 0).unwrap();
    image.write_at(&base_c1, cluster_size).unwrap();
    image.flush().unwrap();

    // Snapshot "base"
    image.snapshot_create("base").unwrap();
    image.flush().unwrap();

    // Branch A: overwrite cluster 0 with generation-A data
    let branch_a_c0 = make_pattern(0, 10, cluster_size as usize);
    image.write_at(&branch_a_c0, 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("branch_a").unwrap();
    image.flush().unwrap();

    // Further writes on branch A
    let branch_a2_c2 = make_pattern(2 * cluster_size, 11, cluster_size as usize);
    image.write_at(&branch_a2_c2, 2 * cluster_size).unwrap();
    image.flush().unwrap();
    image.snapshot_create("branch_a2").unwrap();
    image.flush().unwrap();

    // Now revert to "base" to start branch B
    image.snapshot_apply("base").unwrap();
    image.flush().unwrap();

    // Verify we see base state after apply
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(
        buf, base_c0,
        "after apply(base), cluster 0 should be base data"
    );

    // Branch B: overwrite cluster 1 with generation-B data
    let branch_b_c1 = make_pattern(cluster_size, 20, cluster_size as usize);
    image.write_at(&branch_b_c1, cluster_size).unwrap();
    image.flush().unwrap();
    image.snapshot_create("branch_b").unwrap();
    image.flush().unwrap();

    // Cluster 0 = base, cluster 1 = branch_b
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, base_c0, "cluster 0 should still be base on branch B");
    image.read_at(&mut buf, cluster_size).unwrap();
    assert_eq!(
        buf, branch_b_c1,
        "cluster 1 should be branch_b data"
    );

    // 4 snapshots total: base, branch_a, branch_a2, branch_b
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 4, "should have 4 snapshots");

    // Integrity
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "snapshot tree should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 3. Heavy scattered writes with pattern verification
// ============================================================

#[test]
fn heavy_scattered_writes_with_pattern_verification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scatter.qcow2");
    let cluster_size = 65536u64;
    let virtual_size = 64 * 1024 * 1024; // 64 MB

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Write to 200 different offsets across the image with diverse patterns.
    // Mix cluster-aligned and unaligned, various sizes.
    let mut writes: Vec<(u64, Vec<u8>)> = Vec::new();

    for i in 0..200u64 {
        // Spread writes across the virtual space using a hash-like offset
        let base = (i.wrapping_mul(0x517CC1B727220A95) % (virtual_size / cluster_size))
            * cluster_size;

        // Vary write sizes: 512, 4096, partial cluster, full cluster
        let size = match i % 4 {
            0 => 512,
            1 => 4096,
            2 => 16384,
            _ => cluster_size as usize,
        };

        let data = make_pattern(base, (i & 0xFF) as u8, size);
        image.write_at(&data, base).unwrap();
        writes.push((base, data));
    }
    image.flush().unwrap();

    // Build expected full-cluster state by replaying all writes in order.
    // This catches residual data from earlier larger writes that a partial
    // overwrite doesn't touch.
    let mut cluster_state: HashMap<u64, Vec<u8>> = HashMap::new();
    for (offset, data) in &writes {
        let state = cluster_state
            .entry(*offset)
            .or_insert_with(|| vec![0u8; cluster_size as usize]);
        state[..data.len()].copy_from_slice(data);
    }

    for (offset, expected) in &cluster_state {
        let mut buf = vec![0u8; cluster_size as usize];
        image.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, expected,
            "full cluster mismatch at offset 0x{offset:x} after scattered writes"
        );
    }

    // Integrity check
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "200-write scatter should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 4. Bitmask patterns: structured data, read-back verification
// ============================================================

#[test]
fn bitmask_pattern_verification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bitmask.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 16 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Pattern 1: Counting bytes (0x00, 0x01, ..., 0xFF, 0x00, ...)
    let counting: Vec<u8> = (0..cluster_size as usize).map(|i| i as u8).collect();
    image.write_at(&counting, 0).unwrap();

    // Pattern 2: Alternating bits (0xAA, 0x55 repeating)
    let alternating: Vec<u8> = (0..cluster_size as usize)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    image.write_at(&alternating, cluster_size).unwrap();

    // Pattern 3: Walking ones (each byte has a different single bit set)
    let walking_ones: Vec<u8> = (0..cluster_size as usize)
        .map(|i| 1u8 << (i % 8))
        .collect();
    image.write_at(&walking_ones, 2 * cluster_size).unwrap();

    // Pattern 4: PRNG sequence (deterministic pseudo-random)
    let prng = make_pattern(3 * cluster_size, 42, cluster_size as usize);
    image.write_at(&prng, 3 * cluster_size).unwrap();

    // Pattern 5: All 0xFF (bitwise inverse of zero)
    let all_ff = vec![0xFFu8; cluster_size as usize];
    image.write_at(&all_ff, 4 * cluster_size).unwrap();

    // Pattern 6: 32-bit little-endian offset markers
    let mut offset_markers = vec![0u8; cluster_size as usize];
    for i in (0..cluster_size as usize).step_by(4) {
        let val = (5 * cluster_size + i as u64) as u32;
        offset_markers[i..i + 4].copy_from_slice(&val.to_le_bytes());
    }
    image.write_at(&offset_markers, 5 * cluster_size).unwrap();

    image.flush().unwrap();

    // Read back and verify all patterns
    let patterns: Vec<(u64, Vec<u8>, &str)> = vec![
        (0, counting, "counting"),
        (cluster_size, alternating, "alternating 0xAA/0x55"),
        (2 * cluster_size, walking_ones, "walking ones"),
        (3 * cluster_size, prng, "PRNG"),
        (4 * cluster_size, all_ff, "all 0xFF"),
        (5 * cluster_size, offset_markers, "offset markers"),
    ];

    for (offset, expected, name) in &patterns {
        let mut buf = vec![0u8; expected.len()];
        image.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, expected,
            "pattern '{name}' mismatch at offset 0x{offset:x}"
        );
    }

    // Now create a snapshot and overwrite some patterns
    image.snapshot_create("before_overwrite").unwrap();
    image.flush().unwrap();

    // Overwrite patterns 1 and 3 with inverted data
    let inv_counting: Vec<u8> = patterns[0].1.iter().map(|b| !b).collect();
    image.write_at(&inv_counting, 0).unwrap();

    let inv_walking: Vec<u8> = patterns[2].1.iter().map(|b| !b).collect();
    image.write_at(&inv_walking, 2 * cluster_size).unwrap();
    image.flush().unwrap();

    // Verify overwritten patterns
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, inv_counting, "inverted counting pattern mismatch");

    image.read_at(&mut buf, 2 * cluster_size).unwrap();
    assert_eq!(buf, inv_walking, "inverted walking ones mismatch");

    // Un-overwritten patterns should still match
    image.read_at(&mut buf, cluster_size).unwrap();
    assert_eq!(buf, patterns[1].1, "alternating pattern should survive COW");

    image.read_at(&mut buf, 4 * cluster_size).unwrap();
    assert_eq!(buf, patterns[4].1, "all-FF pattern should survive COW");

    // Apply snapshot: revert to original patterns
    image.snapshot_apply("before_overwrite").unwrap();
    image.flush().unwrap();

    for (offset, expected, name) in &patterns {
        let mut buf = vec![0u8; expected.len()];
        image.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, expected,
            "pattern '{name}' should be restored after snapshot apply"
        );
    }

    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "bitmask test should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 5. Chaos cycle: write → snapshot → overwrite → delete → repeat
// ============================================================

#[test]
fn chaos_cycle_write_snapshot_delete() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chaos.qcow2");
    let cluster_size = 65536u64;
    let virtual_size = 16 * 1024 * 1024;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    // 10 rounds of: write data → snapshot → overwrite → (maybe delete old snap)
    let mut active_snapshots: Vec<String> = Vec::new();
    let mut expected_active: HashMap<u64, Vec<u8>> = HashMap::new();

    for round in 0..10u8 {
        // Write to 5 clusters per round
        for c in 0..5u64 {
            let offset = ((round as u64 * 5 + c) % (virtual_size / cluster_size)) * cluster_size;
            let data = make_pattern(offset, round, cluster_size as usize);
            image.write_at(&data, offset).unwrap();
            expected_active.insert(offset, data);
        }
        image.flush().unwrap();

        // Create snapshot
        let snap_name = format!("round_{round}");
        image.snapshot_create(&snap_name).unwrap();
        image.flush().unwrap();
        active_snapshots.push(snap_name);

        // Delete oldest snapshot every 3 rounds to stress refcount management
        if round % 3 == 2 && !active_snapshots.is_empty() {
            let to_delete = active_snapshots.remove(0);
            image.snapshot_delete(&to_delete).unwrap();
            image.flush().unwrap();
        }
    }

    // Verify all active data
    for (offset, expected) in &expected_active {
        let mut buf = vec![0u8; expected.len()];
        image.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, expected,
            "chaos cycle: data mismatch at offset 0x{offset:x}"
        );
    }

    // Integrity check
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "chaos cycle should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 6. Snapshot chain with apply-back and forward writes
// ============================================================

#[test]
fn snapshot_apply_back_and_forward() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("apply-fwd.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 8 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // State A: write pattern to cluster 0
    let state_a = make_pattern(0, 1, cluster_size as usize);
    image.write_at(&state_a, 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("state_a").unwrap();
    image.flush().unwrap();

    // State B: overwrite cluster 0, write cluster 1
    let state_b_c0 = make_pattern(0, 2, cluster_size as usize);
    let state_b_c1 = make_pattern(cluster_size, 2, cluster_size as usize);
    image.write_at(&state_b_c0, 0).unwrap();
    image.write_at(&state_b_c1, cluster_size).unwrap();
    image.flush().unwrap();
    image.snapshot_create("state_b").unwrap();
    image.flush().unwrap();

    // State C: overwrite cluster 0 again
    let state_c_c0 = make_pattern(0, 3, cluster_size as usize);
    image.write_at(&state_c_c0, 0).unwrap();
    image.flush().unwrap();
    image.snapshot_create("state_c").unwrap();
    image.flush().unwrap();

    // Now go back to A
    image.snapshot_apply("state_a").unwrap();
    image.flush().unwrap();
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, state_a, "after apply(A), cluster 0 = state A");

    // Write new data (state D, branching from A)
    let state_d_c0 = make_pattern(0, 4, cluster_size as usize);
    let state_d_c2 = make_pattern(2 * cluster_size, 4, cluster_size as usize);
    image.write_at(&state_d_c0, 0).unwrap();
    image.write_at(&state_d_c2, 2 * cluster_size).unwrap();
    image.flush().unwrap();
    image.snapshot_create("state_d").unwrap();
    image.flush().unwrap();

    // Go back to B, verify
    image.snapshot_apply("state_b").unwrap();
    image.flush().unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, state_b_c0, "after apply(B), cluster 0 = state B");
    image.read_at(&mut buf, cluster_size).unwrap();
    assert_eq!(buf, state_b_c1, "after apply(B), cluster 1 = state B");

    // Go to C, verify
    image.snapshot_apply("state_c").unwrap();
    image.flush().unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, state_c_c0, "after apply(C), cluster 0 = state C");

    // Go to D, verify
    image.snapshot_apply("state_d").unwrap();
    image.flush().unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, state_d_c0, "after apply(D), cluster 0 = state D");
    image.read_at(&mut buf, 2 * cluster_size).unwrap();
    assert_eq!(buf, state_d_c2, "after apply(D), cluster 2 = state D");

    // All 4 snapshots + integrity
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 4);

    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "apply-back-and-forward should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 7. Large sequential write + cross-validation with qemu-io
// ============================================================

#[test]
fn large_sequential_write_cross_validation() {
    if !common::has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large-seq.qcow2");
    let cluster_size = 65536u64;
    let num_clusters = 100u64;
    let virtual_size = (num_clusters + 10) * cluster_size;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Write 100 clusters with distinct patterns
    let mut all_patterns: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 0..num_clusters {
        let offset = i * cluster_size;
        let pattern = make_pattern(offset, (i & 0xFF) as u8, cluster_size as usize);
        image.write_at(&pattern, offset).unwrap();
        all_patterns.push((offset, pattern));
    }
    image.flush().unwrap();
    drop(image);

    assert_qemu_check(&path);

    // Re-open read-only and verify all patterns
    let mut image = Qcow2Image::open(&path).unwrap();
    for (offset, expected) in &all_patterns {
        let mut buf = vec![0u8; expected.len()];
        image.read_at(&mut buf, *offset).unwrap();
        assert_eq!(
            &buf, expected,
            "100-cluster write: mismatch at offset 0x{offset:x}"
        );
    }

    // Also verify with qemu-io for a sample of offsets
    let test_img = common::TestImage::wrap(path.clone(), dir);
    for &idx in &[0u64, 25, 50, 75, 99] {
        let offset = idx * cluster_size;
        let qemu_data = test_img.read_via_qemu(offset, 512);
        assert_eq!(
            &qemu_data[..],
            &all_patterns[idx as usize].1[..512],
            "qemu-io cross-validation failed at cluster {idx}"
        );
    }
}

// ============================================================
// 8. Delete all snapshots then repair
// ============================================================

#[test]
fn delete_all_snapshots_then_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delete-all.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 8 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Build up 5 snapshots with data
    for gen in 0..5u8 {
        let data = make_pattern(gen as u64 * cluster_size, gen, cluster_size as usize);
        image.write_at(&data, gen as u64 * cluster_size).unwrap();
        image.flush().unwrap();
        image.snapshot_create(&format!("snap_{gen}")).unwrap();
        image.flush().unwrap();
    }

    // Final write after last snapshot
    let final_data = make_pattern(5 * cluster_size, 99, cluster_size as usize);
    image.write_at(&final_data, 5 * cluster_size).unwrap();
    image.flush().unwrap();

    // Now delete all 5 snapshots
    for gen in 0..5u8 {
        image.snapshot_delete(&format!("snap_{gen}")).unwrap();
        image.flush().unwrap();
    }

    assert_eq!(image.snapshot_list().unwrap().len(), 0);

    // Active data should still be intact
    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 5 * cluster_size).unwrap();
    assert_eq!(buf, final_data, "final write should survive snapshot deletion");

    // Integrity check
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "after deleting all snapshots: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}

// ============================================================
// 9. Compact after heavy fragmentation
// ============================================================

#[test]
fn compact_after_fragmentation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frag.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 32 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Create fragmentation: write many clusters, snapshot, overwrite half, delete snapshot
    for i in 0..50u64 {
        let data = make_pattern(i * cluster_size, 0, cluster_size as usize);
        image.write_at(&data, i * cluster_size).unwrap();
    }
    image.flush().unwrap();
    image.snapshot_create("before").unwrap();
    image.flush().unwrap();

    // Overwrite every other cluster (COW creates new allocations)
    for i in (0..50u64).step_by(2) {
        let data = make_pattern(i * cluster_size, 1, cluster_size as usize);
        image.write_at(&data, i * cluster_size).unwrap();
    }
    image.flush().unwrap();

    // Delete snapshot → the old versions of overwritten clusters become leaked
    image.snapshot_delete("before").unwrap();
    image.flush().unwrap();
    drop(image);

    // Compact
    let compacted = dir.path().join("compacted.qcow2");
    qcow2_lib::engine::converter::convert_qcow2_to_qcow2(&path, &compacted, false).unwrap();
    assert_qemu_check(&compacted);

    let orig_size = std::fs::metadata(&path).unwrap().len();
    let compact_size = std::fs::metadata(&compacted).unwrap().len();
    // Compacted should not be larger (likely smaller due to reclaimed space)
    assert!(
        compact_size <= orig_size,
        "compacted ({compact_size}) should be <= original ({orig_size})"
    );

    // Verify data in compacted image
    let mut image = Qcow2Image::open(&compacted).unwrap();
    for i in 0..50u64 {
        let gen = if i % 2 == 0 { 1 } else { 0 };
        let expected = make_pattern(i * cluster_size, gen, cluster_size as usize);
        let mut buf = vec![0u8; cluster_size as usize];
        image.read_at(&mut buf, i * cluster_size).unwrap();
        assert_eq!(
            buf, expected,
            "compacted data mismatch at cluster {i}"
        );
    }
}

// ============================================================
// 10. Partial cluster writes: sub-cluster data integrity
// ============================================================

#[test]
fn partial_cluster_writes_interleaved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.qcow2");
    let cluster_size = 65536u64;

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size: 4 * 1024 * 1024,
            cluster_bits: None,
        },
    )
    .unwrap();

    // Write at sub-cluster granularity within the same cluster
    // This tests read-modify-write (partial cluster update)
    let w1 = vec![0x11u8; 512]; // bytes 0..512
    let w2 = vec![0x22u8; 1024]; // bytes 1024..2048
    let w3 = vec![0x33u8; 4096]; // bytes 4096..8192
    let w4 = vec![0x44u8; 256]; // bytes 512..768

    image.write_at(&w1, 0).unwrap();
    image.write_at(&w2, 1024).unwrap();
    image.write_at(&w3, 4096).unwrap();
    image.write_at(&w4, 512).unwrap(); // overwrites part of the gap
    image.flush().unwrap();

    // Build expected cluster content
    let mut expected = vec![0u8; cluster_size as usize];
    expected[0..512].copy_from_slice(&w1);
    expected[512..768].copy_from_slice(&w4);
    // 768..1024 remains zero
    expected[1024..2048].copy_from_slice(&w2);
    // 2048..4096 remains zero
    expected[4096..8192].copy_from_slice(&w3);
    // rest remains zero

    let mut buf = vec![0u8; cluster_size as usize];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, expected, "partial cluster writes should compose correctly");

    // Snapshot, then overwrite a sub-region
    image.snapshot_create("snap").unwrap();
    image.flush().unwrap();

    let w5 = vec![0x55u8; 2048]; // bytes 0..2048, overwrites w1, w4, gap, and w2
    image.write_at(&w5, 0).unwrap();
    image.flush().unwrap();

    let mut buf2 = vec![0u8; 2048];
    image.read_at(&mut buf2, 0).unwrap();
    assert_eq!(buf2, w5, "sub-cluster overwrite after snapshot");

    // Rest of cluster should be preserved (COW copies full cluster)
    let mut buf3 = vec![0u8; 4096];
    image.read_at(&mut buf3, 4096).unwrap();
    assert_eq!(buf3, w3, "non-overwritten sub-region preserved after COW");

    // Apply snapshot restores original
    image.snapshot_apply("snap").unwrap();
    image.flush().unwrap();
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, expected, "snapshot apply restores partial writes");

    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "partial write test should be clean: {} mismatches, {} leaks",
        report.mismatches.len(),
        report.leaks.len()
    );

    drop(image);
    assert_qemu_check(&path);
}
