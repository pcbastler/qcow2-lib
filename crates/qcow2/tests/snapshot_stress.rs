//! Stress tests for the snapshot subsystem.
//!
//! Verifies that the snapshot table handles many snapshots, rapid create/delete
//! cycles, and data isolation correctly.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

/// Helper: create a 2 MB in-memory image.
fn mem_image() -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: 2 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

#[test]
fn create_50_snapshots() {
    let mut image = mem_image();
    for i in 0..50 {
        image.snapshot_create(&format!("snap-{i}")).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    assert_eq!(list.len(), 50);
}

#[test]
fn create_delete_cycle_100() {
    let mut image = mem_image();
    for i in 0..100 {
        let name = format!("cycle-{i}");
        image.snapshot_create(&name).unwrap();
        image.snapshot_delete(&name).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    assert_eq!(list.len(), 0);
    assert!(image.check_integrity().unwrap().is_clean());
}

#[test]
fn snapshot_names_preserved_at_scale() {
    let mut image = mem_image();
    let names: Vec<String> = (0..30).map(|i| format!("snapshot-{i:03}")).collect();
    for name in &names {
        image.snapshot_create(name).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    let listed_names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    for name in &names {
        assert!(
            listed_names.contains(&name.as_str()),
            "missing snapshot: {name}"
        );
    }
}

#[test]
fn data_isolation_many_snapshots() {
    let mut image = mem_image();
    // Write unique data, snapshot, overwrite — repeat
    for i in 0..20u8 {
        image.write_at(&[i; 512], 0).unwrap();
        image.snapshot_create(&format!("s{i}")).unwrap();
    }

    // Apply each snapshot and verify data
    for i in 0..20u8 {
        image.snapshot_apply(&format!("s{i}")).unwrap();
        let mut buf = [0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(
            buf.iter().all(|&b| b == i),
            "snapshot s{i} should have pattern {i}"
        );
    }
}

#[test]
fn snapshot_table_growth() {
    // Use small clusters (4KB) to force snapshot table to grow past one cluster
    let mut image = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(12), // 4 KB clusters
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap();

    // Each snapshot entry is ~50+ bytes, so 100 snapshots in 4KB clusters should force growth
    for i in 0..100 {
        image.snapshot_create(&format!("grow-{i}")).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    assert_eq!(list.len(), 100);
    assert!(image.check_integrity().unwrap().is_clean());
}

#[test]
fn delete_all_from_many() {
    let mut image = mem_image();
    for i in 0..25 {
        image.snapshot_create(&format!("del-{i}")).unwrap();
    }
    for i in 0..25 {
        image.snapshot_delete(&format!("del-{i}")).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    assert_eq!(list.len(), 0);
    assert!(image.check_integrity().unwrap().is_clean());
}

#[test]
fn integrity_clean_with_many_snapshots() {
    let mut image = mem_image();
    for i in 0..30 {
        image.write_at(&[i as u8; 256], (i * 4096) as u64).unwrap();
        image.snapshot_create(&format!("int-{i}")).unwrap();
    }
    let report = image.check_integrity().unwrap();
    assert!(
        report.is_clean(),
        "integrity should be clean with {} snapshots, mismatches: {:?}, leaks: {:?}",
        30,
        report.mismatches,
        report.leaks
    );
}

#[test]
fn interleaved_create_delete() {
    let mut image = mem_image();
    // Create 10, delete odd, create 10 more
    for i in 0..10 {
        image.snapshot_create(&format!("a-{i}")).unwrap();
    }
    for i in (1..10).step_by(2) {
        image.snapshot_delete(&format!("a-{i}")).unwrap();
    }
    for i in 10..20 {
        image.snapshot_create(&format!("b-{i}")).unwrap();
    }
    let list = image.snapshot_list().unwrap();
    assert_eq!(list.len(), 15); // 5 even from a + 10 from b
    assert!(image.check_integrity().unwrap().is_clean());
}
