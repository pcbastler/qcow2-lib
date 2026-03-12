//! Tests for snapshot_manager (originally in engine/snapshot_manager.rs)

use crate::engine::image::{CreateOptions, Qcow2Image};
use crate::error::Error;
use crate::io::MemoryBackend;

/// Create a minimal writable image on a MemoryBackend for snapshot tests.
fn create_test_image(virtual_size: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            refcount_order: None,
        },
    )
    .unwrap()
}

// ---- Table I/O tests ----

#[test]
fn load_empty_snapshot_table() {
    let image = create_test_image(1 << 20);
    let snapshots = image.snapshot_list().unwrap();
    assert!(snapshots.is_empty());
}

#[test]
fn snapshot_table_write_and_load_round_trip() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("snap-1").unwrap();

    let snapshots = image.snapshot_list().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "snap-1");
    assert_eq!(snapshots[0].id, "1");
}

#[test]
fn find_snapshot_by_name() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("alpha").unwrap();
    image.snapshot_create("beta").unwrap();

    // Delete by name -- exercises the find_snapshot() path
    image.snapshot_delete("alpha").unwrap();

    let snapshots = image.snapshot_list().unwrap();
    assert_eq!(snapshots.len(), 1, "alpha should be deleted");
    assert_eq!(snapshots[0].name, "beta", "beta should remain");

    // Apply by name -- also exercises find_snapshot()
    image.snapshot_apply("beta").unwrap();
}

#[test]
fn find_snapshot_not_found() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("exists").unwrap();

    let result = image.snapshot_delete("nonexistent");
    assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
}

#[test]
fn header_snapshot_fields_updated() {
    let mut image = create_test_image(1 << 20);
    assert_eq!(image.header().snapshot_count, 0);

    image.snapshot_create("snap-1").unwrap();
    assert_eq!(image.header().snapshot_count, 1);
    assert_ne!(image.header().snapshots_offset.0, 0);
}

// ---- Create tests ----

#[test]
fn create_snapshot_empty_name_rejected() {
    let mut image = create_test_image(1 << 20);
    let result = image.snapshot_create("");
    assert!(matches!(result, Err(Error::SnapshotNameEmpty)));
}

#[test]
fn create_snapshot_too_many_rejected() {
    // refcount_order=1 → 2-bit refcounts → max_refcount=3.
    // Guard: existing.len() + 2 > max_rc → triggers at 2 snapshots (2+2=4 > 3).
    let mut image = Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
            refcount_order: Some(1),
        },
    )
    .unwrap();

    image.snapshot_create("snap-1").unwrap();
    image.snapshot_create("snap-2").unwrap();
    let result = image.snapshot_create("snap-3");
    assert!(matches!(result, Err(Error::TooManySnapshots { count: 2, max_refcount: 3 })));
}

#[test]
fn create_snapshot_duplicate_name_rejected() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("dup").unwrap();
    let result = image.snapshot_create("dup");
    assert!(matches!(result, Err(Error::SnapshotNameDuplicate { .. })));
}

#[test]
fn create_snapshot_generates_sequential_ids() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("first").unwrap();
    image.snapshot_create("second").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps[0].id, "1");
    assert_eq!(snaps[1].id, "2");
}

#[test]
fn create_snapshot_with_data_increments_refcounts() {
    let mut image = create_test_image(1 << 20);

    // Write some data
    image.write_at(&[0xAA; 4096], 0).unwrap();

    // Take snapshot
    image.snapshot_create("snap-1").unwrap();

    // The data cluster should now have refcount 2 (active + snapshot)
    // We verify indirectly: writing should trigger COW (allocate new cluster)
    image.write_at(&[0xBB; 4096], 0).unwrap();

    // Read back should return the new data
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

#[test]
fn create_snapshot_clears_copied_flags() {
    let mut image = create_test_image(1 << 20);
    image.write_at(&[0xCC; 64], 0).unwrap();

    // Before snapshot: L1 and L2 should have copied=true
    image.snapshot_create("snap").unwrap();

    // After snapshot: writing to the same cluster triggers COW
    // (if COPIED were still set, it would write in-place, which is wrong)
    image.write_at(&[0xDD; 64], 0).unwrap();

    let mut buf = vec![0u8; 64];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

#[test]
fn write_after_snapshot_preserves_snapshot_data() {
    let mut image = create_test_image(1 << 20);

    image.write_at(&[0x11; 512], 0).unwrap();
    image.snapshot_create("before-write").unwrap();
    image.write_at(&[0x22; 512], 0).unwrap();

    // Apply the snapshot to restore old data
    image.snapshot_apply("before-write").unwrap();

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x11),
        "snapshot data should be preserved after COW write"
    );
}

#[test]
fn create_two_snapshots_sequentially() {
    let mut image = create_test_image(1 << 20);

    image.write_at(&[0xAA; 256], 0).unwrap();
    image.snapshot_create("snap-1").unwrap();

    image.write_at(&[0xBB; 256], 0).unwrap();
    image.snapshot_create("snap-2").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 2);
}

#[test]
fn create_snapshot_empty_image() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("empty-snap").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "empty-snap");
}

// ---- List tests ----

#[test]
fn list_snapshots_metadata_correct() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("my-snap").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps[0].name, "my-snap");
    assert_eq!(snaps[0].virtual_size, Some(1 << 20));
    assert!(snaps[0].timestamp_seconds > 0);
}

// ---- Delete tests ----

#[test]
fn delete_only_snapshot() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("snap").unwrap();
    assert_eq!(image.snapshot_list().unwrap().len(), 1);

    image.snapshot_delete("snap").unwrap();
    assert_eq!(image.snapshot_list().unwrap().len(), 0);
    assert_eq!(image.header().snapshot_count, 0);
}

#[test]
fn delete_first_of_two() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("first").unwrap();
    image.snapshot_create("second").unwrap();

    image.snapshot_delete("first").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "second");
}

#[test]
fn delete_second_of_two() {
    let mut image = create_test_image(1 << 20);
    image.snapshot_create("first").unwrap();
    image.snapshot_create("second").unwrap();

    image.snapshot_delete("second").unwrap();

    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "first");
}

#[test]
fn delete_nonexistent_returns_error() {
    let mut image = create_test_image(1 << 20);
    let result = image.snapshot_delete("nope");
    assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
}

#[test]
fn delete_does_not_affect_active_data() {
    let mut image = create_test_image(1 << 20);
    image.write_at(&[0xAA; 256], 0).unwrap();
    image.snapshot_create("snap").unwrap();
    image.snapshot_delete("snap").unwrap();

    let mut buf = vec![0u8; 256];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

// ---- Apply tests ----

#[test]
fn apply_reverts_data() {
    let mut image = create_test_image(1 << 20);

    image.write_at(&[0x11; 256], 0).unwrap();
    image.snapshot_create("snap").unwrap();

    image.write_at(&[0x22; 256], 0).unwrap();
    image.snapshot_apply("snap").unwrap();

    let mut buf = vec![0u8; 256];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x11));
}

#[test]
fn apply_nonexistent_returns_error() {
    let mut image = create_test_image(1 << 20);
    let result = image.snapshot_apply("nonexistent");
    assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
}

#[test]
fn apply_then_write_triggers_cow() {
    let mut image = create_test_image(1 << 20);

    image.write_at(&[0x11; 512], 0).unwrap();
    image.snapshot_create("snap").unwrap();
    image.snapshot_apply("snap").unwrap();

    // Writing after apply should trigger COW (shared clusters)
    image.write_at(&[0x33; 512], 0).unwrap();

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x33));
}

#[test]
fn apply_modify_apply_cycle() {
    let mut image = create_test_image(1 << 20);

    // Phase 1: Write data, snapshot
    image.write_at(&[0xAA; 256], 0).unwrap();
    image.snapshot_create("base").unwrap();

    // Phase 2: Modify, then revert
    image.write_at(&[0xBB; 256], 0).unwrap();
    image.snapshot_apply("base").unwrap();

    let mut buf = vec![0u8; 256];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first apply should revert");

    // Phase 3: Modify again, then revert again
    image.write_at(&[0xCC; 256], 0).unwrap();
    image.snapshot_apply("base").unwrap();

    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "second apply should revert");
}

#[test]
fn apply_preserves_snapshot_table() {
    let mut image = create_test_image(1 << 20);

    image.write_at(&[0x55; 64], 0).unwrap();
    image.snapshot_create("snap-a").unwrap();
    image.snapshot_create("snap-b").unwrap();

    image.snapshot_apply("snap-a").unwrap();

    // Both snapshots should still exist
    let snaps = image.snapshot_list().unwrap();
    assert_eq!(snaps.len(), 2);
}

#[test]
fn apply_to_empty_image_state() {
    let mut image = create_test_image(1 << 20);

    // Snapshot the empty state
    image.snapshot_create("empty").unwrap();

    // Write data
    image.write_at(&[0xFF; 1024], 0).unwrap();

    // Revert to empty
    image.snapshot_apply("empty").unwrap();

    let mut buf = vec![0u8; 1024];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00), "should revert to zeros");
}
