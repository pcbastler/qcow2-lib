# Snapshots API

<!-- TODO
- Document the four snapshot operations on Qcow2Image (and Qcow2ImageAsync):
    create_snapshot(id: &str, name: &str) -> Result<()>
    delete_snapshot(id: &str) -> Result<()>
    revert_snapshot(id: &str) -> Result<()>
    list_snapshots() -> Result<Vec<SnapshotInfo>>

- Document SnapshotInfo fields: id, name, timestamp, vm_clock_nsec, vm_state_size,
  virtual_size, l1_table_offset

- Explain what happens during create_snapshot:
    1. Flush dirty metadata
    2. Copy current L1 table → new snapshot L1 table cluster
    3. Increment refcounts of all L2 clusters referenced by L1
    4. Write SnapshotHeader to snapshot table
    5. Update nb_snapshots in header

- Explain revert_snapshot:
    1. Decrement refcounts of current L1 clusters (free if zero)
    2. Replace current L1 with snapshot's L1 copy
    3. Update header

- Explain delete_snapshot:
    Decrements refcounts of snapshot's L1 clusters; does NOT restore data

- Warn about revert being destructive: uncommitted writes in the live image are lost

- Reference: crates/qcow2-core/src/engine/snapshot_manager.rs
- Reference: crates/qcow2/src/engine/image/snapshot.rs
- Reference: crates/qcow2/src/engine/image_async/snapshot.rs
-->
