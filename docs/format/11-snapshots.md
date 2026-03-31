# 11. Snapshots

QCOW2 stores internal snapshots as a table of snapshot headers. Each snapshot
captures the full guest address space at a point in time by keeping a private
copy of the L1 table.

<!-- TODO
- Explain snapshot table: contiguous array at snapshots_offset, nb_snapshots entries
- Document SnapshotHeader fields:
    l1_table_offset: host offset of this snapshot's L1 table copy
    l1_size: number of L1 entries
    unique_id: null-terminated string (numeric by convention, e.g. "1", "2")
    name: null-terminated string (human-readable)
    timestamp_seconds: Unix timestamp of creation
    timestamp_nseconds: nanosecond part
    vm_clock_nsec: VM clock at snapshot time
    vm_state_size: size of saved VM RAM state (0 if disk-only snapshot)
    extra_data_size: length of trailing extra_data region
    extra_data: extensible; known fields:
      - virtual_disk_size (8 bytes): guest size at snapshot time
      - blake3_hash_table_offset (8 bytes): optional hash table for this snapshot
- Explain COW semantics: snapshot creation copies L1, increments refcounts of all
  referenced L2 clusters; writes to the live image trigger COW
- Note: snapshot L1 tables must be cluster-aligned
- Reference: crates/qcow2-format/src/snapshot.rs
- Reference: crates/qcow2-core/src/engine/snapshot_manager.rs
-->
