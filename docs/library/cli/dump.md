# qcow2-tool dump

Print the raw contents of internal metadata tables for debugging and inspection.

<!-- TODO
- Show usage: qcow2-tool dump <IMAGE> <TABLE>
  where TABLE is one of: l1, l2, refcount
- Document l1 output columns:
    index, raw_entry (hex), l2_host_offset, COPIED flag
- Document l2 output columns:
    index, raw_entry (hex), state (Unallocated/Allocated/Zero/Compressed),
    host_offset, COPIED, ZERO, COMPRESSED flags
    For extended L2: subcluster_alloc bitmap, subcluster_zero bitmap
- Document refcount output columns:
    cluster_index, host_offset, refcount_value
- Note: l2 dump iterates all L2 tables referenced by the L1 table
- Note: useful for diagnosing corruption alongside qcow2-rescue
- Show example output for each table type
- Reference: crates/qcow2-tool/src/cli/dump.rs
-->
