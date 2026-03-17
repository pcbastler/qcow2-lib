# Cluster Types

An L2 entry encodes not just a host offset but the storage state of a cluster.
There are four distinct states.

<!-- TODO
- Document each state with its L2 entry encoding and read/write semantics:

  Unallocated (host_offset == 0, ZERO == 0):
    - Read: fall through to backing file, or return zeros if no backing
    - Write: allocate new cluster, write data, update L2

  Zero (ZERO flag set, host_offset may be 0 or valid):
    - Read: always returns zeros, no backing fallback
    - Write: depends on host_offset — may update in-place or reallocate

  Allocated (host_offset != 0, ZERO == 0, COMPRESSED == 0):
    - Read: read from host_offset + within_cluster
    - Write: in-place if COPIED, COW if not

  Compressed (COMPRESSED flag set):
    - Read: decode compressed descriptor, read sectors, decompress
    - Write: decompress, modify, recompress, write new compressed cluster
    - Compressed clusters are never written in-place (always reallocated)

- Note that extended L2 adds per-subcluster granularity to Unallocated and Zero
- Reference: crates/qcow2-format/src/l2.rs (L2Entry enum)
- Reference: crates/qcow2-core/src/engine/reader.rs
- Reference: crates/qcow2-core/src/engine/writer/data_ops.rs
-->
