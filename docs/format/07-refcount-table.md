# 7. Refcount Table

Every host cluster in a QCOW2 image has a reference count maintained in a
two-level refcount structure. This enables copy-on-write semantics and
garbage collection of unreferenced clusters.

<!-- TODO
- Explain two-level structure: refcount table (array of cluster offsets) → refcount blocks
- Refcount table entry: 64-bit host offset of a refcount block cluster (low bits zero)
- Refcount block: array of refcount_order-bit values, one per cluster in a block
  - refcount_order = 4 → 16-bit refcounts (v2 fixed, v3 default)
  - refcount_order = 5 → 32-bit refcounts
  - refcount_order = 6 → 64-bit refcounts
- Explain entries_per_block = (cluster_size * 8) / (1 << refcount_order)
- Explain how cluster index maps to table_index + block_index
- Document refcount semantics:
    0 = free cluster
    1 = owned by exactly one L2/refcount/snapshot entry (COPIED flag may be set)
    >1 = shared (COW required before write)
- Explain COPIED flag relationship to refcount
- Reference: crates/qcow2-format/src/refcount.rs
- Reference: crates/qcow2-core/src/engine/refcount_manager.rs
-->
