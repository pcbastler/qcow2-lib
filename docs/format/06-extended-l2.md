# 6. Extended L2 Entries & Subclusters

When the `EXTENDED_L2` incompatible feature flag is set, L2 entries are 128 bits
wide instead of 64 bits. The extra 64 bits hold two 32-bit subcluster bitmaps
that track allocation and zero status at sub-cluster granularity.

<!-- TODO
- Explain motivation: finer-grained COW, smaller dirty regions, less space waste
- Document 128-bit entry layout:
    bits 127–64: standard 64-bit L2 entry (host offset, flags)
    bits 63–32:  subcluster_alloc bitmap (bit x → subcluster x is allocated)
    bits 31–0:   subcluster_zero bitmap  (bit x → subcluster x reads as zero)
- Explain subcluster size = cluster_size / 32
- Note bit ordering: bit 0 = subcluster 0 (lowest guest address), NOT MSB-first
  (confirmed via QEMU interop testing)
- Explain SubclusterBitmap and SubclusterState types
- Describe read logic: check subcluster_zero first, then subcluster_alloc, then backing
- Describe write logic: update both bitmaps atomically with L2 entry
- Reference: crates/qcow2-format/src/l2.rs (SubclusterBitmap, SubclusterState)
- Reference: crates/qcow2-core/src/engine/cluster_mapping.rs
- Reference: crates/qcow2-core/src/engine/writer/data_ops.rs
-->
