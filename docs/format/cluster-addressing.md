# Cluster Addressing (L1 / L2 Tables)

QCOW2 maps guest offsets to host cluster offsets using a two-level page table.
The L1 table is fixed at the offset given in the header; L2 tables are
allocated dynamically.

<!-- TODO
- Explain guest offset → host offset translation step by step:
    guest_offset
    → l1_index  = guest_offset >> (cluster_bits + l2_bits)
    → l2_index  = (guest_offset >> cluster_bits) & l2_mask
    → within_cluster = guest_offset & cluster_mask
- Explain l2_bits = cluster_bits - 3 (8-byte L2 entries per cluster)
  (for extended L2: cluster_bits - 4, 16-byte entries)
- L1 entry format: bits 63–9 = L2 table host offset (cluster-aligned), bit 0 = COPIED
- Standard L2 entry format (64-bit):
    bits 63–62: 00 = unallocated, 01 = compressed, 10/11 = allocated/zero
    bit 0: COPIED flag
    bit 1: ZERO flag
    bits 63–56: nb_sectors (compressed only)
    bits 55–0: host cluster offset or compressed descriptor
- Document the COPIED flag: set when refcount == 1, allows in-place write
- Document maximum L1 table size (derived from virtual_size and cluster_bits)
- Reference: crates/qcow2-format/src/l1.rs, crates/qcow2-format/src/l2.rs
- Reference: crates/qcow2-core/src/engine/cluster_mapping.rs
-->
