# QCOW2 Header

The header is the first structure in every QCOW2 file and describes the overall
image geometry. QCOW2 v2 uses a 72-byte fixed header; v3 extends it to 104 bytes
and adds feature flags.

<!-- TODO
- Document every field: byte offset, size, type, description
- v2 fields: magic, version, backing_file_offset, backing_file_size, cluster_bits,
  size, crypt_method, l1_size, l1_table_offset, refcount_table_offset,
  refcount_table_clusters, nb_snapshots, snapshots_offset
- v3 additional fields: incompatible_features, compatible_features,
  autoclear_features, refcount_order, header_length, compression_type
- Explain magic value 0x514649fb ("QFI\xfb")
- Explain cluster_bits → cluster_size = 1 << cluster_bits
- Explain valid cluster_bits range (9–21)
- Note: header_length field allows future extension without breaking parsers
- Reference: crates/qcow2-format/src/header.rs
-->
