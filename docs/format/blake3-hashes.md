# BLAKE3 Hash Extension

The BLAKE3 hash extension is a qcow2-lib-specific feature (not part of the QEMU
spec). It stores a per-chunk cryptographic hash of the guest data, enabling
integrity verification without reading the entire image.

<!-- TODO
- Note clearly: this is NOT a QEMU feature; images using it are not portable to QEMU
  unless the BLAKE3 autoclear feature bit allows graceful degradation
- Explain the Blake3Extension header structure:
    hash_table_offset: host offset of the top-level hash table
    hash_table_entries: number of entries
    hash_size: bytes per hash (16 = 128-bit truncated, 32 = full 256-bit)
    hash_chunk_bits: log2 of chunk size (range: 12 = 4 KB to 24 = 16 MB)
- Explain two-level structure: hash table → hash data clusters
    each entry covers hash_chunk_size bytes of guest address space
- Hash function: BLAKE3 (keyed mode is NOT used; standard hash of raw cluster data)
- Explain HashTableEntry states (similar to BitmapTableEntry)
- Explain per-snapshot hash tables: stored in snapshot extra_data
- AUTOCLEAR_BLAKE3_HASHES flag semantics: cleared if hash data may be stale
- Reference: crates/qcow2-format/src/hash.rs
- Reference: crates/qcow2-core/src/engine/hash_manager.rs
-->
