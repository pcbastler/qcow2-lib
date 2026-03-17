# BLAKE3 Hash API

<!-- TODO
- Remind reader this is a qcow2-lib extension; images with BLAKE3 hashes are not
  portable to QEMU (the autoclear flag ensures graceful degradation)

- Document all hash operations on Qcow2Image (and Qcow2ImageAsync):
    compute_hashes(chunk_bits: u8, hash_size: u8) -> Result<()>
    verify_hashes() -> Result<HashVerifyReport>
    list_hash_entries() -> Result<Vec<HashEntry>>

- Document HashEntry fields: guest_offset, hash_bytes

- Document HashVerifyReport: total_chunks, ok_chunks, mismatch_chunks,
  missing_chunks; list of HashMismatch { offset, stored, computed }

- Explain the chunk size parameter: hash_chunk_bits (12–24); chunks are
  independent of cluster size and may span multiple clusters

- Explain the two hash_size options:
    16 = 128-bit truncated BLAKE3 (saves space, still cryptographically strong)
    32 = full 256-bit BLAKE3

- Explain per-snapshot hashes: each snapshot can have its own hash table
  stored in the snapshot's extra_data; verify_hashes checks against the
  current L1 (live image) or a specified snapshot

- Show use case: post-transfer integrity verification, image signing pipeline

- Reference: crates/qcow2-core/src/engine/hash_manager.rs
- Reference: crates/qcow2/src/engine/image/hash.rs
- Reference: crates/qcow2/src/engine/image_async/hash.rs
- Reference: crates/qcow2-format/src/hash.rs
-->
