# Testing & Fuzzing

<!-- TODO
- State the test count: 1332 tests, 0 failures (as of last update)
- Describe the test organization:
    - Unit tests in each crate (inline #[cfg(test)] modules)
    - Integration tests in crates/qcow2/src/engine/tests/
    - e2e tests in crates/qcow2-rescue-e2e/

- List the integration test modules and what they cover:
    test_cluster_mapping.rs    — L1/L2 address translation, edge cases
    test_reader.rs             — reads with backing, compression, encryption
    test_writer.rs             — writes, COW, zero clusters, compressed writes
    test_refcount_manager.rs   — allocation, deallocation, COW refcount updates
    test_bitmap_manager.rs     — create/delete/set/clear bitmaps
    test_snapshot_manager.rs   — create/delete/revert snapshots
    test_metadata_io.rs        — L2/refcount table serialization round-trips

- Document the 9 fuzz targets (in fuzz/ directory):
    fuzz_image_open            — random bytes as QCOW2 file → open must not panic
    fuzz_header_extensions     — random TLV extension blobs
    fuzz_snapshot_table        — random snapshot table data
    fuzz_refcount_block        — random refcount block data
    fuzz_engine_ops            — random read/write sequences on small images
    fuzz_l2_entry              — random 64-bit and 128-bit L2 entry decoding
    fuzz_bitmap_extension      — random bitmap directory blobs
    fuzz_compression           — random data through compress/decompress round-trip
    fuzz_engine_extended_l2    — random subcluster read/write sequences

- Explain how to run fuzz targets:
    cargo +nightly fuzz run fuzz_image_open

- Explain the MemoryBackend role in tests: all engine tests run in memory,
  no temp files needed, fast and deterministic

- Reference: crates/qcow2/src/engine/tests/
- Reference: crates/qcow2-rescue-e2e/src/
- Reference: fuzz/fuzz_targets/
-->
