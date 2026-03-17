# qcow2-tool compact

Defragment and repack a QCOW2 image into a new contiguous file.

<!-- TODO
- Show usage:
    qcow2-tool compact <INPUT> <OUTPUT> [--compress] [--compression-type <deflate|zstd>]

- Explain the difference from convert --format qcow2:
    compact is specifically about defragmentation; it removes gaps between
    allocated clusters that accumulate after many writes and deletes

- Explain what "compact" means:
    - All allocated clusters written sequentially in L1/L2 order
    - No holes between data clusters
    - Output file is the minimum possible size for the image content

- Document options:
    --compress: compress clusters in the output
    --compression-type: deflate (default) or zstd

- Note: metadata (L1, L2, refcounts) is also rewritten contiguously

- Warn: compact writes to a NEW output file; the input is not modified

- Reference: crates/qcow2-tool/src/cli/compact.rs
- Reference: crates/qcow2/src/engine/converter.rs (convert_qcow2_to_qcow2)
-->
