# 9. Compression

QCOW2 supports per-cluster compression. Compressed clusters are stored at
variable size (multiple of 512-byte sectors) and identified by the COMPRESSED
flag in the L2 entry.

<!-- TODO
- Explain the two supported algorithms:
    compression_type 0: Deflate (RFC 1951 raw deflate, no zlib/gzip wrapper)
    compression_type 1: Zstandard (available since QEMU 5.0, requires COMPRESSION_TYPE feature flag)
- Document compressed cluster descriptor (62-bit field in L2 entry):
    bits 61..(62-cluster_bits): compressed host sector offset (in 512-byte sectors)
    bits (62-cluster_bits-1)..0: nb_sectors - 1 (number of 512-byte sectors occupied)
  The exact bit split depends on cluster_bits — explain the formula
- Explain that nb_sectors is the ceiling: actual compressed data may be shorter
  (remaining bytes in last sector are garbage)
- Note: compression_type 0 does not require the COMPRESSION_TYPE feature flag
  (deflate is the default and implied)
- Note: compressed clusters are always read-decompress-modify-recompress on write
- Reference: crates/qcow2-format/src/compressed.rs
- Reference: crates/qcow2-core/src/engine/writer/compressed.rs
- Reference: crates/qcow2/src/engine/compression.rs (StdCompressor)
-->
