# Feature Flags

QCOW2 v3 introduces three 64-bit feature flag fields in the header. Parsers that
encounter unknown incompatible bits must refuse to open the image.

<!-- TODO
- Explain the three categories and their semantics:
  - Incompatible: unknown bit → must refuse to open (read or write)
  - Compatible: unknown bit → may open and ignore
  - Autoclear: cleared by writer on open; signals data consistency
- Document all defined bits:
  Incompatible:
    bit 0: DIRTY — refcounts may be stale (not closed cleanly)
    bit 1: CORRUPT — data structures may be corrupt (open read-only only)
    bit 2: EXTERNAL_DATA_FILE — guest data in a separate file
    bit 3: COMPRESSION_TYPE — compression_type byte in header is valid
    bit 4: EXTENDED_L2 — 128-bit L2 entries with subcluster bitmaps
  Compatible:
    bit 0: LAZY_REFCOUNTS — refcounts may be stale; run consistency check
  Autoclear:
    bit 0: BITMAPS — bitmap extension data is consistent
    bit 1: RAW_EXTERNAL — external data file contains raw data
    bit 2: BLAKE3_HASHES — BLAKE3 hash extension data is consistent (qcow2-lib extension)
- Reference: crates/qcow2-format/src/feature_flags.rs
-->
