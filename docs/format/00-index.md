# QCOW2 Format Reference

| Section | File | Topic |
|---------|------|-------|
| 1 | [Overview](01-overview.md) | What QCOW2 is, file layout, core mechanisms, versions |
| 2 | [Header](02-header.md) | The 72/104-byte structure at offset 0 |
| 3 | [Feature Flags](03-feature-flags.md) | Incompatible, compatible, and autoclear bits |
| 4 | [Header Extensions](04-header-extensions.md) | TLV chain after the fixed header |
| 5 | [Cluster Addressing](05-cluster-addressing.md) | Two-level L1 → L2 → data translation |
| 6 | [Extended L2](06-extended-l2.md) | 128-bit L2 entries with 32 subclusters |
| 7 | [Refcount Table](07-refcount-table.md) | Two-level reference count structure |
| 8 | [Cluster Types](08-cluster-types.md) | Allocated, zero, compressed, unallocated |
| 9 | [Compression](09-compression.md) | Deflate, Zstandard, compressed descriptors |
| 10 | [Encryption](10-encryption.md) | LUKS1/2, AES-XTS, AES-CBC-ESSIV |
| 11 | [Snapshots](11-snapshots.md) | Snapshot table, COW semantics |
| 12 | [Bitmaps](12-bitmaps.md) | Persistent dirty bitmaps |
| 13 | [BLAKE3 Hashes](13-blake3-hashes.md) | Per-chunk integrity hashes (qcow2-lib extension) |
| 14 | [External Data File](14-external-data-file.md) | Guest data in a separate file |
| 15 | [Backing File](15-backing-file.md) | Copy-on-write overlay chains |
