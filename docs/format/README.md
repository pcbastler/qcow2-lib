# QCOW2 Format Reference

QCOW2 (QEMU Copy-On-Write version 2) is a disk image format designed for
virtual machine storage. This reference documents the on-disk layout as
implemented and extended by qcow2-lib.

<!-- TODO
- Write a 1–2 paragraph intro: what QCOW2 is, where it comes from (QEMU), why it exists
- Describe the overall file layout: header → L1 table → L2 tables → data clusters → refcount structures
- Add a simple ASCII diagram of the file regions
- Note which parts are QEMU-compatible and which are qcow2-lib extensions (BLAKE3)
- Reference: crates/qcow2-format/src/lib.rs, crates/qcow2-format/src/constants.rs
-->

## Sections

- [Header](header.md)
- [Feature Flags](feature-flags.md)
- [Header Extensions](header-extensions.md)
- [Cluster Addressing (L1 / L2)](cluster-addressing.md)
- [Extended L2 & Subclusters](extended-l2.md)
- [Refcount Table](refcount-table.md)
- [Cluster Types](cluster-types.md)
- [Compression](compression.md)
- [Encryption](encryption.md)
- [Snapshots](snapshots.md)
- [Bitmaps](bitmaps.md)
- [BLAKE3 Hashes](blake3-hashes.md)
- [External Data File](external-data-file.md)
- [Backing File](backing-file.md)
