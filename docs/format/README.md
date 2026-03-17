# QCOW2 Format Reference

## What is QCOW2?

A virtual hard disk is a file that pretends to be a physical disk drive. A
virtual machine reads and writes to it exactly as it would to real hardware —
but underneath, the data lives in a regular file on the host filesystem.

The simplest way to implement this is a **raw image**: a file that is exactly as
large as the virtual disk. A 100 GB virtual disk becomes a 100 GB file. This
works, but wastes space — most of the disk is typically empty.

QCOW2 (**Q**EMU **C**opy-**O**n-**W**rite version **2**) solves this. It is the
native disk image format of [QEMU](https://www.qemu.org/) and is widely used by
KVM, libvirt, OpenStack, and other virtualization tools. It adds:

- **Sparse storage** — only clusters that have actually been written occupy
  space on the host. A 100 GB virtual disk might only use 2 GB on disk.
- **Copy-on-write snapshots** — the image can be "frozen" at any point.
  Subsequent writes go to new clusters while the snapshot retains the originals.
- **Backing files** — an image can be layered on top of another image, storing
  only the differences. This enables template-based provisioning and thin clones.
- **Compression** — individual clusters can be stored compressed (deflate or
  zstd), reducing host disk usage further.
- **Encryption** — cluster data can be encrypted with AES (via LUKS), providing
  at-rest encryption without relying on the host filesystem.
- **Dirty bitmaps** — the image tracks which regions have changed since a
  reference point, enabling efficient incremental backups.

## How a QCOW2 file is organized

A QCOW2 file is divided into fixed-size **clusters**. The cluster size is
configurable (512 bytes to 2 MB; the default is 64 KB) [1]. Every structure in the
file — metadata tables, compressed data, uncompressed data — is
cluster-aligned.

At a high level, the file looks like this:

```
 ┌────────────────────────────────────────────────────────────────┐
 │                       Header (cluster 0)                      │
 │  magic number, version, geometry, pointers to other tables    │
 │  followed by header extensions (TLV chain)                    │
 ├────────────────────────────────────────────────────────────────┤
 │                       Refcount Table                          │
 │  array of 64-bit pointers to refcount blocks                  │
 ├────────────────────────────────────────────────────────────────┤
 │                        L1 Table                               │
 │  array of 64-bit pointers to L2 tables                        │
 ├────────────────────────────────────────────────────────────────┤
 │                                                               │
 │         L2 Tables, Refcount Blocks, Data Clusters,            │
 │         Snapshot Tables, Bitmap Data, Hash Data               │
 │                                                               │
 │        (allocated on demand, interleaved, cluster-aligned)    │
 │                                                               │
 └────────────────────────────────────────────────────────────────┘
```

The order of regions is not fixed — only the header is guaranteed to be at
offset 0. The L1 table, refcount table, snapshot table, and everything else are
located via offsets stored in the header. New clusters are appended at the end of
the file as data is written.

## The two core mechanisms

Understanding QCOW2 requires understanding two things:

### 1. Address translation — "Where is my data?"

A virtual disk has a flat address space: byte 0 through byte *virtual_size - 1*.
The guest writes to a guest offset, and QCOW2 must map that to a location in
the host file.

This mapping uses a **two-level page table**, similar to how a CPU translates
virtual addresses to physical addresses:

```
 Guest offset
 ┌──────────────────────────────────────────────────────────────┐
 │   L1 index          │   L2 index          │  cluster offset  │
 │   (which L2 table)  │   (which entry)     │  (byte within)   │
 └─────────┬───────────┴────────┬────────────┴───────┬──────────┘
           │                    │                    │
           ▼                    │                    │
    ┌──────────────┐            │                    │
    │   L1 Table   │            │                    │
    │   entry [i]  │─────┐      │                    │
    └──────────────┘     │      │                    │
                         ▼      ▼                    │
                  ┌──────────────────┐               │
                  │    L2 Table      │               │
                  │    entry [j]     │───┐           │
                  └──────────────────┘   │           │
                                         ▼           ▼
                               ┌───────────────────────────┐
                               │     Data Cluster          │
                               │     byte [k]              │
                               └───────────────────────────┘
```

- The **L1 table** is an array of pointers. Each entry points to an L2 table [2].
- Each **L2 table** is an array of pointers. Each entry points to a data cluster
  (or says "not allocated" or "reads as zero" or "compressed") [3].
- The **cluster offset** is the byte position within that data cluster [4].

The L1 table is small (tens to hundreds of entries for typical images). L2
tables are larger (thousands of entries each) and are allocated on demand — an
L2 table only exists once a guest write touches that range.

→ Details: [Cluster Addressing](cluster-addressing.md)

### 2. Reference counting — "Who is using this cluster?"

Every cluster in the file has a **reference count** that tracks how many
metadata entries (L1 entries, L2 entries, snapshot tables) point to it.

- A cluster with refcount **0** is free and can be reused.
- A cluster with refcount **1** is owned by exactly one entry. Writes can
  modify it in place.
- A cluster with refcount **> 1** is shared — for example, it is referenced by
  both the live image and a snapshot. Writing to it triggers a
  **copy-on-write**: the data is copied to a new cluster, and the original
  remains untouched for the snapshot.

Reference counts are stored in a two-level structure similar to the L1/L2
tables: a **refcount table** (array of pointers) points to **refcount blocks**
(arrays of reference counts).

→ Details: [Refcount Table](refcount-table.md)

## Versions

QCOW2 exists in two versions:

- **Version 2** — the original format. 72-byte header, fixed 16-bit reference
  counts, no feature flags [5].
- **Version 3** — extends the header to 104+ bytes. Adds three 64-bit feature
  flag fields, variable-width reference counts, and a header length field that
  allows future extensions without breaking parsers [5].

Both versions share the same core address translation and refcount mechanisms.
Version 3 adds the ability to signal optional features (compression types,
subclusters, bitmaps) through standardized feature flags. Encryption is
signaled separately via the `crypt_method` header field, not through feature
flags.

→ Details: [Header](header.md), [Feature Flags](feature-flags.md)

## qcow2-lib extensions

This documentation describes the QCOW2 format as implemented by qcow2-lib.

The **BLAKE3 hash extension** is a qcow2-lib-specific feature not defined by
the upstream QCOW2 specification. It uses the autoclear mechanism
(`AutoclearFeatures::BLAKE3_HASHES`, bit 2) [6]: implementations that do not
understand this bit will clear it on first write, discarding the hash metadata.
The image itself remains fully usable.

→ Details: [BLAKE3 Hashes](blake3-hashes.md)

## All bytes are big-endian

Every multi-byte integer in a QCOW2 file is stored in **big-endian** (network)
byte order [7]. This applies to the header, L1/L2 entries, refcount tables,
snapshot headers, bitmap structures — everything. There are no exceptions.

## Sections

Each section below documents one aspect of the format in detail.

| Section | What it covers |
|---------|---------------|
| [Header](header.md) | The 72/104-byte structure at offset 0: version, geometry, pointers |
| [Feature Flags](feature-flags.md) | Incompatible, compatible, and autoclear feature bits |
| [Header Extensions](header-extensions.md) | Type-length-value chain after the fixed header |
| [Cluster Addressing](cluster-addressing.md) | Two-level L1 → L2 → data translation |
| [Extended L2](extended-l2.md) | 128-bit L2 entries with 32 subclusters per cluster |
| [Refcount Table](refcount-table.md) | Two-level reference count structure |
| [Cluster Types](cluster-types.md) | Allocated, zero, compressed, and unallocated states |
| [Compression](compression.md) | Deflate and Zstandard, compressed cluster descriptors |
| [Encryption](encryption.md) | LUKS1/2, AES-XTS, AES-CBC-ESSIV, key derivation |
| [Snapshots](snapshots.md) | Snapshot table, COW semantics, L1 table copies |
| [Bitmaps](bitmaps.md) | Persistent dirty bitmaps for incremental backup |
| [BLAKE3 Hashes](blake3-hashes.md) | Per-chunk integrity hashes (qcow2-lib extension) |
| [External Data File](external-data-file.md) | Storing guest data in a separate file |
| [Backing File](backing-file.md) | Copy-on-write overlay chains |

## Source References

| Ref | File | What it contains |
|-----|------|-----------------|
| [1] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L26-L34) | `MIN_CLUSTER_BITS`, `MAX_CLUSTER_BITS`, `DEFAULT_CLUSTER_BITS` |
| [2] | [l1.rs](../../crates/qcow2-format/src/l1.rs#L18-L73) | `L1Entry` struct, offset extraction, COPIED flag |
| [3] | [l2.rs](../../crates/qcow2-format/src/l2.rs#L158-L188) | `L2Entry` enum (Unallocated, Zero, Standard, Compressed) |
| [4] | [types.rs](../../crates/qcow2-format/src/types.rs#L244-L269) | `GuestOffset::split()` — address decomposition |
| [5] | [header.rs](../../crates/qcow2-format/src/header.rs#L24-L64) | `Header` struct, all field definitions |
| [6] | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L44-L51) | `AutoclearFeatures::BLAKE3_HASHES` |
| [7] | [header.rs](../../crates/qcow2-format/src/header.rs#L11) | `use byteorder::{BigEndian, ByteOrder}` — all fields big-endian |
