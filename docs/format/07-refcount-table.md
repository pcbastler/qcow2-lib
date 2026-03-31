# 7. Refcount Table

Every host cluster in a QCOW2 image has a reference count (refcount). The
refcount tracks how many metadata structures — L1 entries, L2 entries,
snapshot copies — point to a given cluster. When a cluster's refcount is
greater than 1, it is shared and must be copied before modification
(copy-on-write).

Refcounts are stored in a **two-level lookup structure**: a refcount table
points to refcount blocks, which contain the actual values.


## 7.1 Lookup: from cluster to refcount

To find the refcount of a cluster, two steps are needed: first look up the
right **refcount block** via the **refcount table**, then read the entry
inside that block.

The refcount table lives at a fixed position in the image (the header field
`refcount_table_offset`). It is an array of 64-bit entries, where each entry
stores the disk offset of one refcount block. A refcount block is a
cluster-sized array of packed refcount values.

The lookup works as follows:

```
refcount_of(cluster_index):
    table_index  = cluster_index / entries_per_block
    block_index  = cluster_index % entries_per_block
    block_offset = refcount_table[table_index]   // 64-bit disk offset
    if block_offset == 0:
        return 0                                 // no block → cluster is free
    block = read_from_disk(block_offset)
    return block[block_index]
```

The `cluster_index` is derived from a host offset: `cluster_index = host_offset >> cluster_bits`.

The key insight: the refcount table entry tells you **where** the block is on
disk (it can sit anywhere in the image). The position **within** that block is
purely arithmetic — entry N in the block belongs to cluster N of the block's
range.


## 7.2 Concrete example

With 64 KB clusters and 16-bit refcounts, one refcount block holds
32,768 entries. Block 0 covers clusters 0–32,767, block 1 covers
32,768–65,535, and so on.

```
 Refcount Table                        Refcount Blocks
 (at refcount_table_offset)            (each one cluster, allocated on demand)

 ┌──────────────────────┐
 │ [0] → offset 0x20000 │─────────────► Block 0 (at 0x20000)
 │                      │               ┌─────────────────────────────┐
 │                      │               │ cluster 0     → refcount 1  │
 │                      │               │ cluster 1     → refcount 1  │
 │                      │               │ cluster 2     → refcount 3  │
 │                      │               │ cluster 3     → refcount 0  │
 │                      │               │ ...                         │
 │                      │               │ cluster 32767 → refcount 0  │
 │                      │               └─────────────────────────────┘
 ├──────────────────────┤
 │ [1] → 0 (no block)   │               Clusters 32,768–65,535 all have
 │                      │               refcount 0 (free).
 ├──────────────────────┤
 │ [2] → offset 0x50000 │─────────────► Block 2 (at 0x50000)
 │                      │               ┌─────────────────────────────┐
 │                      │               │ cluster 65536 → refcount 1  │
 │                      │               │ cluster 65537 → refcount 1  │
 │                      │               │ cluster 65538 → refcount 2  │
 │                      │               │ ...                         │
 │                      │               └─────────────────────────────┘
 └──────────────────────┘

 Lookup: refcount of cluster 65,538?
   table_index = 65,538 / 32,768 = 2   →  table entry [2] = 0x50000
   block_index = 65,538 % 32,768 = 2   →  block[2] = refcount 2
```

Refcount blocks are allocated on demand. A freshly created image only has
blocks for ranges that actually contain allocated clusters. A 1 TiB image
with 64 KB clusters would need 16 million refcount entries (32 MB) in a flat
array — the two-level structure avoids this entirely when the image is mostly
empty.


## 7.3 Refcount table entries

Each refcount table entry is 8 bytes (`REFCOUNT_TABLE_ENTRY_SIZE`) [4],
big-endian [1]:

```
 ┌──────────────────────────────────────────────────────────────┐
 │ bits 63 .. 9: refcount block offset (cluster-aligned)       │
 │ bits 8 .. 0:  reserved (must be zero)                       │
 └──────────────────────────────────────────────────────────────┘
```

The offset is extracted with `REFCOUNT_TABLE_OFFSET_MASK = 0xffff_ffff_ffff_fe00`
[4]. If the masked result is zero, the block is unallocated and all clusters
in its range have refcount 0 [1].


## 7.4 Refcount blocks

A refcount block is one cluster of packed refcount values [2]. The width of
each value is `1 << refcount_order` bits:

| `refcount_order` | Width | Entries per 64 KB block | Max value |
|-----------------|-------|------------------------|-----------|
| 0 | 1 bit | 524,288 | 1 |
| 1 | 2 bits | 262,144 | 3 |
| 2 | 4 bits | 131,072 | 15 |
| 3 | 8 bits | 65,536 | 255 |
| 4 | 16 bits | 32,768 | 65,535 |
| 5 | 32 bits | 16,384 | ~4 billion |
| 6 | 64 bits | 8,192 | ~1.8 × 10¹⁹ |

The entries-per-block formula [2]:

```
refcount_bits     = 1 << refcount_order
entries_per_block = cluster_size * 8 / refcount_bits
```

All values are big-endian. Widths smaller than 8 bits are packed MSB-first
within each byte (for 1-bit refcounts, bit 7 of the first byte is entry 0)
[2].

Version 2 always uses `refcount_order = 4` (16-bit) [5]. Version 3 allows
orders 0 through 6 (`MAX_REFCOUNT_ORDER`) [5].


## 7.5 Refcount semantics

| Refcount | Meaning |
|----------|---------|
| 0 | Free — cluster is not in use and can be allocated |
| 1 | Owned by exactly one structure — in-place writes are safe |
| > 1 | Shared (e.g. live image + snapshot) — copy-on-write required |

L1 and L2 entries contain a `COPIED` flag (bit 63) [4] that caches whether
the refcount is exactly 1. When the flag is set, the engine can skip the
refcount lookup and write in place. When the flag is cleared, a copy-on-write
check is needed.


## 7.6 Allocation

The refcount manager [6] supports two allocation modes:

- **Scanning** (default): searches refcount blocks for clusters with
  refcount 0, falls back to appending at the end of the file.
- **Append**: always allocates at the end of the file (simple and fast, but
  the image only grows).

When a cluster is allocated, its refcount is set to 1 [6].


## 7.7 Coverage and growth

Each refcount table entry covers `entries_per_block` clusters. When clusters
are allocated beyond the current table's coverage, the refcount manager must:

1. Allocate a new refcount block.
2. Store its offset in the refcount table.
3. If the table itself is full, grow it (allocate a larger table, copy
   entries, update the header).

This is handled by `ensure_refcount_coverage()` in the engine [6].


## 7.8 Worked example

10 GiB image, 64 KB clusters, 16-bit refcounts:

```
total_clusters    = 10 GiB / 64 KB         = 163,840
entries_per_block = 65,536 × 8 / 16        = 32,768
refcount_blocks   = ceil(163,840 / 32,768) = 5
refcount_table    = 5 entries × 8 bytes    = 40 bytes
```

The refcount table is 40 bytes (fits in one cluster). It points to 5 refcount
blocks, each 64 KB, for a total refcount overhead of 320 KB — about 0.003%
of the virtual disk size.


## Source References

| Ref | File | What it contains |
|-----|------|-----------------|
| [1] | [refcount.rs](../../crates/qcow2-format/src/refcount.rs#L22-L65) | `RefcountTableEntry` — 64-bit entry, `block_offset()`, `is_unallocated()` |
| [2] | [refcount.rs](../../crates/qcow2-format/src/refcount.rs#L67-L265) | `RefcountBlock` — parsing for all widths (1–64 bit), `read_from()`, `write_to()`, `new_empty()` |
| [3] | [header.rs](../../crates/qcow2-format/src/header.rs#L43-L45) | `refcount_table_offset`, `refcount_table_clusters` header fields |
| [4] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L63-L69) | `L1_COPIED_FLAG`, `L2_COPIED_FLAG` |
| | [constants.rs](../../crates/qcow2-format/src/constants.rs#L87-L88) | `REFCOUNT_TABLE_OFFSET_MASK` |
| | [constants.rs](../../crates/qcow2-format/src/constants.rs#L137) | `REFCOUNT_TABLE_ENTRY_SIZE = 8` |
| [5] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L38-L42) | `MAX_REFCOUNT_ORDER = 6`, `DEFAULT_REFCOUNT_ORDER_V2 = 4` |
| [6] | [refcount_manager.rs](../../crates/qcow2-core/src/engine/refcount_manager.rs#L62-L147) | `RefcountManager`, `allocate_cluster()`, `get_refcount()`, `AllocationMode` |
