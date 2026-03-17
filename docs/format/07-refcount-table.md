# 7. Refcount Table

Every host cluster in a QCOW2 image has a reference count. The refcount
tracks how many metadata structures (L1 entries, L2 entries, snapshot L1
copies) point to a given cluster. This enables copy-on-write: when a cluster's
refcount is greater than 1, it must be copied before modification.

Reference counts use a **two-level structure** — similar to the L1/L2 address
translation (Section 5), but for cluster ownership instead of guest data.

## 7.1 Two-level structure

```
 cluster host offset
        │
        ▼
 ┌─────────────────┐
 │ compute indices  │
 │ (table, block)   │
 └────────┬─────────┘
          │
          ▼
 ┌─────────────────┐     offset == 0
 │ Refcount Table  │ ─────────────────────► refcount = 0
 │ entry [table_i] │
 └────────┬─────────┘
          │ offset != 0
          ▼
 ┌─────────────────┐
 │ Refcount Block  │
 │ entry [block_i] │ ──► refcount value
 └─────────────────┘
```

- The **refcount table** is a flat array of 64-bit entries. Each entry points
  to a refcount block, or is zero (unallocated — all clusters in that range
  have refcount 0) [1].
- Each **refcount block** is one cluster of packed refcount values. The width
  of each value depends on `refcount_order` [2].

The refcount table itself is located at `refcount_table_offset` in the header,
occupying `refcount_table_clusters` clusters [3].

## 7.2 Refcount table entries

Each entry is 64 bits, big-endian [1]:

```
 ┌──────────────────────────────────────────────────────────────┐
 │ bits 63 .. 9: refcount block offset (cluster-aligned)       │
 │ bits 8 .. 0:  reserved (must be zero)                       │
 └──────────────────────────────────────────────────────────────┘
```

The offset is masked with `REFCOUNT_TABLE_OFFSET_MASK = 0xffff_ffff_ffff_fe00`
(bits 9–63) [4]. If the masked offset is zero, the entry is unallocated and
all clusters in that block's range have refcount 0 [1].

Each entry is 8 bytes (`REFCOUNT_TABLE_ENTRY_SIZE`) [4].

## 7.3 Refcount blocks

A refcount block is one cluster of packed refcount values. The width of each
value is `1 << refcount_order` bits [2]:

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
refcount_bits    = 1 << refcount_order
entries_per_block = cluster_size * 8 / refcount_bits
```

For the default configuration (64 KB clusters, 16-bit refcounts):
`65,536 × 8 / 16 = 32,768` entries per block.

All refcount values are stored big-endian, regardless of width [2]. Widths
smaller than 8 bits are packed MSB-first within each byte (e.g. for 1-bit
refcounts, bit 7 of the first byte is entry 0) [2].

Version 2 always uses `refcount_order = 4` (16-bit refcounts) [5]. Version 3
allows any order from 0 to 6 (`MAX_REFCOUNT_ORDER`) [5].

## 7.4 Index computation

Given a host cluster offset, the refcount indices are computed as [6]:

```
cluster_index = host_offset >> cluster_bits
table_index   = cluster_index / entries_per_block
block_index   = cluster_index % entries_per_block
```

If `table_index` is beyond the refcount table, or the table entry at that
index is unallocated, the refcount is 0 [6].

## 7.5 Refcount semantics

The refcount value determines what operations are allowed on a cluster:

| Refcount | Meaning | COPIED flag |
|----------|---------|-------------|
| 0 | Free — cluster is not in use and can be allocated | — |
| 1 | Owned by exactly one structure — in-place writes are safe | Set (bit 63 of L1/L2 entry) [4] |
| > 1 | Shared — e.g. live image + snapshot both reference it. Copy-on-write required before modification | Cleared |

The `COPIED` flag (`L1_COPIED_FLAG`, `L2_COPIED_FLAG`) in L1/L2 entries [4]
is a cached indicator that the refcount is exactly 1. It avoids a refcount
lookup on every write — if `COPIED` is set, the engine knows it can write
in place.

## 7.6 Allocation

The `RefcountManager` [6] supports two allocation modes:

- **Scanning** (default): scans refcount blocks for clusters with refcount 0,
  then falls back to appending at the end of the file.
- **Append**: always allocates at the end of the file (simple, fast, but the
  image only grows).

When a cluster is allocated, its refcount is set to 1 [6].

## 7.7 Coverage and growth

Each refcount table entry covers `entries_per_block` clusters. As new
clusters are allocated beyond the current table's coverage, the refcount
manager must:

1. Allocate a new refcount block.
2. Add its offset to the refcount table.
3. If the table itself is full, grow it (allocate a larger table, copy
   entries, update the header).

This is handled by `ensure_refcount_coverage()` in the engine [6].

## 7.8 Worked example

**10 GiB image, 64 KB clusters, 16-bit refcounts**:

```
total_clusters    = 10 GiB / 64 KB        = 163,840
entries_per_block = 65,536 × 8 / 16       = 32,768
refcount_blocks   = ceil(163,840 / 32,768) = 5
refcount_table    = 5 entries × 8 bytes    = 40 bytes
```

The refcount table is 40 bytes (fits easily in one cluster). It points to 5
refcount blocks, each 64 KB, for a total refcount overhead of 5 × 64 KB =
320 KB (~0.003% of the virtual disk size).

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
