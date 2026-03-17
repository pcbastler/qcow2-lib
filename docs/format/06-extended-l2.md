# 6. Extended L2 Entries & Subclusters

When the `EXTENDED_L2` incompatible feature flag (bit 4) is set [1], L2
entries are 128 bits wide instead of 64 bits [2]. The extra 64 bits hold a
**subcluster bitmap** that divides each cluster into 32 independently
trackable regions called subclusters.

This feature requires `cluster_bits >= 14` (cluster size >= 16 KB) [2].

## 6.1 Why subclusters?

Without extended L2, the smallest unit of allocation and zero-tracking is a
full cluster. With 64 KB clusters, even writing a single byte marks the entire
64 KB as allocated. Extended L2 divides each cluster into 32 subclusters
(each 2 KB with 64 KB clusters), enabling finer-grained tracking without
reducing the cluster size.

## 6.2 Entry layout

An extended L2 entry consists of two 64-bit big-endian words:

```
 Word 0 (first 8 bytes):
 ┌──────┬──────┬──────────────────────────────────────┬──────┐
 │ bit  │ bit  │                                      │ bit  │
 │ 63   │ 62   │          9 .. 55                     │  0   │
 ├──────┼──────┼──────────────────────────────────────┼──────┤
 │COPIED│COMPR │  host cluster offset                 │  0   │
 └──────┴──────┴──────────────────────────────────────┴──────┘

 Word 1 (second 8 bytes):
 ┌──────────────────────────────┬──────────────────────────────┐
 │  bits 63 .. 32               │  bits 31 .. 0                │
 ├──────────────────────────────┼──────────────────────────────┤
 │  zero bitmap (32 bits)       │  allocation bitmap (32 bits) │
 └──────────────────────────────┴──────────────────────────────┘
```

**Word 0** has the same layout as a standard L2 entry (see Section 5.2.3),
**except bit 0 is always 0** — the per-cluster zero flag is not used in
extended mode. Zero status is tracked per-subcluster in the bitmap instead [3].

**Word 1** is the `SubclusterBitmap` [4]:
- **Bits 0–31** (allocation bitmap): bit `x` = 1 means subcluster `x` has
  data stored at the host offset.
- **Bits 32–63** (zero bitmap): bit `x` = 1 means subcluster `x` reads as
  zeros regardless of the host data or backing file.

## 6.3 Bit ordering

Bit `x` in each 32-bit half corresponds to **subcluster `x`** [4]. Subcluster
0 is at the lowest guest address within the cluster, subcluster 31 at the
highest. This is **not** MSB-first — bit 0 (the least significant bit) maps
to subcluster 0.

```
 Allocation bitmap (bits 31..0 of word 1):
 ┌────┬────┬────┬─ ─ ─┬────┬────┬────┐
 │ 31 │ 30 │ 29 │     │  2 │  1 │  0 │
 └────┴────┴────┴─ ─ ─┴────┴────┴────┘
  sc31 sc30 sc29        sc2  sc1  sc0
```

Confirmed by bitmap bit-ordering tests [4] — e.g. setting subcluster 0 to
`Allocated` sets `bitmap.0 = 1` (bit 0), setting subcluster 31 sets
`bitmap.0 = 1 << 31`.

## 6.4 Subcluster states

Each subcluster has two bits (one allocation bit, one zero bit) that combine
into four possible states [5]:

| alloc | zero | State | Meaning |
|-------|------|-------|---------|
| 0 | 0 | `Unallocated` | Not allocated; reads from backing file or returns zeros |
| 1 | 0 | `Allocated` | Data at `host_offset + subcluster_index × subcluster_size` |
| 0 | 1 | `Zero` | Reads as zeros regardless of backing file |
| 1 | 1 | `Invalid` | Must not occur; indicates corruption |

## 6.5 Subcluster size

The subcluster size is always `cluster_size / 32` [6]:

| `cluster_bits` | Cluster size | Subcluster size |
|---------------|-------------|----------------|
| 14 | 16 KB | 512 B |
| 16 | 64 KB | 2 KB |
| 21 | 2 MB | 64 KB |

`cluster_bits = 14` is the minimum for extended L2 (`MIN_CLUSTER_BITS_EXTENDED_L2`)
[2]. The validation in `validate_structural()` enforces this minimum [7].

## 6.6 Predefined bitmaps

The code provides constants for common bitmap states [4]:

| Method | Value | Meaning |
|--------|-------|---------|
| `all_unallocated()` | `0x0000_0000_0000_0000` | All 32 subclusters unallocated |
| `all_allocated()` | `0x0000_0000_FFFF_FFFF` | All 32 subclusters allocated |
| `all_zero()` | `0xFFFF_FFFF_0000_0000` | All 32 subclusters read as zero |

In standard (non-extended) mode, the `L2Entry::Standard` variant uses
`all_allocated()` and `L2Entry::Zero` uses `all_zero()` as synthetic bitmaps
so the engine can treat both modes uniformly [3].

## 6.7 Decoding logic

The extended L2 decoding branch in `decode_extended()` [3]:

1. If the `COMPRESSED` flag (bit 62) is set → `Compressed` (bitmap must be
   all zeros).
2. If the host offset is non-zero → `Standard` with the bitmap from word 1.
3. If the host offset is zero and the zero bitmap has any bits set → `Zero`.
4. If the host offset is zero and the allocation bitmap has bits set →
   `Standard` with zero host offset (unusual but valid).
5. If both bitmaps are zero → `Unallocated`.

## 6.8 Entry count per table

Because each entry is 16 bytes instead of 8, an extended L2 table holds
**half as many entries** as a standard table [2][6]:

```
entries_per_l2 = cluster_size / 16
```

With 64 KB clusters: 65,536 / 16 = 4,096 entries (vs. 8,192 in standard mode).

This means each L2 table covers half the address space, and the L1 table
needs twice as many entries for the same virtual disk size.

## 6.9 Validation

The `SubclusterBitmap::validate()` method [4] checks that no subcluster has
both the allocation and zero bits set simultaneously (the `Invalid` state).
This is a structural invariant:

```
allocation_mask & zero_mask == 0
```

## Source References

| Ref | File | What it contains |
|-----|------|-----------------|
| [1] | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L26) | `IncompatibleFeatures::EXTENDED_L2 = 1 << 4` |
| [2] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L122-L131) | `L2_ENTRY_SIZE_EXTENDED = 16`, `SUBCLUSTERS_PER_CLUSTER = 32`, `MIN_CLUSTER_BITS_EXTENDED_L2 = 14` |
| [3] | [l2.rs](../../crates/qcow2-format/src/l2.rs#L202-L263) | `L2Entry::decode_extended()` — standard and extended mode branches |
| [4] | [l2.rs](../../crates/qcow2-format/src/l2.rs#L45-L143) | `SubclusterBitmap` struct, `get()`, `set()`, `validate()`, predefined constants |
| [5] | [l2.rs](../../crates/qcow2-format/src/l2.rs#L30-L43) | `SubclusterState` enum (Unallocated, Allocated, Zero, Invalid) |
| [6] | [types.rs](../../crates/qcow2-format/src/types.rs#L222-L239) | `ClusterGeometry::l2_entry_size()`, `l2_entries_per_table()`, `subcluster_size()` |
| [7] | [header.rs](../../crates/qcow2-format/src/header.rs#L379-L385) | `validate_structural()` — rejects `cluster_bits < 14` for extended L2 |
