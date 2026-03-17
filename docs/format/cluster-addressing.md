# Cluster Addressing (L1 / L2 Tables)

QCOW2 maps guest offsets to host file locations using a two-level lookup
table. This is the core mechanism of the format — every read and write starts
here.

The guest sees a flat address space from byte 0 to `virtual_size - 1`. The
QCOW2 engine translates each guest offset into one of four outcomes: the data
is at a specific host offset, it reads as zeros, it is compressed, or it is
not allocated (fall through to a backing file or return zeros).

## Address decomposition

A guest offset is split into three parts:

```
 Guest offset (64 bits)
 ┌──────────────────────────────────────────────────────────────┐
 │   L1 index          │   L2 index          │  intra-cluster   │
 │   (which L2 table)  │   (which entry)     │  (byte within)   │
 └─────────────────────┴─────────────────────┴──────────────────┘
         high bits            middle bits          low bits
```

The split points depend on `cluster_bits` and the L2 entry size:

```
intra_cluster_offset = guest_offset & (cluster_size - 1)        [cluster_bits bits]
cluster_number       = guest_offset >> cluster_bits
l2_index             = cluster_number & ((1 << l2_bits) - 1)    [l2_bits bits]
l1_index             = cluster_number >> l2_bits
```

Where:
- `cluster_size = 1 << cluster_bits`
- `l2_bits = cluster_bits - l2_entry_shift`
- `l2_entry_shift = 3` for standard mode (8-byte entries), `4` for extended
  L2 (16-byte entries)

Source: `types.rs:259–269` — `GuestOffset::split()`, the single authoritative
implementation of this formula.

### Concrete examples

**Standard mode, `cluster_bits = 16` (64 KB clusters)**:

```
l2_entry_shift  = 3
l2_bits         = 16 - 3 = 13
entries_per_l2  = 1 << 13 = 8,192
address space per L2 table = 8,192 × 65,536 = 512 MiB
```

| Guest offset | L1 index | L2 index | Intra-cluster |
|-------------|----------|----------|---------------|
| `0x00000000` | 0 | 0 | 0 |
| `0x00010000` (64 KB) | 0 | 1 | 0 |
| `0x00010200` (64 KB + 512) | 0 | 1 | 512 |
| `0x1FFFFFFF` (512 MiB - 1) | 0 | 8,191 | 65,535 |
| `0x20000000` (512 MiB) | 1 | 0 | 0 |

Source: `types.rs:292–327` — split tests confirming these values.

**Extended L2, `cluster_bits = 16`**:

```
l2_entry_shift  = 4
l2_bits         = 16 - 4 = 12
entries_per_l2  = 1 << 12 = 4,096
address space per L2 table = 4,096 × 65,536 = 256 MiB
```

Source: `types.rs:222–234` — `ClusterGeometry::l2_entry_shift()`,
`l2_entries_per_table()`.

## The lookup algorithm

The full resolution follows these steps:

```
 guest_offset
      │
      ▼
 ┌─────────────────┐
 │ split into       │
 │ (l1, l2, intra)  │
 └────────┬─────────┘
          │
          ▼
 ┌─────────────────┐     offset == 0
 │ L1 Table        │ ─────────────────────► Unallocated
 │ entry [l1_index] │
 └────────┬─────────┘
          │ offset != 0
          ▼
 ┌─────────────────┐
 │ L2 Table at     │     L2Entry::Unallocated ──► Unallocated
 │ host offset     │     L2Entry::Zero ─────────► Zero
 │ entry [l2_index] │     L2Entry::Standard ────► Allocated
 └─────────────────┘     L2Entry::Compressed ──► Compressed
```

Source: `cluster_mapping.rs:78–130` — `ClusterMapper::resolve()`.

### Step 1: L1 lookup

The L1 table is read from the header's `l1_table_offset`. Each entry is a
64-bit value:

```
 L1 Entry (64 bits, big-endian)
 ┌──────┬─────────────────────────────────────────────┬──────────┐
 │ bit  │                                             │ bits     │
 │ 63   │              9 .. 55                        │ 8 .. 0   │
 ├──────┼─────────────────────────────────────────────┼──────────┤
 │COPIED│     L2 table host offset (cluster-aligned)  │ reserved │
 └──────┴─────────────────────────────────────────────┴──────────┘
```

- **Bits 9–55**: Host offset of the L2 table (masked with `L1_OFFSET_MASK =
  0x00ff_ffff_ffff_fe00`). If zero, the entire L2 range is unallocated.
- **Bit 63**: `COPIED` flag (`L1_COPIED_FLAG = 1 << 63`). Set when the
  refcount of the L2 table cluster is exactly one.
- **Bits 0–8, 56–62**: Reserved (must be zero).

Source: `constants.rs:65–69`, `l1.rs:18–23` — `L1Entry` doc comment and
bitmask definitions.

If the L1 entry's offset is zero, the lookup short-circuits to
`ClusterResolution::Unallocated`.

Source: `cluster_mapping.rs:88–91`.

### Step 2: Load L2 table

The L2 table is one cluster of L2 entries at the host offset from the L1
entry. The table is loaded into a cache (`MetadataCache`) on first access.

- Standard mode: `cluster_size / 8` entries, each 8 bytes.
- Extended L2: `cluster_size / 16` entries, each 16 bytes.

Source: `l2.rs:313–317` — `L2Table` doc comment,
`types.rs:231–234` — `ClusterGeometry::l2_entries_per_table()`.

### Step 3: Read L2 entry

Each L2 entry describes the state of one guest cluster. The entry is decoded
into one of four variants:

**Standard L2 entry (64 bits)**:

```
 ┌──────┬──────┬──────────────────────────────────────┬──────┐
 │ bit  │ bit  │                                      │ bit  │
 │ 63   │ 62   │          9 .. 55                     │  0   │
 ├──────┼──────┼──────────────────────────────────────┼──────┤
 │COPIED│COMPR │  host cluster offset                 │ ZERO │
 └──────┴──────┴──────────────────────────────────────┴──────┘
```

| Bit | Constant | Meaning |
|-----|----------|---------|
| 63 | `L2_COPIED_FLAG` (`1 << 63`) | Refcount of this cluster is exactly one |
| 62 | `L2_COMPRESSED_FLAG` (`1 << 62`) | Cluster is compressed (offset field has different meaning) |
| 0 | `L2_ZERO_FLAG` (`1`) | Cluster reads as zeros (v3 only) |
| 9–55 | `L2_STANDARD_OFFSET_MASK` (`0x00ff_ffff_ffff_fe00`) | Host cluster offset |

Source: `constants.rs:73–83`.

**Decoding logic** (standard mode):

| Offset | COMPRESSED | ZERO | Result |
|--------|-----------|------|--------|
| 0 | 0 | 0 | `Unallocated` |
| any | 0 | 1 | `Zero` (with optional preallocated offset) |
| != 0 | 0 | 0 | `Standard` (allocated, data at host offset) |
| — | 1 | — | `Compressed` (offset encodes compressed descriptor) |

Source: `l2.rs:244–262` — `L2Entry::decode_extended()` standard mode branch.

**Extended L2 entry (128 bits)**:

In extended L2 mode, each entry is two 64-bit words. The first word has the
same layout as above **except bit 0 is always 0** — zero status is tracked in
the subcluster bitmap instead. The second word is a `SubclusterBitmap`.

See [Extended L2](extended-l2.md) for the bitmap format.

Source: `l2.rs:216–263` — extended mode branch.

### Step 4: Map to ClusterResolution

The decoded `L2Entry` maps to a `ClusterResolution`:

| L2Entry | ClusterResolution | Meaning |
|---------|-------------------|---------|
| `Unallocated` | `Unallocated` | No data in this image; check backing file or return zeros |
| `Zero { preallocated: None }` | `Zero` | Returns zeros; no host cluster allocated |
| `Zero { preallocated: Some(offset) }` | `Allocated` | Has host cluster but reads as zeros (per-subcluster dispatch) |
| `Standard { host_offset, .. }` | `Allocated` | Data at `host_offset + intra_cluster_offset` |
| `Compressed(descriptor)` | `Compressed` | Compressed data; descriptor encodes location and size |

Source: `cluster_mapping.rs:97–129`.

## L1 table sizing

The L1 table must have enough entries to cover the virtual disk:

```
l1_size = ceil(virtual_size / (entries_per_l2 × cluster_size))
```

Each L1 entry is 8 bytes (`L1_ENTRY_SIZE` in `constants.rs:134`). The table
is stored at `l1_table_offset` (header field, must be cluster-aligned).

### Examples

| Virtual size | Cluster bits | Entries per L2 | L1 entries | L1 table bytes |
|-------------|-------------|---------------|-----------|---------------|
| 1 GiB | 16 | 8,192 | 2 | 16 |
| 10 GiB | 16 | 8,192 | 20 | 160 |
| 1 TiB | 16 | 8,192 | 2,048 | 16,384 |
| 1 GiB | 12 | 512 | 512 | 4,096 |

Source: `types.rs:319–327` — test `split_crosses_l1_boundary` confirms
`8192 * 65536 = 0x2000_0000` as the L1 boundary for `cluster_bits = 16`.

## Refcount table entry format

For reference, the refcount table uses a similar two-level structure. Its
entries are also 64-bit big-endian values with the offset in bits 9–63:

```
REFCOUNT_TABLE_OFFSET_MASK = 0xffff_ffff_ffff_fe00  (bits 9..=63)
```

Source: `constants.rs:87–88`.

See [Refcount Table](refcount-table.md) for details.
