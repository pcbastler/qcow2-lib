# 2. Header

The header is the first thing in every QCOW2 file. It sits at byte offset 0 and
tells a reader everything it needs to know before touching any other part of the
file: what version this is, how large the virtual disk is, where the metadata
tables are, and which optional features are in use.

## 2.1 Two versions, one header

QCOW2 version 2 uses a fixed 72-byte header. Version 3 extends it to at least
104 bytes and adds feature flag fields. A reader can distinguish them by
checking the `version` field at byte 4.

Both versions share the same first 72 bytes. Version 3 appends 32 bytes of
feature flags and a self-describing `header_length` field, which allows future
versions to extend the header further without breaking existing parsers.

## 2.2 Reading the header

The first four bytes are the **magic number**: `0x514649fb` [1]. In ASCII, this
spells "QFI" followed by `0xfb`. If these bytes don't match, the file is not a
QCOW2 image.

```
 Byte 0    1    2    3
 ┌────┬────┬────┬────┐
 │ 51 │ 46 │ 49 │ fb │   "QFI\xfb"
 └────┴────┴────┴────┘
```

After confirming the magic, read the `version` field (bytes 4–7). If it's `2`,
read 72 bytes total. If it's `3`, read at least 104 bytes, then check
`header_length` to see if there's more.

## 2.3 Field reference

All fields are big-endian.

### 2.3.1 Common fields (v2 and v3)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | Must be `0x514649fb`. |
| 4 | 4 | `version` | `2` or `3`. |
| 8 | 8 | `backing_file_offset` | Byte offset of the backing file name string within this file. `0` means no backing file. |
| 16 | 4 | `backing_file_size` | Length of the backing file name in bytes (not null-terminated). |
| 20 | 4 | `cluster_bits` | Log₂ of the cluster size. For example, `16` means 2¹⁶ = 65,536 bytes = 64 KB. Valid range: 9–21 [2]. |
| 24 | 8 | `size` | Virtual disk size in bytes. This is the size the guest sees. |
| 32 | 4 | `crypt_method` | `0` = no encryption, `1` = AES-CBC (legacy), `2` = LUKS [2]. |
| 36 | 4 | `l1_size` | Number of entries in the L1 table. |
| 40 | 8 | `l1_table_offset` | Byte offset of the L1 table. Must be cluster-aligned. |
| 48 | 8 | `refcount_table_offset` | Byte offset of the refcount table. Must be cluster-aligned. |
| 56 | 4 | `refcount_table_clusters` | Number of clusters occupied by the refcount table. |
| 60 | 4 | `nb_snapshots` | Number of snapshots stored in this image. |
| 64 | 8 | `snapshots_offset` | Byte offset of the snapshot table. |

**Total: 72 bytes.** For version 2, the header ends here.

### 2.3.2 Version 3 additional fields

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 72 | 8 | `incompatible_features` | Feature bits that a reader **must** understand to open the image. Unknown bits → refuse to open. |
| 80 | 8 | `compatible_features` | Feature bits that a reader **may** safely ignore. |
| 88 | 8 | `autoclear_features` | Feature bits that are automatically cleared on first write by any implementation that does not understand them. Used for consistency flags. |
| 96 | 4 | `refcount_order` | Log₂ of the refcount width in bits. `4` = 2⁴ = 16-bit refcounts (the default and the only option in v2 [2]). Maximum: `6` = 64-bit [2]. |
| 100 | 4 | `header_length` | Total header size in bytes. At least 104 for v3. Allows future extension: a reader should read `header_length` bytes and ignore any trailing fields it does not understand. |
| 104 | 1 | `compression_type` | `0` = deflate, `1` = zstd [2]. Only valid if the `COMPRESSION_TYPE` incompatible feature flag is set [3]. Otherwise, deflate is assumed. |

**Total: at least 104 bytes** (may be larger if `header_length` says so).

### 2.3.3 Visual layout

```
 Offset (hex)
 00  ┌──────────────────────────┐
     │  magic          (4)      │
 04  │  version        (4)      │
 08  │  backing_file_offset (8) │
 10  │  backing_file_size   (4) │
 14  │  cluster_bits       (4)  │
 18  │  size               (8)  │
 20  │  crypt_method       (4)  │
 24  │  l1_size            (4)  │
 28  │  l1_table_offset    (8)  │
 30  │  refcount_table_off (8)  │
 38  │  refcount_tbl_clust (4)  │
 3C  │  nb_snapshots       (4)  │
 40  │  snapshots_offset   (8)  │
     ├──────────────────────────┤ ← v2 ends here (72 bytes)
 48  │  incompatible_feat  (8)  │
 50  │  compatible_feat    (8)  │
 58  │  autoclear_feat     (8)  │
 60  │  refcount_order     (4)  │
 64  │  header_length      (4)  │
 68  │  compression_type   (1)  │
     ├──────────────────────────┤ ← v3 minimum (104 bytes)
     │  (padding / future use)  │
     └──────────────────────────┘
```

## 2.4 Key concepts

### 2.4.1 cluster_bits and cluster size

The `cluster_bits` field determines the cluster size: **cluster_size = 2^cluster_bits^** [1].

| `cluster_bits` | Cluster size | Typical use |
|---------------|-------------|-------------|
| 9 | 512 B | Minimum, rarely used |
| 12 | 4 KB | Matches common filesystem block size |
| 16 | **64 KB** | **Default.** Good balance of metadata overhead and space efficiency. |
| 21 | 2 MB | Maximum. Large clusters reduce metadata but waste space for small writes. |

The cluster size affects everything:
- How many entries fit in an L2 table (= cluster_size / 8, or / 16 for extended L2) [4]
- How much address space each L2 table covers
- The granularity of allocation (even a 1-byte write allocates a full cluster)

### 2.4.2 How l1_size is calculated

The `l1_size` field is not arbitrary — it is determined by the virtual disk size
and the cluster geometry:

```
entries_per_l2   = cluster_size / 8
bytes_per_l2     = entries_per_l2 × cluster_size
l1_size          = ceil(virtual_size / bytes_per_l2)
```

**Example**: A 10 GiB image with 64 KB clusters:

```
entries_per_l2   = 65,536 / 8 = 8,192
bytes_per_l2     = 8,192 × 65,536 = 536,870,912 (512 MiB)
l1_size          = ceil(10 GiB / 512 MiB) = 20
```

The L1 table has 20 entries, occupying 20 × 8 = 160 bytes.

### 2.4.3 refcount_order and refcount width

Version 2 always uses 16-bit reference counts (`refcount_order` = 4,
meaning 2⁴ = 16 bits). Version 3 allows wider refcounts:

| `refcount_order` | Refcount width | Max refcount value | Use case |
|-----------------|---------------|-------------------|----------|
| 0 | 1 bit | 1 | Minimal (cluster is used or free, no sharing) |
| 4 | 16 bits | 65,535 | Default. Sufficient for most workloads. |
| 5 | 32 bits | ~4 billion | Many snapshots sharing clusters |
| 6 | 64 bits | ~1.8 × 10¹⁹ | Theoretical maximum |

Wider refcounts use more space per cluster but allow more sharing (more
snapshots referencing the same cluster without overflow).

## 2.5 What comes after the header?

Immediately after the header (padded to 8-byte alignment) come the **header
extensions** — a chain of type-length-value entries that carry optional
metadata. The chain is terminated by a zero-type entry. For version 2,
extensions may or may not be present. For version 3, the extension area starts
at byte `header_length`.

→ Next: Section 4 — [Header Extensions](04-header-extensions.md)

## 2.6 Validation

A QCOW2 reader should validate the header before trusting any offsets [1]. Key
checks:

1. **Magic** must be `0x514649fb`.
2. **Version** must be `2` or `3`.
3. **cluster_bits** must be in range 9–21.
4. **l1_table_offset** must be cluster-aligned (if `l1_size` > 0).
5. **refcount_table_offset** must be cluster-aligned.
6. **incompatible_features** (v3): all set bits must be known. Unknown bits
   mean the image uses features this reader cannot handle — it must refuse to
   open.
7. All offsets (L1, refcount, snapshots, backing file) must point within the
   physical file size.
8. **header_length** must not exceed the cluster size.

## Source References

| Ref | File | What it contains |
|-----|------|-----------------|
| [1] | [header.rs](../../crates/qcow2-format/src/header.rs#L24-L64) | `Header` struct with all fields |
| | [header.rs](../../crates/qcow2-format/src/header.rs#L67-L86) | `OFF_*` byte offset constants |
| | [header.rs](../../crates/qcow2-format/src/header.rs#L99-L130) | `read_from()` — parsing logic |
| | [header.rs](../../crates/qcow2-format/src/header.rs#L352-L396) | `validate_structural()` |
| | [header.rs](../../crates/qcow2-format/src/header.rs#L403-L417) | `validate_against_file()` |
| [2] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L9) | `QCOW2_MAGIC = 0x514649fb` |
| | [constants.rs](../../crates/qcow2-format/src/constants.rs#L26-L34) | `MIN_CLUSTER_BITS`, `MAX_CLUSTER_BITS`, `DEFAULT_CLUSTER_BITS` |
| | [constants.rs](../../crates/qcow2-format/src/constants.rs#L38-L42) | `MAX_REFCOUNT_ORDER`, `DEFAULT_REFCOUNT_ORDER_V2` |
| | [constants.rs](../../crates/qcow2-format/src/constants.rs#L46-L61) | `CRYPT_*`, `COMPRESSION_*` |
| [3] | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L24) | `IncompatibleFeatures::COMPRESSION_TYPE` |
| [4] | [types.rs](../../crates/qcow2-format/src/types.rs#L222-L234) | `ClusterGeometry::l2_entry_size()`, `l2_entries_per_table()` |
