# TODO

## Bugs (critical)

### ~~Bug 1: Normal Writer — L1 Table Overwrites Refcount Structures~~ (FIXED)

**File:** `crates/qcow2/src/engine/image/create.rs:330-334`

**Root Cause:** The disk layout in `create_on_backend()` is hardcoded to exactly
1 cluster for the L1 table:

```rust
let l1_offset = cluster_size;          // Cluster 1
let rt_offset = 2 * cluster_size;      // Cluster 2
let rb_offset = 3 * cluster_size;      // Cluster 3
let initial_clusters = 4u64;
```

For images >4 TiB (with 64 KiB clusters) the L1 table needs more than
1 cluster. Example 13 TiB: 26,624 L1 entries × 8 bytes = 212,992 bytes =
3.25 clusters. The L1 table grows into the refcount table region
(cluster 2) and the refcount block (cluster 3).

**Thresholds** (cluster_bits=16, non-extended L2):
- Up to 4 TiB: L1 fits in 1 cluster (8192 entries) → OK
- From 4 TiB: L1 index 8192+ overwrites refcount table (cluster 2)
- From 8 TiB: L1 index 16384+ overwrites refcount block (cluster 3)

**Proof:** QEMU reports `L1 entry with reserved bits set: 1000100010001`.
The value `0x0001_0001_0001_0001` corresponds exactly to four 16-bit refcount
entries (value 1, big-endian) — the refcount block is misinterpreted as an
L1 entry.

**Also affects:** `create_overlay_on_backend()` (same file, same layout).

**Fix:**
```rust
let l1_clusters = ((l1_entries as u64 * 8) + cluster_size - 1) / cluster_size;
let l1_offset = cluster_size;
let rt_offset = (1 + l1_clusters) * cluster_size;
let rb_offset = (2 + l1_clusters) * cluster_size;
let initial_clusters = 3 + l1_clusters;
```

---

### ~~Bug 2: BlockWriter — Compressed Cluster Corruption at High Offsets~~ (FIXED)

**Root Cause:** `allocate_compressed()` in `InMemoryMetadata` had a
cursor overflow bug in compressed cluster packing. When compressed entries
filled a host cluster exactly (128 × 512 = 65536 = cluster_size), the
`compressed_cursor` advanced to `next_host_offset`. The modulo check
`cursor % cluster_size == 0` treated this as free space — subsequent writes
went into unallocated memory. During finalize, metadata (L2 tables) was
written over the compressed data.

**Three sub-bugs:**
1. Cursor overflow without interleaving → Fix: `compressed_cluster_end` field
   tracks the exact end of the current packing cluster
2. Cursor not invalidated when `allocate_cluster()` allocates into the cursor
   region → Fix: invalidation in `allocate_cluster()` and `allocate_n_clusters()`
3. Reader error message showed `guest_offset: 0x0` instead of the actual offset
   → Fix: patch `DecompressionFailed` error in reader with correct guest_offset

**Files:**
- `crates/qcow2-core/src/engine/block_writer/metadata.rs` (fixes 1+2, 6 unit tests)
- `crates/qcow2-core/src/engine/reader.rs` (fix 3)
- `crates/qcow2/tests/block_writer.rs` (2 end-to-end regression tests)

---

## Metadata Overwrite Protection

Currently only `debug_assert!`-based checks exist (completely absent in release
builds) and a post-hoc overlap detection in the integrity checker. The following
runtime protection mechanisms are missing:

- [ ] **`debug_assert!` → runtime check in `write_l1_entry()`** — The existing
  `debug_assert!(index.0 < self.mapper.l1_table().len())` in
  `crates/qcow2-core/src/engine/writer/mod.rs:291` should become an actual
  `Error` return. An L1 index overflow is a fatal logic error that must be
  caught immediately — even in release builds. Cost: 1 comparison per
  L1 write (negligible).

- [ ] **`debug_assert_layout_no_overlap()` → runtime check** — The function in
  `crates/qcow2/src/engine/image/create.rs:95` uses `debug_assert!`. Since it
  is only called during image creation (once), it can become an actual
  `Error` return with no performance impact.

- [ ] **`allocate_cluster()` metadata collision check** —
  `RefcountManager::allocate_cluster()` in
  `crates/qcow2-core/src/engine/refcount_manager.rs:121` does not check whether
  the allocated offset collides with existing metadata regions (header, L1 table,
  refcount table). Fix: the RefcountManager already knows the header offsets — a
  check `new_offset < data_start` in append mode would be free.

- [ ] **`write_l2_entry()` offset validation** — Writes to
  `l2_table_offset + index * entry_size` without verifying that the target offset
  is actually an allocated L2 cluster. A corrupt L1 entry could redirect an
  L2 write into arbitrary metadata regions.

- [ ] **Central metadata region registry** — Currently no code path knows at
  runtime which byte ranges belong to which structures. A lightweight registry
  (sorted list of `(start, end, kind)`) in `Qcow2Image` would allow validating
  every write against known metadata regions. Overhead: built once during
  `open()`, O(log n) lookup per allocation.

---

## Unchecked Index Accesses

Variable array/slice index accesses in production code that could panic on
out-of-bounds. Use `scripts/find-production-indexing.sh` to regenerate.

- [x] **refcount_manager.rs:409** — `refcount_table[table_index]` without bounds check
  - Also hardened line 205 (had check before but still used direct index)
- [x] **image_async/read_write.rs:51,122,212** — `l2_locks[l1_index]` → extracted `l2_read_guard`/`l2_write_guard` helpers with `.get()`
- [x] **io/mod.rs:74,98** — `data[start..end]` in MemoryBackend (already safe, documented)
- [x] **bitmap_manager.rs:546** — `data[byte_idx]` in `set_bits_msb` → `.get_mut()` with error
- [x] **chain.rs:55** — `output_files[layer_idx - 1]` → `.get()` with error
- [x] **structure.rs:53** — `data[i - 1]` (already safe, documented)
- [ ] **bitmap_manager.rs** — `entries[idx]` (414, 456, 483, 554, 588, 589, 683, 685), `data[byte_off]` (469)
- [ ] **reader.rs** — `buf[pos..pos+len]` slice accesses (197, 253, 316, 317, 321, 331, 335, 339, 371, 372)
- [ ] **writer/data_ops.rs** — `buf[start..]` slice accesses (60, 108, 210, 261, 262, 347, 490), block_writer
- [ ] **Format parsing** — `bytes[pos..]` in snapshot.rs, header_extension.rs, l1.rs, l2.rs, refcount.rs, bitmap.rs, hash.rs
- [ ] **Encryption** — `data[off..off+N]` in luks_header.rs, af_splitter.rs, mod.rs
- [ ] **Rescue/Recovery** — `buf[entry_offset+N]` in orphan.rs, classifier.rs, refinement.rs
- [ ] **integrity.rs** — `regions[i]`/`regions[j]` (347-348), `rt_buf[i*SIZE..]`
- [ ] **converter.rs** — `buf[pos..pos+chunk]` slice accesses
- [ ] **image/create.rs** — `header_buf[ext_offset..]`, `rb_buf[i*2..]` etc.
- [ ] **CLI dump.rs/resize.rs** — `rt_buf[offset..]`, `l1_buf[offset..]`

---

## Performance

- [ ] **Cache hash table in `Qcow2Image`** — `update_hashes_for_range` loads the
  hash table from disk on every `write_at` call via `load_hash_table`. For many
  small writes this is an I/O read per write. Fix: store `Option<HashTable>` in
  `Qcow2Image`, lazy-load on first hash write, invalidate on flush/snapshot ops.

## Async Concurrency

- [ ] **Investigate: Meta mutex potentially held too long in `Qcow2ImageAsync`** —
  `read_chunk` and `write_chunk` in
  `crates/qcow2/src/engine/image_async/read_write.rs:55,122` appear to hold the
  global `Mutex<ImageMeta>` for the entire operation including data I/O. If
  confirmed, all reads and writes would be globally serialized, rendering the
  per-L2 `RwLock`s ineffective — the documented parallelism (doc-comment table
  in `mod.rs`) would not match the implementation. Needs verification: whether
  the meta mutex is actually held across data I/O, and if so, whether it can be
  shortened to cluster resolution only.

---

## API Design

- [ ] **`write_at` with empty buffer** — Currently a silent no-op (POSIX
  convention). Consider returning an error instead to catch caller bugs early.
  Would need `Error::EmptyWrite` and guards in both `write_at` and
  `update_hashes_for_range`.
