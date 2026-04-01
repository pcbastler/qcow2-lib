# TODO

## Bugs (kritisch)

### ~~Bug 1: Normal Writer — L1-Tabelle überschreibt Refcount-Strukturen~~ (FIXED)

**Datei:** `crates/qcow2/src/engine/image/create.rs:330-334`

**Root Cause:** Das Disk-Layout in `create_on_backend()` ist hardcoded auf genau
1 Cluster für die L1-Tabelle:

```rust
let l1_offset = cluster_size;          // Cluster 1
let rt_offset = 2 * cluster_size;      // Cluster 2
let rb_offset = 3 * cluster_size;      // Cluster 3
let initial_clusters = 4u64;
```

Für Images >4 TiB (bei 64 KiB Clustern) braucht die L1-Tabelle aber mehr als
1 Cluster. Beispiel 13 TiB: 26.624 L1-Einträge × 8 Bytes = 212.992 Bytes =
3,25 Cluster. Die L1-Tabelle wächst in den Bereich der Refcount-Tabelle
(Cluster 2) und des Refcount-Blocks (Cluster 3) hinein.

**Schwellenwerte** (cluster_bits=16, non-extended L2):
- Bis 4 TiB: L1 passt in 1 Cluster (8192 Einträge) → OK
- Ab 4 TiB: L1-Index 8192+ überschreibt Refcount-Tabelle (Cluster 2)
- Ab 8 TiB: L1-Index 16384+ überschreibt Refcount-Block (Cluster 3)

**Beweis:** QEMU meldet `L1 entry with reserved bits set: 1000100010001`.
Der Wert `0x0001_0001_0001_0001` entspricht exakt vier 16-Bit-Refcount-Einträgen
(Wert 1, Big-Endian) — der Refcount-Block wird als L1-Entry fehlinterpretiert.

**Betrifft auch:** `create_overlay_on_backend()` (gleiche Datei, gleiches Layout).

**Fix:**
```rust
let l1_clusters = ((l1_entries as u64 * 8) + cluster_size - 1) / cluster_size;
let l1_offset = cluster_size;
let rt_offset = (1 + l1_clusters) * cluster_size;
let rb_offset = (2 + l1_clusters) * cluster_size;
let initial_clusters = 3 + l1_clusters;
```

---

### ~~Bug 2: BlockWriter — Compressed Cluster Corruption bei hohen Offsets~~ (FIXED)

**Root Cause:** `allocate_compressed()` in `InMemoryMetadata` hatte einen
Cursor-Overflow-Bug beim Compressed-Cluster-Packing. Wenn komprimierte Einträge
einen Host-Cluster exakt füllten (128 × 512 = 65536 = cluster_size), rückte der
`compressed_cursor` auf `next_host_offset` vor. Die Modulo-Prüfung
`cursor % cluster_size == 0` sah das als freien Platz — nachfolgende Writes
gingen in nicht-allokierten Speicher. Beim Finalize wurden Metadaten (L2-Tabellen)
über die komprimierten Daten geschrieben.

**Drei Unter-Bugs:**
1. Cursor-Overflow ohne Interleaving → Fix: `compressed_cluster_end` Feld trackt
   exakt das Ende des aktuellen Packing-Clusters
2. Cursor nicht invalidiert wenn `allocate_cluster()` den Cursor-Bereich allokiert
   → Fix: Invalidierung in `allocate_cluster()` und `allocate_n_clusters()`
3. Reader-Fehlermeldung zeigte `guest_offset: 0x0` statt des echten Offsets
   → Fix: `DecompressionFailed` Error im Reader mit korrektem guest_offset patchen

**Dateien:**
- `crates/qcow2-core/src/engine/block_writer/metadata.rs` (Fixes 1+2, 6 Unit-Tests)
- `crates/qcow2-core/src/engine/reader.rs` (Fix 3)
- `crates/qcow2/tests/block_writer.rs` (2 End-to-End-Regressionstests)

---

## Metadaten-Überschreibungsschutz

Aktuell existieren nur `debug_assert!`-basierte Checks (in Release komplett weg)
und eine nachträgliche Overlap-Detection im Integrity Checker. Folgende
Runtime-Schutzmechanismen fehlen:

- [ ] **`debug_assert!` → Runtime-Check in `write_l1_entry()`** — Der bestehende
  `debug_assert!(index.0 < self.mapper.l1_table().len())` in
  `crates/qcow2-core/src/engine/writer/mod.rs:291` sollte ein echter
  `Error`-Return werden. Ein L1-Index-Overflow ist ein fataler Logikfehler, der
  sofort abgefangen werden muss — auch in Release. Kosten: 1 Vergleich pro
  L1-Write (vernachlässigbar).

- [ ] **`debug_assert_layout_no_overlap()` → Runtime-Check** — Die Funktion in
  `crates/qcow2/src/engine/image/create.rs:95` verwendet `debug_assert!`. Da sie
  nur bei Image-Erstellung (einmalig) aufgerufen wird, kann sie ohne
  Performance-Einbußen zu einem echten `Error`-Return werden.

- [ ] **`allocate_cluster()` Metadaten-Kollisionsprüfung** —
  `RefcountManager::allocate_cluster()` in
  `crates/qcow2-core/src/engine/refcount_manager.rs:121` prüft nicht, ob der
  allokierte Offset mit bestehenden Metadaten-Regionen (Header, L1-Table,
  Refcount-Table) kollidiert. Fix: Der RefcountManager kennt die Header-Offsets
  bereits — ein Check `new_offset < data_start` bei Append-Mode wäre kostenlos.

- [ ] **`write_l2_entry()` Offset-Validierung** — Schreibt an
  `l2_table_offset + index * entry_size` ohne zu prüfen, ob der Ziel-Offset
  tatsächlich ein allokierter L2-Cluster ist. Ein korrupter L1-Eintrag könnte
  einen L2-Write in beliebige Metadaten-Bereiche umleiten.

- [ ] **Zentrales Metadaten-Region-Registry** — Aktuell weiß kein Codepfad zur
  Laufzeit, welche Byte-Bereiche zu welchen Strukturen gehören. Ein leichtgewichtiges
  Registry (sortierte Liste von `(start, end, kind)`) im `Qcow2Image` würde
  ermöglichen, jeden Write gegen bekannte Metadaten-Regionen zu validieren. Overhead:
  einmalig bei `open()` aufbauen, O(log n) Lookup pro Allokation.

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
- [ ] **Format-Parsing** — `bytes[pos..]` in snapshot.rs, header_extension.rs, l1.rs, l2.rs, refcount.rs, bitmap.rs, hash.rs
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

## API Design

- [ ] **`write_at` with empty buffer** — Currently a silent no-op (POSIX
  convention). Consider returning an error instead to catch caller bugs early.
  Would need `Error::EmptyWrite` and guards in both `write_at` and
  `update_hashes_for_range`.
