# TODO

## Bugs (kritisch)

### Bug 1: Normal Writer — L1-Tabelle überschreibt Refcount-Strukturen

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

### Bug 2: BlockWriter — Compressed Cluster Corruption bei hohen Offsets

**Symptome:**
- `qemu-img check` meldet keine Fehler (Metadaten strukturell gültig)
- `qemu-io read` und unsere Library scheitern ab ~9 TiB:
  - `"unexpected end of file: failed to fill whole buffer"`
  - `"invalid input: corrupt deflate stream"`
- Nur bei `compress: true` mit verstreuten Writes über große Adressräume

**Nicht betroffen:** Das L1-Layout ist korrekt — der BlockWriter berechnet die
L1-Cluster-Anzahl dynamisch in `finalize.rs:204-209`.

**Verdachtsmomente (noch nicht definitiv isoliert):**

1. **`CompressedClusterDescriptor::encode()`** (`crates/qcow2-format/src/compressed.rs:51-57`):
   Maskiert `nb_sectors` mit `(1 << sector_bits) - 1` ohne Validierung. Bei
   `cluster_bits=16` stehen nur 8 Bits zur Verfügung (max 255 Sektoren = 128 KiB).
   Einzelne 64 KiB Cluster sollten nie >64 KiB komprimiert sein, aber `encode()`
   prüft das nicht — stille Abschneidung bei Randfällen möglich.

2. **Compressed Packing** (`crates/qcow2-core/src/engine/block_writer/metadata.rs:103-126`):
   `allocate_compressed()` verwaltet einen `compressed_cursor` für Cluster-Packing.
   Mögliche Überlappung zwischen gepackten komprimierten Clustern bei bestimmten
   Schreibmustern.

3. **Reader-Bug:** Fehlermeldung zeigt `"guest offset 0x0"` statt des tatsächlichen
   Offsets (9 TiB), was auf eine falsche Offset-Berechnung im Lese-Pfad hindeutet.

**Nächster Schritt:** Raw L2-Einträge bei 9 TiB und 12.8 TiB aus der
BlockWriter-Datei auslesen und `CompressedClusterDescriptor` manuell dekodieren,
um `host_offset` und `compressed_size` gegen die tatsächliche Dateigröße und
die Daten auf Disk zu verifizieren.

**Reproduzierbar mit:** `cargo run --release --example generate_13t`

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
