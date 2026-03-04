# TODO

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
