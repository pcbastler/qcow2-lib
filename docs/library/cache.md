# Metadata Cache

The engine caches L2 tables and refcount blocks in an LRU cache to avoid
redundant I/O. Two modes control when dirty entries are written back to disk.

<!-- TODO
- Explain the two CacheMode variants:
    WriteBack (default):
      Dirty entries stay in the cache until evicted or flush() is called.
      The DIRTY incompatible feature flag is set in the header while entries
      are unflushed, allowing crash recovery.
      ~54% faster than WriteThrough in sequential write benchmarks
      (128 MiB/s vs 83 MiB/s on a 5 MB sequential write test).
    WriteThrough:
      Every mutation is written to disk immediately.
      Higher I/O amplification but no crash window.

- Explain CacheEntry<T>: wraps a value + dirty flag

- Explain LRU eviction: dirty entries evicted from LRU go into a pending buffer;
  the caller (engine) writes them before they are dropped

- Explain flush order (important for crash consistency):
    1. Write dirty refcount blocks
    2. Write dirty L2 tables
    3. fsync
    4. Clear the DIRTY incompatible flag in the header

- List when flush_dirty_metadata() is called automatically:
    - Before snapshot operations
    - Before integrity check
    - Before resize
    - On cache.clear()
    - In the Drop impl (best-effort; always call flush() explicitly)

- Explain CacheConfig: l2_table_capacity, refcount_block_capacity
- Reference: crates/qcow2-core/src/engine/cache.rs
- Reference: crates/qcow2-core/src/lru.rs
- Reference: crates/qcow2-core/src/engine/image_meta.rs
-->
