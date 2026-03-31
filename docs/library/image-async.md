# Qcow2ImageAsync API

`Qcow2ImageAsync` wraps `Qcow2Image` with fine-grained locking for concurrent
access from multiple threads. All methods take `&self`.

<!-- TODO
- Explain the locking model:
    - Per-L2-table RwLock: concurrent reads on different L2 ranges proceed in parallel
    - Global Mutex<ImageMeta>: held for ~1–5 µs during metadata mutations
      (cluster allocation, L2 update, refcount update)
    - Write path: acquire per-L2 write lock → acquire global meta lock →
      mutate → release both

- Document construction:
    Qcow2ImageAsync::from_image(image: Qcow2Image) -> Result<Self>
    Qcow2ImageAsync::into_image(self) -> Result<Qcow2Image>

- Document all methods (same feature set as Qcow2Image):
    read_at(&self, buf: &mut [u8], offset: u64) -> Result<()>
    write_at(&self, buf: &[u8], offset: u64) -> Result<()>
    flush(&self) -> Result<()>
    header(&self) -> Result<Header>
    virtual_size(&self) -> u64
    + snapshot, bitmap, hash, integrity methods

- Explain performance characteristics:
    - Parallel reads on non-overlapping L2 regions: ~2–4x throughput
    - Concurrent writes to different L2 tables proceed in parallel
    - All writes to the same L2 table are serialized

- Mention: this is NOT async/await based — it uses std threads and blocking I/O.
  The name "Async" refers to concurrent access, not async Rust.

- Reference: crates/qcow2/src/engine/image_async/mod.rs
- Reference: crates/qcow2/src/engine/image_async/read_write.rs
- Reference: crates/qcow2/src/engine/image_async/tests.rs
-->
