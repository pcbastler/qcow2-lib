# IoBackend Trait

`IoBackend` is the abstraction over positioned I/O that decouples the QCOW2
engine from any concrete storage. Implementing it is all that's needed to use
qcow2-core with a custom storage layer.

<!-- TODO
- Show the full trait definition with all methods and their contracts:
    read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>
    write_all_at(&self, buf: &[u8], offset: u64) -> Result<()>
    flush(&self) -> Result<()>
    file_size(&self) -> Result<u64>
    set_len(&self, size: u64) -> Result<()>

- Explain: trait is Send + Sync (required for Qcow2ImageAsync)
- Explain positioned I/O semantics: reads/writes do NOT advance a cursor;
  concurrent calls at different offsets are safe

- Document the two built-in implementations:
    SyncFileBackend: wraps std::fs::File using pread/pwrite on Unix
      - Construction: SyncFileBackend::open(path), ::create(path)
    MemoryBackend: Vec<u8> with RwLock, used in tests
      - Construction: MemoryBackend::new(), ::with_size(n)

- Show a minimal custom IoBackend implementation skeleton
- Reference: crates/qcow2-core/src/io.rs (trait definition)
- Reference: crates/qcow2/src/io/sync_backend.rs (SyncFileBackend)
- Reference: crates/qcow2/src/io/mod.rs (MemoryBackend)
-->
