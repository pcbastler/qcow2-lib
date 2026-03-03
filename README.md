# qcow2-lib

A pure-Rust library for reading, writing, and managing QCOW2 virtual disk images.

The `IoBackend` trait provides a clean async boundary — the consuming program controls I/O scheduling.

## Features

- **Read/Write** — Guest-offset based I/O with COW semantics and metadata caching
- **Create** — New QCOW2 v3 images with configurable cluster size
- **Snapshots** — Create, delete, apply, and list internal snapshots
- **Backing chains** — Full chain walk, commit (merge overlay → backing), rebase
- **Integrity** — Consistency checking and refcount repair
- **Resize** — Grow virtual disk size
- **Convert** — QCOW2 ↔ raw format conversion
- **Compact** — Defragment and shrink images, optional compression

## Quick start

```rust
use qcow2_lib::Qcow2Image;

// Read
let mut image = Qcow2Image::open("disk.qcow2")?;
let mut buf = vec![0u8; 4096];
image.read_at(&mut buf, 0)?;

// Write
let mut image = Qcow2Image::open_rw("disk.qcow2")?;
image.write_at(b"hello world", 0)?;
image.flush()?;
```

### Create a new image

```rust
use qcow2_lib::engine::image::CreateOptions;

let opts = CreateOptions {
    virtual_size: 10 * 1024 * 1024 * 1024, // 10 GiB
    cluster_bits: Some(16),                  // 64 KiB clusters
};
let mut image = Qcow2Image::create("new.qcow2", opts)?;
```

### Snapshots

```rust
let mut image = Qcow2Image::open_rw("disk.qcow2")?;
image.snapshot_create("before-upgrade")?;
// ... make changes ...
image.snapshot_apply("before-upgrade")?; // revert
```

### Custom I/O backend

```rust
use qcow2_lib::io::IoBackend;
use qcow2_lib::Qcow2Image;

struct MyBackend { /* ... */ }

impl IoBackend for MyBackend {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> qcow2_lib::Result<()> { todo!() }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> qcow2_lib::Result<()> { todo!() }
    fn flush(&self) -> qcow2_lib::Result<()> { todo!() }
    fn file_size(&self) -> qcow2_lib::Result<u64> { todo!() }
    fn set_len(&self, size: u64) -> qcow2_lib::Result<()> { todo!() }
}

let image = Qcow2Image::from_backend(Box::new(MyBackend { /* ... */ }))?;
```

## Architecture

```
format/     Pure on-disk data structures (header, L1/L2, refcount, snapshots)
io/         IoBackend trait + SyncFileBackend, MemoryBackend
engine/     Stateful logic: read/write translation, COW, cache, snapshots, repair
```

The three layers are strictly separated: `format` has no I/O, `io` has no format knowledge, `engine` combines both.

The `IoBackend` trait requires `Send + Sync` and uses positioned I/O (`pread`/`pwrite` style) — no file cursor, safe for concurrent access from the consuming program.

## CLI tool

An optional CLI tool is included for inspection and maintenance tasks:

```sh
cargo install --path . --features cli
```

```
qcow2-tool info disk.qcow2
qcow2-tool check disk.qcow2 --repair
qcow2-tool snapshot list disk.qcow2
qcow2-tool snapshot create disk.qcow2 snap1
qcow2-tool resize disk.qcow2 20G
qcow2-tool convert disk.qcow2 disk.raw
qcow2-tool compact disk.qcow2 compacted.qcow2 --compress
qcow2-tool commit overlay.qcow2
qcow2-tool rebase overlay.qcow2 --backing new-base.qcow2
```

## Testing

```sh
cargo test                 # 548 tests (unit + integration)
```

Integration tests use `qemu-img` / `qemu-io` for cross-validation and are skipped automatically if those tools are not installed.

## License

This software is proprietary. See [LICENSE](LICENSE) for details.
