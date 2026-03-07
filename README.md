# qcow2-lib

A pure-Rust library for reading, writing, and managing QCOW2 virtual disk images.

## Workspace

```
qcow2-format   Pure on-disk types, encode/decode (no_std)
    |
qcow2-core     Engine: cluster mapping, read/write, COW, snapshots, refcounts (no_std)
    |
qcow2          std wrapper: file/memory backends, compression, encryption, backing chains
    |
qcow2-tool     CLI for inspection and maintenance
qcow2-rescue   Recovery tool for corrupted images
```

All crates live under `crates/`. The `IoBackend` trait (Send + Sync, positioned I/O) provides the async boundary — the consuming program controls I/O scheduling.

## Features

- **Read/Write** — Guest-offset based I/O with COW semantics and metadata caching
- **Create** — New QCOW2 v3 images with configurable cluster size
- **Snapshots** — Create, delete, apply, and list internal snapshots
- **Backing chains** — Full chain walk, commit (merge overlay into backing), rebase
- **Integrity** — Consistency checking and refcount repair
- **Resize** — Grow virtual disk size
- **Convert** — QCOW2 <-> raw format conversion
- **Compact** — Defragment and shrink images, optional compression
- **Extended L2** — Subcluster-granular allocation (32 subclusters per cluster)
- **Zstandard compression** — Zstd-compressed clusters (`compression_type=1`)
- **External data file** — Separate raw data file with `data_file` / `data_file_raw` support
- **Persistent dirty bitmaps** — Full bitmap lifecycle and QEMU interop
- **BLAKE3 hashes** — Per-cluster content hashes via custom extension
- **LUKS encryption** — LUKS1/LUKS2, AES-XTS-plain64 and AES-CBC-ESSIV, full QEMU interop

## Quick start

```rust
use qcow2::Qcow2Image;

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
use qcow2::engine::image::CreateOptions;

let opts = CreateOptions {
    virtual_size: 10 * 1024 * 1024 * 1024, // 10 GiB
    cluster_bits: Some(16),                  // 64 KiB clusters
    extended_l2: false,
    compression_type: None,
    data_file: None,
    encryption: None,
};
let mut image = Qcow2Image::create("new.qcow2", opts)?;
```

### Encrypted images

```rust
use qcow2::engine::image::{CreateOptions, EncryptionOptions};
use qcow2::engine::encryption::CipherMode;

let opts = CreateOptions {
    virtual_size: 1 << 30,
    cluster_bits: None,
    extended_l2: false,
    compression_type: None,
    data_file: None,
    encryption: Some(EncryptionOptions {
        password: b"my-secret".to_vec(),
        cipher: CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: None,
    }),
};
let mut image = Qcow2Image::create("encrypted.qcow2", opts)?;
image.write_at(b"secret data", 0)?;
image.flush()?;

// Open existing encrypted image
let mut image = Qcow2Image::open_with_password("encrypted.qcow2", b"my-secret")?;
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
use qcow2::io::IoBackend;
use qcow2::Qcow2Image;

struct MyBackend { /* ... */ }

impl IoBackend for MyBackend {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> qcow2::Result<()> { todo!() }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> qcow2::Result<()> { todo!() }
    fn flush(&self) -> qcow2::Result<()> { todo!() }
    fn file_size(&self) -> qcow2::Result<u64> { todo!() }
    fn set_len(&self, size: u64) -> qcow2::Result<()> { todo!() }
}

let image = Qcow2Image::from_backend(Box::new(MyBackend { /* ... */ }))?;
```

## CLI tool (`qcow2-tool`)

```
qcow2-tool info disk.qcow2
qcow2-tool check disk.qcow2 --repair
qcow2-tool snapshot list disk.qcow2
qcow2-tool snapshot create disk.qcow2 snap1
qcow2-tool resize disk.qcow2 20G
qcow2-tool convert disk.qcow2 disk.raw
qcow2-tool convert disk.qcow2 encrypted.qcow2 --encrypt --encrypt-password secret
qcow2-tool compact disk.qcow2 compacted.qcow2 --compress
qcow2-tool commit overlay.qcow2
qcow2-tool rebase overlay.qcow2 --backing new-base.qcow2
qcow2-tool bitmap list disk.qcow2
qcow2-tool hash disk.qcow2
```

## Recovery tool (`qcow2-rescue`)

A standalone tool for recovering data from corrupted QCOW2 images that `qemu-img check -r all` cannot repair. See the [qcow2-rescue README](crates/qcow2-rescue/README.md) for details.

## Testing

```sh
cargo test --workspace    # 1314 tests
```

Integration tests use `qemu-img` / `qemu-io` for cross-validation (LUKS encryption, zstd compression, extended L2, external data files) and are skipped automatically if those tools are not installed.

## License

This software is proprietary. See [LICENSE](LICENSE) for details.
