# Qcow2Image API

`Qcow2Image` is the primary single-threaded interface for reading and writing
QCOW2 images. All operations take `&mut self`.

<!-- TODO
- Document the lifecycle methods:
    Qcow2Image::open(path) -> Result<Self>
    Qcow2Image::open_with_options(path, OpenOptions) -> Result<Self>
    Qcow2Image::create(path, CreateOptions) -> Result<Self>
    image.flush() -> Result<()>    ← must be called before drop in production
    Drop impl: best-effort flush (panics are swallowed)

- Document CreateOptions fields:
    virtual_size: u64
    cluster_bits: u8 (default 16 = 64 KB)
    version: v2 or v3
    encryption: Option<EncryptionOptions>
    compression_type: Option<CompressionType>
    extended_l2: bool
    refcount_order: u8
    backing_file: Option<String>
    cache_mode: CacheMode

- Document OpenOptions: password, cache_mode, read_only

- Document core I/O methods:
    read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<()>
    write_at(&mut self, buf: &[u8], offset: u64) -> Result<()>

- Document accessor methods:
    header(), virtual_size(), cluster_size(), is_encrypted(), is_dirty(),
    backing_file_path(), extensions()

- Document resize:
    resize(&mut self, new_size: u64) -> Result<()>

- Cross-reference: Snapshots API, Bitmaps API, BLAKE3 API, Integrity

- Reference: crates/qcow2/src/engine/image/mod.rs
- Reference: crates/qcow2/src/engine/image/open.rs
- Reference: crates/qcow2/src/engine/image/create.rs
- Reference: crates/qcow2/src/engine/image/read_write.rs
- Reference: crates/qcow2/src/engine/image/resize.rs
- Reference: crates/qcow2/src/engine/image/accessors.rs
-->
