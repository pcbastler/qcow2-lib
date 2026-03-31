# qcow2-lib Library Reference

A pure-Rust implementation of QCOW2 with no unsafe code, no_std-compatible
engine, and full QEMU interoperability.

<!-- TODO
- Write a 2–3 paragraph intro: what the library provides, who it's for,
  what QEMU compatibility level to expect
- List crate names and what to add to Cargo.toml for common use cases:
    read/write images → qcow2
    format types only → qcow2-format
    custom I/O backend → qcow2-core
    CLI tool → qcow2-tool (binary)
- Add a minimal "5 lines to read a QCOW2 file" teaser
- Reference: crates/qcow2/src/lib.rs, Cargo.toml workspace root
-->

## Sections

- [Architecture](architecture.md)
- [Getting Started](getting-started.md)
- [Error Handling](error-handling.md)
- [IoBackend Trait](io-backend.md)
- [Compressor Trait](compressor.md)
- [BackingImage Trait](backing-image.md)
- [Metadata Cache](cache.md)
- [Qcow2Image API](image-api.md)
- [Qcow2ImageAsync API](image-async.md)
- [Qcow2BlockWriter](block-writer.md)
- [Encryption API](encryption-api.md)
- [Snapshots API](snapshots-api.md)
- [Bitmaps API](bitmaps-api.md)
- [BLAKE3 Hash API](blake3-api.md)
- [Integrity Check & Repair](integrity.md)
- [Format Conversion](conversion.md)
- [CLI — qcow2-tool](cli/README.md)
- [qcow2-rescue](rescue.md)
- [Testing & Fuzzing](testing.md)
