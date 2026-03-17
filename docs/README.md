# qcow2-lib Documentation

## Format Reference

On-disk QCOW2 format specification. Language-agnostic — covers binary layout,
field semantics, and algorithm details.

- [Format Overview](format/README.md)
- [Header](format/header.md)
- [Feature Flags](format/feature-flags.md)
- [Header Extensions](format/header-extensions.md)
- [Cluster Addressing (L1 / L2)](format/cluster-addressing.md)
- [Extended L2 & Subclusters](format/extended-l2.md)
- [Refcount Table](format/refcount-table.md)
- [Cluster Types](format/cluster-types.md)
- [Compression](format/compression.md)
- [Encryption](format/encryption.md)
- [Snapshots](format/snapshots.md)
- [Bitmaps](format/bitmaps.md)
- [BLAKE3 Hashes](format/blake3-hashes.md)
- [External Data File](format/external-data-file.md)
- [Backing File](format/backing-file.md)

## Library Reference

Rust library (`qcow2-lib`) usage, API, and internals.

- [Library Overview](library/README.md)
- [Architecture](library/architecture.md)
- [Getting Started](library/getting-started.md)
- [Error Handling](library/error-handling.md)
- [IoBackend Trait](library/io-backend.md)
- [Compressor Trait](library/compressor.md)
- [BackingImage Trait](library/backing-image.md)
- [Metadata Cache](library/cache.md)
- [Qcow2Image API](library/image-api.md)
- [Qcow2ImageAsync API](library/image-async.md)
- [Qcow2BlockWriter](library/block-writer.md)
- [Encryption API](library/encryption-api.md)
- [Snapshots API](library/snapshots-api.md)
- [Bitmaps API](library/bitmaps-api.md)
- [BLAKE3 Hash API](library/blake3-api.md)
- [Integrity Check & Repair](library/integrity.md)
- [Format Conversion](library/conversion.md)
- [CLI — qcow2-tool](library/cli/README.md)
- [qcow2-rescue](library/rescue.md)
- [Testing & Fuzzing](library/testing.md)

## Meta

- [Documentation Audit](audit.md) — claims not directly verifiable from source code
