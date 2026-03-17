# qcow2-lib Documentation

## Format Reference

On-disk QCOW2 format specification. Language-agnostic — covers binary layout,
field semantics, and algorithm details.

- [Index](format/00-index.md)
- [1. Overview](format/01-overview.md)
- [2. Header](format/02-header.md)
- [3. Feature Flags](format/03-feature-flags.md)
- [4. Header Extensions](format/04-header-extensions.md)
- [5. Cluster Addressing](format/05-cluster-addressing.md)
- [6. Extended L2](format/06-extended-l2.md)
- [7. Refcount Table](format/07-refcount-table.md)
- [8. Cluster Types](format/08-cluster-types.md)
- [9. Compression](format/09-compression.md)
- [10. Encryption](format/10-encryption.md)
- [11. Snapshots](format/11-snapshots.md)
- [12. Bitmaps](format/12-bitmaps.md)
- [13. BLAKE3 Hashes](format/13-blake3-hashes.md)
- [14. External Data File](format/14-external-data-file.md)
- [15. Backing File](format/15-backing-file.md)

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
