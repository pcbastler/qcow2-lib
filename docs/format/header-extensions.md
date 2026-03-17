# Header Extensions

Header extensions are optional metadata entries that follow the fixed header
fields within the first cluster. They use a simple type-length-value (TLV)
encoding that allows new extension types to be added without changing the
header layout.

## Location

The extension area begins immediately after the fixed header:

- **Version 3**: at byte offset `header_length` within the first cluster.
- **Version 2**: after byte 72 (if any data is present before the first
  cluster boundary).

Source: `header_extension.rs:73–78` — `read_all()` doc comment: "The slice
should start immediately after the main header (at the offset `header_length`
within the first cluster)."

## TLV encoding

Each extension consists of a header and a data payload:

```
 ┌─────────────────────────────┐
 │  type       (4 bytes, u32)  │
 │  length     (4 bytes, u32)  │
 ├─────────────────────────────┤
 │  data       (length bytes)  │
 │  padding    (0–7 bytes)     │  ← pad to 8-byte boundary
 └─────────────────────────────┘
```

- **type**: a 32-bit identifier. Type `0x00000000` marks the end of the
  extension list.
- **length**: the number of data bytes (not including padding).
- **data**: `length` bytes of extension-specific content.
- **padding**: zero bytes to bring the total (header + data) to the next
  8-byte boundary. The padding length is `(8 - (length % 8)) % 8`.

All fields are big-endian. The TLV header itself is 8 bytes
(`TLV_HEADER_SIZE` in `header_extension.rs:21`).

Source: `header_extension.rs:1–5` — module doc, and `read_all()` /
`write_all()` implementations.

### Parsing

Extensions are read sequentially until:

1. An end-of-extensions marker (type `0x00000000`) is encountered, **or**
2. There are fewer than 8 bytes remaining (not enough for another TLV header).

If an extension claims more data than is available, parsing fails with
`Error::ExtensionTruncated`.

Source: `header_extension.rs:83–122`.

## Known extension types

| Type ID | Constant | Variant | Description |
|---------|----------|---------|-------------|
| `0x00000000` | `EXT_END_OF_EXTENSIONS` | — | End marker. Terminates the extension list. |
| `0xe2792aca` | `EXT_BACKING_FILE_FORMAT` | `BackingFileFormat(String)` | Format name of the backing file (e.g. `"qcow2"`, `"raw"`). Stored as a UTF-8 string, not null-terminated. |
| `0x6803f857` | `EXT_FEATURE_NAME_TABLE` | `FeatureNameTable(Vec<FeatureNameEntry>)` | Maps (feature_type, bit_number) pairs to human-readable names. See below. |
| `0x23852875` | `EXT_BITMAPS` | `Bitmaps(BitmapExtension)` | Bitmap directory reference. See [Bitmaps](bitmaps.md). |
| `0x0537be77` | `EXT_FULL_DISK_ENCRYPTION` | `FullDiskEncryption { offset, length }` | Pointer to the LUKS encryption header: 8-byte offset + 8-byte length (16 bytes total). See [Encryption](encryption.md). |
| `0x44415441` | `EXT_EXTERNAL_DATA_FILE` | `ExternalDataFile(String)` | Path of the external data file. Stored as a UTF-8 string. See [External Data File](external-data-file.md). |
| `0x434c4233` | `EXT_BLAKE3_HASHES` | `Blake3Hashes(Blake3Extension)` | BLAKE3 per-chunk hash table reference (qcow2-lib extension). See [BLAKE3 Hashes](blake3-hashes.md). |

Source: `constants.rs:92–108` (type IDs), `constants.rs:188–189` (BLAKE3),
`header_extension.rs:24–56` (enum variants).

### Unknown extension types

Any extension type not listed above is preserved as
`Unknown { extension_type, data }`. This allows round-trip fidelity: reading
and re-writing an image preserves extensions that qcow2-lib does not
understand.

Source: `header_extension.rs:210–213`.

## Feature name table

The feature name table extension (`0x6803f857`) contains a sequence of
fixed-size entries, each 48 bytes:

```
 ┌────────────────────────────────────┐
 │  feature_type     (1 byte, u8)    │  0=incompatible, 1=compatible, 2=autoclear
 │  bit_number       (1 byte, u8)    │  bit position within the flag field
 │  name             (46 bytes)      │  UTF-8, zero-padded
 └────────────────────────────────────┘
```

This maps feature flag bits to human-readable names so that tools can display
meaningful messages for unknown features (e.g. "incompatible feature bit 4:
extended_l2" instead of just "unknown bit 4").

Source: `header_extension.rs:58–70` — `FeatureNameEntry` struct and
`FEATURE_NAME_ENTRY_SIZE = 48`.

## Full disk encryption extension

The full disk encryption extension (`0x0537be77`) contains exactly 16 bytes:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `offset` | Byte offset of the encryption header (LUKS) in the image file. |
| 8 | 8 | `length` | Length of the encryption header in bytes. |

If the data is shorter than 16 bytes, the extension is treated as unknown.

Source: `header_extension.rs:194–204`.

## Serialization

`HeaderExtension::write_all()` serializes a list of extensions followed by
the end-of-extensions marker (8 zero bytes). Each extension's data is padded
to an 8-byte boundary with zero bytes.

Source: `header_extension.rs:129–148`.
