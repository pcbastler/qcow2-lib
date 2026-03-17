# 3. Feature Flags

QCOW2 version 3 adds three 64-bit fields to the header that signal which
optional features an image uses. These flags allow implementations to detect
features they don't support before they corrupt the image by misinterpreting
its data.

Version 2 has no feature flags — all v2 images use the same fixed feature set.

## 3.1 The three categories

Each category has different rules for how an implementation must handle unknown
(unrecognized) bits:

### 3.1.1 Incompatible features (header bytes 72–79)

An implementation **must refuse to open** an image if any unknown incompatible
bit is set [1]. These features change the on-disk layout in ways that an
unaware reader would misinterpret.

Unknown bits are validated in `validate_structural()` against
`SUPPORTED_INCOMPATIBLE_FEATURES` [1][2].

### 3.1.2 Compatible features (header bytes 80–87)

An implementation **may safely ignore** unknown compatible bits [1]. These
features add optional metadata that does not affect the core data layout.

### 3.1.3 Autoclear features (header bytes 88–95)

Unknown autoclear bits are **automatically cleared on first write** by any
implementation that does not understand them [1]. This signals that the
associated metadata may now be stale.

This mechanism is designed for consistency flags: the bit is set when the
metadata is known to be consistent, and cleared when it might not be.

## 3.2 Defined bits

### 3.2.1 Incompatible feature bits

| Bit | Name | Constant | Description |
|-----|------|----------|-------------|
| 0 | `DIRTY` | `IncompatibleFeatures::DIRTY` | The image was not closed cleanly. Refcounts may be inconsistent and should be checked before use. |
| 1 | `CORRUPT` | `IncompatibleFeatures::CORRUPT` | Data structures may be corrupt. The image should only be opened read-only. |
| 2 | `EXTERNAL_DATA_FILE` | `IncompatibleFeatures::EXTERNAL_DATA_FILE` | Guest data is stored in an external file, not in the QCOW2 file itself. See [External Data File](14-external-data-file.md). |
| 3 | `COMPRESSION_TYPE` | `IncompatibleFeatures::COMPRESSION_TYPE` | The `compression_type` byte at header offset 104 is valid. If this bit is not set, deflate (type 0) is assumed regardless of that byte's value. |
| 4 | `EXTENDED_L2` | `IncompatibleFeatures::EXTENDED_L2` | L2 entries are 128 bits wide (instead of 64 bits) and carry per-subcluster allocation bitmaps. See [Extended L2](06-extended-l2.md). |

All five bits are defined in [1] (lines 16–27).

The set of incompatible features that qcow2-lib can handle is defined by
`SUPPORTED_INCOMPATIBLE_FEATURES` [1] (lines 58–62), which is the union of
all five bits above.

### 3.2.2 Compatible feature bits

| Bit | Name | Constant | Description |
|-----|------|----------|-------------|
| 0 | `LAZY_REFCOUNTS` | `CompatibleFeatures::LAZY_REFCOUNTS` | Refcounts may be stale and need a consistency check. Unlike `DIRTY`, this is a deliberate optimization, not an error condition. |

Defined in [1] (lines 34–37).

### 3.2.3 Autoclear feature bits

| Bit | Name | Constant | Description |
|-----|------|----------|-------------|
| 0 | `BITMAPS` | `AutoclearFeatures::BITMAPS` | The bitmaps extension data is consistent with the image content. Cleared by implementations that do not maintain bitmaps. |
| 1 | `RAW_EXTERNAL` | `AutoclearFeatures::RAW_EXTERNAL` | The external data file contains raw data (not QCOW2-formatted). |
| 2 | `BLAKE3_HASHES` | `AutoclearFeatures::BLAKE3_HASHES` | The BLAKE3 per-chunk hash data is consistent with the image content. This is a qcow2-lib extension — not defined by the upstream QCOW2 specification. |

Defined in [1] (lines 44–51).

## 3.3 On-disk encoding

All three fields are stored as 64-bit big-endian integers [2]. Bit 0 is the
least-significant bit (value `1`), bit 1 has value `2`, bit 2 has value `4`,
and so on.

```
 Bit  63                                                    0
 ┌────┬────┬────┬────┬─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┬────┬────┬────┐
 │ 63 │ 62 │ 61 │ 60 │        ...           │  2 │  1 │  0 │
 └────┴────┴────┴────┴─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┴────┴────┴────┘
```

For the incompatible features field, the five defined bits occupy positions
0–4. All remaining bits (5–63) are reserved. If any reserved bit is set, a
reader must refuse to open the image [2].

## 3.4 Interaction with version 2

Version 2 headers do not contain feature flag fields. When parsing a v2 image,
all three flag fields are treated as zero (no features set) [2]. The v2 default
for `refcount_order` is 4 (16-bit refcounts) [3].

## Source References

| Ref | File | What it contains |
|-----|------|-----------------|
| [1] | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L16-L27) | `IncompatibleFeatures` (bits 0–4) |
| | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L34-L37) | `CompatibleFeatures` (bit 0) |
| | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L44-L51) | `AutoclearFeatures` (bits 0–2) |
| | [feature_flags.rs](../../crates/qcow2-format/src/feature_flags.rs#L58-L62) | `SUPPORTED_INCOMPATIBLE_FEATURES` |
| [2] | [header.rs](../../crates/qcow2-format/src/header.rs#L370-L377) | `validate_structural()` — rejects unknown incompatible bits |
| | [header.rs](../../crates/qcow2-format/src/header.rs#L183-L216) | `read_version_fields()` — v2 defaults (empty flags) |
| [3] | [constants.rs](../../crates/qcow2-format/src/constants.rs#L42) | `DEFAULT_REFCOUNT_ORDER_V2 = 4` |
