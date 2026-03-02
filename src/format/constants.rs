//! QCOW2 format constants: magic numbers, bitmasks, limits, and extension type IDs.
//!
//! All constants are derived directly from the QCOW2 specification.
//! No magic numbers should appear anywhere else in the crate.

// ---- Magic and versions ----

/// QCOW2 magic number: ASCII "QFI\xfb" at file offset 0.
pub const QCOW2_MAGIC: u32 = 0x514649fb;

/// QCOW2 version 2 (original format).
pub const VERSION_2: u32 = 2;

/// QCOW2 version 3 (extended with feature flags and variable refcounts).
pub const VERSION_3: u32 = 3;

// ---- Header sizes ----

/// Size of the v2 header in bytes (fixed).
pub const HEADER_V2_LENGTH: usize = 72;

/// Minimum size of the v3 header in bytes (may be extended via `header_length`).
pub const HEADER_V3_MIN_LENGTH: usize = 104;

// ---- Cluster size constraints ----

/// Minimum cluster_bits value (2^9 = 512 bytes).
pub const MIN_CLUSTER_BITS: u32 = 9;

/// Maximum cluster_bits value (2^21 = 2 MB, QEMU enforced limit).
pub const MAX_CLUSTER_BITS: u32 = 21;

/// Default cluster_bits for newly created images (2^16 = 64 KB).
pub const DEFAULT_CLUSTER_BITS: u32 = 16;

// ---- Refcount constraints ----

/// Maximum refcount order (2^6 = 64-bit refcounts).
pub const MAX_REFCOUNT_ORDER: u32 = 6;

/// Default refcount order for v2 images (2^4 = 16-bit refcounts, fixed by spec).
pub const DEFAULT_REFCOUNT_ORDER_V2: u32 = 4;

// ---- Encryption methods ----

/// No encryption.
pub const CRYPT_NONE: u32 = 0;

/// AES-CBC encryption (legacy, method 1).
pub const CRYPT_AES_CBC: u32 = 1;

/// LUKS encryption (method 2).
pub const CRYPT_LUKS: u32 = 2;

// ---- Compression types (v3 header byte 104) ----

/// Deflate (zlib raw) compression.
pub const COMPRESSION_DEFLATE: u8 = 0;

/// Zstandard compression.
pub const COMPRESSION_ZSTD: u8 = 1;

// ---- L1 entry bitmasks ----

/// Bits 9..=55 of an L1 entry: L2 table offset (cluster-aligned).
pub const L1_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

/// Bit 63 of an L1 entry: set if the refcount is exactly one (COPIED flag).
pub const L1_COPIED_FLAG: u64 = 1 << 63;

// ---- L2 entry bitmasks (standard, non-extended) ----

/// Bit 62 of an L2 entry: compressed cluster flag.
pub const L2_COMPRESSED_FLAG: u64 = 1 << 62;

/// Bit 63 of an L2 entry: set if the refcount is exactly one (COPIED flag).
pub const L2_COPIED_FLAG: u64 = 1 << 63;

/// Bit 0 of a standard L2 entry: reads-as-zero flag (v3 only).
pub const L2_ZERO_FLAG: u64 = 1;

/// Bits 9..=55 of a standard L2 entry: host cluster offset.
pub const L2_STANDARD_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

// ---- Refcount table entry bitmasks ----

/// Bits 9..=63 of a refcount table entry: refcount block offset (cluster-aligned).
pub const REFCOUNT_TABLE_OFFSET_MASK: u64 = 0xffff_ffff_ffff_fe00;

// ---- Header extension type IDs ----

/// Marks the end of header extensions.
pub const EXT_END_OF_EXTENSIONS: u32 = 0x0000_0000;

/// Backing file format name (e.g., "qcow2", "raw").
pub const EXT_BACKING_FILE_FORMAT: u32 = 0xe279_2aca;

/// Feature name table (maps feature bits to human-readable names).
pub const EXT_FEATURE_NAME_TABLE: u32 = 0x6803_f857;

/// Bitmaps extension.
pub const EXT_BITMAPS: u32 = 0x2385_2875;

/// Full disk encryption header pointer.
pub const EXT_FULL_DISK_ENCRYPTION: u32 = 0x0537_be77;

/// External data file name.
pub const EXT_EXTERNAL_DATA_FILE: u32 = 0x4441_5441;

// ---- Safety limits ----

/// Maximum backing file name length in bytes.
pub const MAX_BACKING_FILE_NAME: u32 = 1023;

/// Maximum backing chain depth (prevents infinite loops).
pub const MAX_BACKING_CHAIN_DEPTH: u32 = 64;

/// Sector size used for compressed cluster size encoding.
pub const COMPRESSED_SECTOR_SIZE: u64 = 512;

/// Size of each L2 entry in bytes (standard, non-extended).
pub const L2_ENTRY_SIZE: usize = 8;

/// Size of each L1 entry in bytes.
pub const L1_ENTRY_SIZE: usize = 8;

/// Size of each refcount table entry in bytes.
pub const REFCOUNT_TABLE_ENTRY_SIZE: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_offset_mask_covers_bits_9_through_55() {
        // Bit 9 should be set
        assert_ne!(L1_OFFSET_MASK & (1u64 << 9), 0);
        // Bit 55 should be set
        assert_ne!(L1_OFFSET_MASK & (1u64 << 55), 0);
        // Bit 8 should NOT be set
        assert_eq!(L1_OFFSET_MASK & (1u64 << 8), 0);
        // Bit 56 should NOT be set
        assert_eq!(L1_OFFSET_MASK & (1u64 << 56), 0);
        // Bit 63 (COPIED flag) should NOT be in the offset mask
        assert_eq!(L1_OFFSET_MASK & (1u64 << 63), 0);
    }

    #[test]
    fn l2_standard_offset_mask_matches_l1() {
        // L2 standard offset uses the same bit range as L1
        assert_eq!(L2_STANDARD_OFFSET_MASK, L1_OFFSET_MASK);
    }

    #[test]
    fn l2_flags_are_distinct() {
        assert_eq!(L2_COMPRESSED_FLAG & L2_COPIED_FLAG, 0);
        assert_eq!(L2_COMPRESSED_FLAG & L2_ZERO_FLAG, 0);
        assert_eq!(L2_COPIED_FLAG & L2_ZERO_FLAG, 0);
    }

    #[test]
    fn refcount_table_offset_mask_covers_bits_9_through_63() {
        assert_ne!(REFCOUNT_TABLE_OFFSET_MASK & (1u64 << 9), 0);
        assert_ne!(REFCOUNT_TABLE_OFFSET_MASK & (1u64 << 63), 0);
        assert_eq!(REFCOUNT_TABLE_OFFSET_MASK & (1u64 << 8), 0);
    }

    #[test]
    fn cluster_bits_range_is_valid() {
        assert!(MIN_CLUSTER_BITS < MAX_CLUSTER_BITS);
        assert!(DEFAULT_CLUSTER_BITS >= MIN_CLUSTER_BITS);
        assert!(DEFAULT_CLUSTER_BITS <= MAX_CLUSTER_BITS);
    }

    #[test]
    fn default_cluster_size_is_64kb() {
        assert_eq!(1u64 << DEFAULT_CLUSTER_BITS, 65536);
    }

    #[test]
    fn max_refcount_order_gives_64_bit() {
        assert_eq!(1u32 << MAX_REFCOUNT_ORDER, 64);
    }
}
