//! Feature flag bitfields for QCOW2 v3 headers.
//!
//! QCOW2 v3 defines three categories of feature flags:
//! - **Incompatible**: Unknown bits mean the image MUST NOT be opened.
//! - **Compatible**: Unknown bits can be safely ignored.
//! - **Autoclear**: Unknown bits are cleared on the first write.

use bitflags::bitflags;

bitflags! {
    /// Incompatible feature flags (header bytes 72-79).
    ///
    /// If any unknown bits are set, the image must not be opened because
    /// the implementation may not handle the format correctly.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IncompatibleFeatures: u64 {
        /// The image was not closed cleanly; refcounts may be inconsistent.
        const DIRTY = 1 << 0;
        /// Data structures may be corrupt; the image should only be opened read-only.
        const CORRUPT = 1 << 1;
        /// Guest data is stored in an external data file (not supported by this crate).
        const EXTERNAL_DATA_FILE = 1 << 2;
        /// The compression type is not deflate; check header byte 104.
        const COMPRESSION_TYPE = 1 << 3;
        /// Extended L2 entries with 32-subcluster allocation bitmaps.
        const EXTENDED_L2 = 1 << 4;
    }

    /// Compatible feature flags (header bytes 80-87).
    ///
    /// Unknown bits can be safely ignored. The image can still be opened
    /// even if unrecognized compatible features are present.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompatibleFeatures: u64 {
        /// Lazy refcounts: refcounts may be stale and need a consistency check.
        const LAZY_REFCOUNTS = 1 << 0;
    }

    /// Autoclear feature flags (header bytes 88-95).
    ///
    /// Unknown bits are automatically cleared on the first modification
    /// to the image, signaling that the associated metadata may be stale.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AutoclearFeatures: u64 {
        /// Bitmaps extension data is consistent with the image content.
        const BITMAPS = 1 << 0;
        /// The external data file contains raw data (not QCOW2 formatted).
        const RAW_EXTERNAL = 1 << 1;
        /// BLAKE3 per-cluster hash data is consistent with the image content.
        const BLAKE3_HASHES = 1 << 2;
    }
}

/// The set of incompatible features that this implementation can handle.
///
/// Opening an image with unknown incompatible bits set outside this mask
/// must be rejected.
pub const SUPPORTED_INCOMPATIBLE_FEATURES: IncompatibleFeatures = IncompatibleFeatures::DIRTY
    .union(IncompatibleFeatures::CORRUPT)
    .union(IncompatibleFeatures::COMPRESSION_TYPE)
    .union(IncompatibleFeatures::EXTENDED_L2);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompatible_bit_positions() {
        assert_eq!(IncompatibleFeatures::DIRTY.bits(), 1);
        assert_eq!(IncompatibleFeatures::CORRUPT.bits(), 2);
        assert_eq!(IncompatibleFeatures::EXTERNAL_DATA_FILE.bits(), 4);
        assert_eq!(IncompatibleFeatures::COMPRESSION_TYPE.bits(), 8);
        assert_eq!(IncompatibleFeatures::EXTENDED_L2.bits(), 16);
    }

    #[test]
    fn compatible_bit_positions() {
        assert_eq!(CompatibleFeatures::LAZY_REFCOUNTS.bits(), 1);
    }

    #[test]
    fn autoclear_bit_positions() {
        assert_eq!(AutoclearFeatures::BITMAPS.bits(), 1);
        assert_eq!(AutoclearFeatures::RAW_EXTERNAL.bits(), 2);
    }

    #[test]
    fn round_trip_incompatible() {
        let flags = IncompatibleFeatures::DIRTY | IncompatibleFeatures::COMPRESSION_TYPE;
        let bits = flags.bits();
        let restored = IncompatibleFeatures::from_bits_truncate(bits);
        assert_eq!(flags, restored);
    }

    #[test]
    fn unknown_bits_removed_by_truncate() {
        // Bit 5 is unknown — from_bits_truncate should drop it
        let with_unknown = IncompatibleFeatures::from_bits_truncate(0b100001);
        assert!(with_unknown.contains(IncompatibleFeatures::DIRTY));
        // The unknown bit 5 should be dropped
        assert_eq!(with_unknown.bits() & (1 << 5), 0);
    }

    #[test]
    fn supported_features_mask() {
        assert!(SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::DIRTY));
        assert!(SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::CORRUPT));
        assert!(SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::COMPRESSION_TYPE));
        assert!(!SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::EXTERNAL_DATA_FILE));
        assert!(SUPPORTED_INCOMPATIBLE_FEATURES.contains(IncompatibleFeatures::EXTENDED_L2));
    }
}
