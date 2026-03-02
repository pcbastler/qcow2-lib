//! Type-safe newtypes for QCOW2 offsets and indices.
//!
//! These newtypes prevent accidental mixing of host offsets, guest offsets,
//! and table indices at compile time. All offset types display in hexadecimal.

use std::fmt;

/// A byte offset within the host (image) file.
///
/// This is where data physically lives on disk. Must not be confused with
/// [`GuestOffset`] which is the virtual disk address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClusterOffset(pub u64);

/// A byte offset within the guest virtual disk.
///
/// This is the address that a virtual machine sees. The QCOW2 two-level
/// mapping translates this to a [`ClusterOffset`] in the host file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GuestOffset(pub u64);

/// A cluster number: `byte_offset / cluster_size`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClusterIndex(pub u64);

/// Index into the L1 table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct L1Index(pub u32);

/// Index into an L2 table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct L2Index(pub u32);

/// Byte offset within a single cluster (0..cluster_size).
///
/// Stored as `u32` because the maximum cluster size is 2 MB (fits in 21 bits).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct IntraClusterOffset(pub u32);

// ---- Debug and Display implementations (hex for offsets) ----

impl fmt::Debug for ClusterOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClusterOffset(0x{:x})", self.0)
    }
}

impl fmt::Display for ClusterOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::Debug for GuestOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuestOffset(0x{:x})", self.0)
    }
}

impl fmt::Display for GuestOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::Debug for ClusterIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClusterIndex({})", self.0)
    }
}

impl fmt::Display for ClusterIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for L1Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L1Index({})", self.0)
    }
}

impl fmt::Display for L1Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for L2Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L2Index({})", self.0)
    }
}

impl fmt::Display for L2Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for IntraClusterOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntraClusterOffset(0x{:x})", self.0)
    }
}

impl fmt::Display for IntraClusterOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

// ---- From/Into conversions ----

impl From<u64> for ClusterOffset {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<ClusterOffset> for u64 {
    fn from(v: ClusterOffset) -> Self {
        v.0
    }
}

impl From<u64> for GuestOffset {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<GuestOffset> for u64 {
    fn from(v: GuestOffset) -> Self {
        v.0
    }
}

impl From<u64> for ClusterIndex {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<ClusterIndex> for u64 {
    fn from(v: ClusterIndex) -> Self {
        v.0
    }
}

// ---- Address decomposition ----

impl GuestOffset {
    /// Decompose a guest offset into L1 index, L2 index, and intra-cluster offset.
    ///
    /// This is the single authoritative implementation of the QCOW2 two-level
    /// address mapping formula:
    ///
    /// ```text
    /// guest_offset = l1_index * l2_entries * cluster_size
    ///              + l2_index * cluster_size
    ///              + intra_cluster_offset
    /// ```
    ///
    /// Where `l2_entries = cluster_size / 8` (each L2 entry is 8 bytes).
    pub fn split(self, cluster_bits: u32) -> (L1Index, L2Index, IntraClusterOffset) {
        let cluster_size = 1u64 << cluster_bits;
        let l2_bits = cluster_bits - 3; // log2(cluster_size / 8)

        let intra = (self.0 & (cluster_size - 1)) as u32;
        let cluster_number = self.0 >> cluster_bits;
        let l2_index = (cluster_number & ((1u64 << l2_bits) - 1)) as u32;
        let l1_index = (cluster_number >> l2_bits) as u32;

        (L1Index(l1_index), L2Index(l2_index), IntraClusterOffset(intra))
    }
}

impl ClusterOffset {
    /// Convert a host offset to a cluster index given the cluster size.
    pub fn to_cluster_index(self, cluster_bits: u32) -> ClusterIndex {
        ClusterIndex(self.0 >> cluster_bits)
    }

    /// Check whether this offset is aligned to a cluster boundary.
    pub fn is_cluster_aligned(self, cluster_bits: u32) -> bool {
        self.0 & ((1u64 << cluster_bits) - 1) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GuestOffset::split tests ----

    #[test]
    fn split_offset_zero() {
        let (l1, l2, intra) = GuestOffset(0).split(16);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(0));
        assert_eq!(intra, IntraClusterOffset(0));
    }

    #[test]
    fn split_first_byte_of_second_cluster() {
        // cluster_bits=16 => cluster_size=65536
        // Offset 65536 = cluster 1 => L1=0, L2=1, intra=0
        let (l1, l2, intra) = GuestOffset(65536).split(16);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(1));
        assert_eq!(intra, IntraClusterOffset(0));
    }

    #[test]
    fn split_with_intra_cluster_offset() {
        // cluster_bits=16, offset = 65536 + 512 = cluster 1, byte 512
        let (l1, l2, intra) = GuestOffset(65536 + 512).split(16);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(1));
        assert_eq!(intra, IntraClusterOffset(512));
    }

    #[test]
    fn split_crosses_l1_boundary() {
        // cluster_bits=16 => cluster_size=65536, l2_entries=8192
        // L1 boundary at l2_entries * cluster_size = 8192 * 65536 = 0x2000_0000
        let boundary = 8192u64 * 65536;
        let (l1, l2, intra) = GuestOffset(boundary).split(16);
        assert_eq!(l1, L1Index(1));
        assert_eq!(l2, L2Index(0));
        assert_eq!(intra, IntraClusterOffset(0));
    }

    #[test]
    fn split_last_byte_before_l1_boundary() {
        let boundary = 8192u64 * 65536;
        let (l1, l2, intra) = GuestOffset(boundary - 1).split(16);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(8191));
        assert_eq!(intra, IntraClusterOffset(65535));
    }

    #[test]
    fn split_with_different_cluster_bits() {
        // cluster_bits=12 => cluster_size=4096, l2_entries=512
        let (l1, l2, intra) = GuestOffset(4096).split(12);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(1));
        assert_eq!(intra, IntraClusterOffset(0));

        // L1 boundary at 512 * 4096 = 2097152
        let (l1, l2, _) = GuestOffset(2097152).split(12);
        assert_eq!(l1, L1Index(1));
        assert_eq!(l2, L2Index(0));
    }

    // ---- ClusterOffset tests ----

    #[test]
    fn cluster_alignment_check() {
        assert!(ClusterOffset(0).is_cluster_aligned(16));
        assert!(ClusterOffset(65536).is_cluster_aligned(16));
        assert!(!ClusterOffset(1).is_cluster_aligned(16));
        assert!(!ClusterOffset(65535).is_cluster_aligned(16));
    }

    #[test]
    fn to_cluster_index() {
        assert_eq!(
            ClusterOffset(65536).to_cluster_index(16),
            ClusterIndex(1)
        );
        assert_eq!(
            ClusterOffset(0).to_cluster_index(16),
            ClusterIndex(0)
        );
    }

    // ---- Display/Debug tests ----

    #[test]
    fn cluster_offset_debug_is_hex() {
        let s = format!("{:?}", ClusterOffset(0x1_0000));
        assert_eq!(s, "ClusterOffset(0x10000)");
    }

    #[test]
    fn guest_offset_display_is_hex() {
        let s = format!("{}", GuestOffset(0xdead_beef));
        assert_eq!(s, "0xdeadbeef");
    }

    #[test]
    fn l1_index_display_is_decimal() {
        assert_eq!(format!("{}", L1Index(42)), "42");
    }

    // ---- Edge cases: split at MIN/MAX cluster_bits ----

    #[test]
    fn split_with_min_cluster_bits() {
        // cluster_bits=9 => cluster_size=512, l2_bits=6, l2_entries=64
        let cluster_size = 1u64 << 9; // 512
        let l2_entries = 64u64;

        // Second cluster
        let (l1, l2, intra) = GuestOffset(cluster_size).split(9);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(1));
        assert_eq!(intra, IntraClusterOffset(0));

        // L1 boundary at l2_entries * cluster_size = 64 * 512 = 32768
        let boundary = l2_entries * cluster_size;
        let (l1, l2, intra) = GuestOffset(boundary).split(9);
        assert_eq!(l1, L1Index(1));
        assert_eq!(l2, L2Index(0));
        assert_eq!(intra, IntraClusterOffset(0));

        // Last byte before L1 boundary
        let (l1, l2, intra) = GuestOffset(boundary - 1).split(9);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(63));
        assert_eq!(intra, IntraClusterOffset(511));
    }

    #[test]
    fn split_with_max_cluster_bits() {
        // cluster_bits=21 => cluster_size=2MB, l2_bits=18, l2_entries=262144
        let cluster_size = 1u64 << 21; // 2097152
        let l2_entries = 1u64 << 18; // 262144

        // Second cluster
        let (l1, l2, intra) = GuestOffset(cluster_size).split(21);
        assert_eq!(l1, L1Index(0));
        assert_eq!(l2, L2Index(1));
        assert_eq!(intra, IntraClusterOffset(0));

        // L1 boundary
        let boundary = l2_entries * cluster_size;
        let (l1, l2, _) = GuestOffset(boundary).split(21);
        assert_eq!(l1, L1Index(1));
        assert_eq!(l2, L2Index(0));
    }

    #[test]
    fn split_u64_max_offset() {
        // Should not panic — the offset is absurd but split() does pure arithmetic
        let (l1, l2, intra) = GuestOffset(u64::MAX).split(16);
        // u64::MAX = 0xFFFF_FFFF_FFFF_FFFF
        // intra = 0xFFFF (65535), cluster_number = 0xFFFF_FFFF_FFFF
        // l2_index = cluster_number & 0x1FFF = 0x1FFF (8191)
        // l1_index = cluster_number >> 13
        assert_eq!(intra, IntraClusterOffset(65535));
        assert_eq!(l2, L2Index(8191));
        assert!(l1.0 > 0); // Very large L1 index
    }

    #[test]
    fn intra_cluster_offset_at_maximum() {
        // Last byte of a 64KB cluster
        let offset = (1u64 << 16) - 1; // 65535
        let (_, _, intra) = GuestOffset(offset).split(16);
        assert_eq!(intra, IntraClusterOffset(65535));

        // Last byte of a 2MB cluster
        let offset = (1u64 << 21) - 1;
        let (_, _, intra) = GuestOffset(offset).split(21);
        assert_eq!(intra, IntraClusterOffset((1u32 << 21) - 1));
    }

    #[test]
    fn cluster_alignment_various_bits() {
        // cluster_bits=9 (512 bytes)
        assert!(ClusterOffset(0).is_cluster_aligned(9));
        assert!(ClusterOffset(512).is_cluster_aligned(9));
        assert!(!ClusterOffset(511).is_cluster_aligned(9));

        // cluster_bits=21 (2 MB)
        assert!(ClusterOffset(0).is_cluster_aligned(21));
        assert!(ClusterOffset(1 << 21).is_cluster_aligned(21));
        assert!(!ClusterOffset((1 << 21) - 1).is_cluster_aligned(21));
    }
}
