//! Compressed cluster descriptor encoding and decoding.
//!
//! When an L2 entry has the compressed flag (bit 62) set, the remaining
//! bits encode a host offset and a sector count using a
//! `cluster_bits`-dependent bit layout.
//!
//! The sector count spans from the sector boundary at or before the host
//! offset to the end of the compressed data. Since compressed clusters
//! may start at non-sector-aligned positions (due to byte-granularity
//! packing), the actual data length is the total sector span minus the
//! intra-sector offset of the host position.

use crate::constants::COMPRESSED_SECTOR_SIZE;

/// Decoded information from a compressed L2 entry.
///
/// Compressed clusters may be stored at non-sector-aligned host offsets.
/// The `compressed_size` field is the actual byte count of compressed data
/// starting at `host_offset`, with the intra-sector offset already
/// accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedClusterDescriptor {
    /// Host file offset of the compressed data (not necessarily sector-aligned).
    pub host_offset: u64,
    /// Byte count of compressed data starting at `host_offset`.
    pub compressed_size: u64,
}

impl CompressedClusterDescriptor {
    /// Decode a compressed cluster descriptor from a raw L2 entry value.
    ///
    /// The on-disk sector count covers whole sectors from the containing
    /// sector boundary through the last sector of compressed data. The
    /// actual data starts at `host_offset` which may be mid-sector, so
    /// the usable byte count is shorter by `host_offset % 512`.
    pub fn decode(raw_entry: u64, cluster_bits: u32) -> Self {
        let sector_bits = cluster_bits - 8;
        let x = 62 - sector_bits;
        let offset_mask = (1u64 << x) - 1;
        let host_offset = raw_entry & offset_mask;
        let nb_csectors = ((raw_entry >> x) & ((1u64 << sector_bits) - 1)) + 1;
        let compressed_size =
            nb_csectors * COMPRESSED_SECTOR_SIZE - (host_offset % COMPRESSED_SECTOR_SIZE);
        Self {
            host_offset,
            compressed_size,
        }
    }

    /// Encode back into a raw L2 entry value.
    ///
    /// Reconstructs the sector count by adding back the intra-sector
    /// offset and rounding up to whole sectors.
    ///
    /// The compressed flag (bit 62) is NOT set by this method; the caller
    /// must OR it in when building the full L2 entry.
    pub fn encode(self, cluster_bits: u32) -> u64 {
        let sector_bits = cluster_bits - 8;
        let x = 62 - sector_bits;
        let intra = self.host_offset % COMPRESSED_SECTOR_SIZE;
        let nb_csectors =
            (self.compressed_size + intra + COMPRESSED_SECTOR_SIZE - 1) / COMPRESSED_SECTOR_SIZE;
        let stored = nb_csectors - 1;
        let offset_part = self.host_offset & ((1u64 << x) - 1);
        let sector_part = (stored & ((1u64 << sector_bits) - 1)) << x;
        offset_part | sector_part
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cluster_bits_16() {
        // cluster_bits=16: sector_bits=8, x=54
        // offset=0x1234 → intra-sector = 0x34 = 52 bytes
        // stored nb_csectors-1 = 2 → nb_csectors = 3
        // compressed_size = 3*512 - 52 = 1484
        let cluster_bits = 16u32;
        let sector_bits = cluster_bits - 8; // 8
        let x = 62 - sector_bits; // 54
        let offset = 0x1234u64;
        let stored_sectors = 2u64;
        let raw = offset | (stored_sectors << x);

        let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
        assert_eq!(desc.host_offset, 0x1234);
        let nb_csectors = stored_sectors + 1;
        let expected = nb_csectors * 512 - (offset % 512);
        assert_eq!(desc.compressed_size, expected); // 3*512 - 52 = 1484
    }

    #[test]
    fn round_trip_cluster_bits_16() {
        let original = CompressedClusterDescriptor {
            host_offset: 0xABCD_0000,
            compressed_size: 4 * 512, // 4 sectors
        };
        let encoded = original.encode(16);
        let decoded = CompressedClusterDescriptor::decode(encoded, 16);
        assert_eq!(original, decoded);
    }

    #[test]
    fn round_trip_cluster_bits_12() {
        // 0x5678 → intra = 0x78 = 120, so compressed_size must account for that
        let original = CompressedClusterDescriptor {
            host_offset: 0x5678,
            compressed_size: 2 * 512 - 120, // 904 bytes of actual data
        };
        let encoded = original.encode(12);
        let decoded = CompressedClusterDescriptor::decode(encoded, 12);
        assert_eq!(original, decoded);
    }

    #[test]
    fn round_trip_cluster_bits_21() {
        let original = CompressedClusterDescriptor {
            host_offset: 0x1_0000,
            compressed_size: 8 * 512, // 8 sectors
        };
        let encoded = original.encode(21);
        let decoded = CompressedClusterDescriptor::decode(encoded, 21);
        assert_eq!(original, decoded);
    }

    #[test]
    fn minimum_compressed_size_is_one_sector() {
        // nb_sectors = 0 in the encoding means 1 sector (512 bytes)
        let cluster_bits = 16u32;
        let raw = 0x5000u64; // offset only, nb_sectors bits = 0
        let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
        assert_eq!(desc.compressed_size, 512);
    }

    // ---- Edge cases ----

    #[test]
    fn round_trip_cluster_bits_9_min() {
        // cluster_bits=9: sector_bits=1, x=61
        // Only 1 sector bit — nb_csectors can be 1 or 2.
        // 0x1234 → intra = 0x34 = 52
        let original = CompressedClusterDescriptor {
            host_offset: 0x1234,
            compressed_size: 2 * 512 - 52, // 972 bytes
        };
        let encoded = original.encode(9);
        let decoded = CompressedClusterDescriptor::decode(encoded, 9);
        assert_eq!(original, decoded);
    }

    #[test]
    fn round_trip_cluster_bits_21_near_max_offset() {
        // cluster_bits=21: sector_bits=13, x=49
        // Offset field is 49 bits wide → max offset is (1<<49)-1.
        // (1<<49)-1 = ...1FF → intra = 0x1FF = 511
        let max_offset = (1u64 << 49) - 1;
        let intra = max_offset % 512; // 511
        let original = CompressedClusterDescriptor {
            host_offset: max_offset,
            compressed_size: 16 * 512 - intra,
        };
        let encoded = original.encode(21);
        let decoded = CompressedClusterDescriptor::decode(encoded, 21);
        assert_eq!(original, decoded);
    }

    #[test]
    fn large_compressed_size_cluster_bits_21() {
        // cluster_bits=21: sector_bits=13, max nb_sectors = (1<<13)-1 = 8191
        // Max compressed_size = (8191 + 1) * 512 = 4194304 = 4 MB (= 2 clusters)
        let max_sectors = (1u64 << 13) - 1;
        let original = CompressedClusterDescriptor {
            host_offset: 0x1000,
            compressed_size: (max_sectors + 1) * 512,
        };
        let encoded = original.encode(21);
        let decoded = CompressedClusterDescriptor::decode(encoded, 21);
        assert_eq!(original, decoded);
    }

    #[test]
    fn offset_at_zero() {
        // Offset 0 is a valid host offset (beginning of file).
        let original = CompressedClusterDescriptor {
            host_offset: 0,
            compressed_size: 512, // minimum: 1 sector
        };
        let encoded = original.encode(16);
        let decoded = CompressedClusterDescriptor::decode(encoded, 16);
        assert_eq!(original, decoded);
    }

    // ---- QEMU-compatible compressed_size (intra-sector offset subtraction) ----

    #[test]
    fn decode_non_aligned_offset_subtracts_intra_sector() {
        // QEMU formula: csize = nb_csectors * 512 - (coffset & 511)
        // When host_offset is not 512-aligned, the actual compressed data
        // size is smaller because the first sector is only partially used.
        //
        // Example: host_offset=0x1234 (intra-sector offset = 0x34 = 52)
        //          nb_csectors=3
        // QEMU:    csize = 3*512 - 52 = 1484
        // Current: csize = 3*512      = 1536  ← BUG: 52 bytes too much
        let cluster_bits = 16u32;
        let sector_bits = cluster_bits - 8; // 8
        let x = 62 - sector_bits; // 54
        let offset = 0x1234u64; // intra-sector = 0x34 = 52
        let nb_sectors = 2u64; // stored value → actual nb_csectors = 3
        let raw = offset | (nb_sectors << x);

        let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
        assert_eq!(desc.host_offset, 0x1234);
        // QEMU-compatible size: (nb_sectors+1)*512 - (offset & 511)
        let expected = (nb_sectors + 1) * 512 - (offset & 511);
        assert_eq!(
            desc.compressed_size, expected,
            "compressed_size should subtract intra-sector offset (QEMU compat): \
             got {}, expected {} (diff={})",
            desc.compressed_size, expected, desc.compressed_size as i64 - expected as i64,
        );
    }

    #[test]
    fn decode_aligned_offset_unchanged() {
        // When host_offset IS 512-aligned, (offset & 511) == 0,
        // so the subtraction changes nothing.
        let cluster_bits = 16u32;
        let sector_bits = cluster_bits - 8;
        let x = 62 - sector_bits;
        let offset = 0x1000u64; // sector-aligned
        let nb_sectors = 2u64;
        let raw = offset | (nb_sectors << x);

        let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
        assert_eq!(desc.host_offset, 0x1000);
        assert_eq!(desc.compressed_size, (nb_sectors + 1) * 512);
    }

    #[test]
    fn decode_non_aligned_various_offsets() {
        // Verify the intra-sector subtraction for a range of non-aligned offsets
        let cluster_bits = 16u32;
        let sector_bits = cluster_bits - 8;
        let x = 62 - sector_bits;

        for intra in [1u64, 100, 255, 511] {
            let offset = 0x1000 + intra;
            let nb_sectors = 4u64; // stored → actual = 5
            let raw = offset | (nb_sectors << x);

            let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
            let expected = (nb_sectors + 1) * 512 - intra;
            assert_eq!(
                desc.compressed_size, expected,
                "intra={intra}: got {}, expected {expected}",
                desc.compressed_size,
            );
        }
    }

    #[test]
    fn single_sector_round_trip_all_cluster_bits() {
        // The minimum compressed size (1 sector) should round-trip for every
        // valid cluster_bits value.
        for cluster_bits in 9..=21 {
            let original = CompressedClusterDescriptor {
                host_offset: 0x400,
                compressed_size: 512,
            };
            let encoded = original.encode(cluster_bits);
            let decoded = CompressedClusterDescriptor::decode(encoded, cluster_bits);
            assert_eq!(original, decoded, "failed at cluster_bits={cluster_bits}");
        }
    }
}
