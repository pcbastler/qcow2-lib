//! L2 table entry and table parsing.
//!
//! The L2 table is the second level of the QCOW2 two-level address mapping.
//! Each entry describes the state of a single guest cluster: unallocated,
//! zero-filled, allocated at a host offset, or compressed.
//!
//! With Extended L2 Entries (incompatible feature bit 4), each entry is 128 bits
//! instead of 64 bits. The extra 64 bits contain a subcluster allocation bitmap
//! that divides each cluster into 32 independently-allocatable subclusters.
//!
//! The [`L2Entry`] enum makes every cluster state an explicit variant,
//! enabling exhaustive pattern matching in the engine's read path.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::compressed::CompressedClusterDescriptor;
use crate::constants::*;
use crate::types::{ClusterGeometry, ClusterOffset, L2Index};

// ---------------------------------------------------------------------------
// Subcluster types (Extended L2)
// ---------------------------------------------------------------------------

/// State of a single subcluster within an extended L2 entry.
///
/// Derived from two bits per subcluster: one allocation bit and one zero bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubclusterState {
    /// alloc=0, zero=0: not allocated, reads from backing or zeros.
    Unallocated,
    /// alloc=1, zero=0: data stored at host_offset + sc_index * sc_size.
    Allocated,
    /// alloc=0, zero=1: reads as zeros regardless of backing.
    Zero,
    /// alloc=1, zero=1: invalid state, must not occur.
    Invalid,
}

/// Subcluster allocation bitmap (second 64 bits of an extended L2 entry).
///
/// Layout (big-endian u64):
/// - Bits 0–31:  allocation status (1 bit per subcluster)
/// - Bits 32–63: zero status (1 bit per subcluster)
///
/// Bit ordering: bit `x` in each 32-bit half corresponds to subcluster `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubclusterBitmap(pub u64);

impl SubclusterBitmap {
    /// A bitmap where all subclusters are unallocated (alloc=0, zero=0).
    pub fn all_unallocated() -> Self {
        Self(0)
    }

    /// A bitmap where all 32 subclusters are allocated (alloc=1, zero=0).
    pub fn all_allocated() -> Self {
        Self(0xFFFF_FFFF)
    }

    /// A bitmap where all 32 subclusters are zero (alloc=0, zero=1).
    pub fn all_zero() -> Self {
        Self(0xFFFF_FFFF_0000_0000)
    }

    /// Whether all subclusters are zero (alloc=0, zero=1).
    pub fn is_all_zero(&self) -> bool {
        self.allocation_mask() == 0 && self.zero_mask() == 0xFFFF_FFFF
    }

    /// Get the state of a single subcluster (index 0..31).
    pub fn get(&self, sc_index: u32) -> SubclusterState {
        debug_assert!(sc_index < SUBCLUSTERS_PER_CLUSTER);
        // Bit x of each 32-bit half corresponds to subcluster x.
        let bit = sc_index;
        let alloc = (self.0 >> bit) & 1 != 0;
        let zero = (self.0 >> (bit + 32)) & 1 != 0;
        match (alloc, zero) {
            (false, false) => SubclusterState::Unallocated,
            (true, false) => SubclusterState::Allocated,
            (false, true) => SubclusterState::Zero,
            (true, true) => SubclusterState::Invalid,
        }
    }

    /// Set the state of a single subcluster (index 0..31).
    pub fn set(&mut self, sc_index: u32, state: SubclusterState) {
        debug_assert!(sc_index < SUBCLUSTERS_PER_CLUSTER);
        let bit = sc_index;
        let alloc_mask = 1u64 << bit;
        let zero_mask = 1u64 << (bit + 32);

        // Clear both bits first
        self.0 &= !(alloc_mask | zero_mask);

        // Set the appropriate bits
        match state {
            SubclusterState::Unallocated => {} // both 0
            SubclusterState::Allocated => self.0 |= alloc_mask,
            SubclusterState::Zero => self.0 |= zero_mask,
            SubclusterState::Invalid => self.0 |= alloc_mask | zero_mask,
        }
    }

    /// Set a contiguous range of subclusters to the same state.
    pub fn set_range(&mut self, start: u32, count: u32, state: SubclusterState) {
        for i in start..start + count {
            if i < SUBCLUSTERS_PER_CLUSTER {
                self.set(i, state);
            }
        }
    }

    /// The raw 32-bit allocation mask (bits 0–31 of the bitmap).
    pub fn allocation_mask(&self) -> u32 {
        self.0 as u32
    }

    /// The raw 32-bit zero mask (bits 32–63 of the bitmap, shifted down).
    pub fn zero_mask(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Whether all subclusters are unallocated (alloc=0, zero=0).
    pub fn is_all_unallocated(&self) -> bool {
        self.0 == 0
    }

    /// Whether all subclusters are allocated (alloc=1, zero=0).
    pub fn is_all_allocated(&self) -> bool {
        self.allocation_mask() == 0xFFFF_FFFF && self.zero_mask() == 0
    }

    /// Check the invariant: no subcluster may have both alloc and zero set.
    pub fn validate(&self) -> bool {
        self.allocation_mask() & self.zero_mask() == 0
    }
}

// ---------------------------------------------------------------------------
// L2Entry
// ---------------------------------------------------------------------------

/// A decoded L2 table entry representing one of four possible cluster states.
///
/// This is the most important type-design decision in the format layer:
/// every cluster state is an explicit enum variant. The Rust compiler
/// ensures that the engine handles every case.
///
/// In extended L2 mode, `Standard` and `Zero` variants carry a
/// [`SubclusterBitmap`] that indicates per-subcluster allocation state.
/// In standard mode the bitmap is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Entry {
    /// Cluster is not allocated; reads return zeros or delegate to backing file.
    Unallocated,

    /// Cluster reads as all zeros.
    ///
    /// In standard mode (v3 zero flag, bit 0): may have a preallocated host cluster.
    /// In extended L2 mode: zero status is per-subcluster in the bitmap,
    /// and bit 0 of the first word is always 0.
    Zero {
        /// If set, a host cluster is preallocated at this offset.
        preallocated_offset: Option<ClusterOffset>,
        /// Subcluster bitmap. In standard mode: `all_zero()`.
        subclusters: SubclusterBitmap,
    },

    /// Standard allocated cluster stored at a specific host offset.
    Standard {
        /// Host file offset of the cluster data.
        host_offset: ClusterOffset,
        /// Whether the COPIED flag (bit 63) is set, indicating refcount is 1.
        copied: bool,
        /// Subcluster bitmap. In standard mode: `all_allocated()`.
        subclusters: SubclusterBitmap,
    },

    /// Compressed cluster (bit 62 set in the raw entry).
    /// In extended L2 mode, the subcluster bitmap must be all zeros.
    Compressed(CompressedClusterDescriptor),
}

impl L2Entry {
    /// Decode a raw 64-bit L2 entry value (standard mode, no subclusters).
    ///
    /// The `cluster_bits` parameter is needed for compressed descriptor decoding.
    pub fn decode(raw: u64, cluster_bits: u32) -> Self {
        Self::decode_extended(raw, 0, cluster_bits, false)
    }

    /// Decode an L2 entry with optional extended bitmap.
    ///
    /// In extended mode, `bitmap_raw` is the second 64-bit word.
    /// In standard mode, `bitmap_raw` is ignored.
    pub fn decode_extended(
        raw: u64,
        bitmap_raw: u64,
        cluster_bits: u32,
        extended_l2: bool,
    ) -> Self {
        // Check compressed flag first (bit 62)
        if raw & L2_COMPRESSED_FLAG != 0 {
            return Self::Compressed(CompressedClusterDescriptor::decode(raw, cluster_bits));
        }

        let offset = raw & L2_STANDARD_OFFSET_MASK;
        let is_copied = raw & L2_COPIED_FLAG != 0;

        if extended_l2 {
            // Extended mode: bit 0 (zero flag) is always 0, zero status is in bitmap
            let bitmap = SubclusterBitmap(bitmap_raw);

            if offset != 0 {
                Self::Standard {
                    host_offset: ClusterOffset(offset),
                    copied: is_copied,
                    subclusters: bitmap,
                }
            } else if bitmap.zero_mask() != 0 {
                // No host offset but some subclusters are zero
                Self::Zero {
                    preallocated_offset: None,
                    subclusters: bitmap,
                }
            } else if bitmap.allocation_mask() != 0 {
                // No host offset but some allocation bits set — treat as standard
                // with zero host offset (unusual but valid per spec)
                Self::Standard {
                    host_offset: ClusterOffset(0),
                    copied: is_copied,
                    subclusters: bitmap,
                }
            } else {
                Self::Unallocated
            }
        } else {
            // Standard mode: use bit 0 as zero flag
            let is_zero = raw & L2_ZERO_FLAG != 0;
            match (offset == 0, is_zero) {
                (true, false) => Self::Unallocated,
                (_, true) => Self::Zero {
                    preallocated_offset: if offset != 0 {
                        Some(ClusterOffset(offset))
                    } else {
                        None
                    },
                    subclusters: SubclusterBitmap::all_zero(),
                },
                (false, false) => Self::Standard {
                    host_offset: ClusterOffset(offset),
                    copied: is_copied,
                    subclusters: SubclusterBitmap::all_allocated(),
                },
            }
        }
    }

    /// Encode the first 64-bit word of an L2 entry.
    ///
    /// In standard mode, bit 0 (L2_ZERO_FLAG) is set for Zero entries.
    /// In extended L2 mode, bit 0 is always 0 (zero status is in the bitmap).
    pub fn encode(self, geo: ClusterGeometry) -> u64 {
        match self {
            Self::Unallocated => 0,
            Self::Zero {
                preallocated_offset, ..
            } => {
                let offset = preallocated_offset.map_or(0, |o| o.0 & L2_STANDARD_OFFSET_MASK);
                if geo.extended_l2 {
                    offset // bit 0 stays 0 — zero status is in bitmap
                } else {
                    offset | L2_ZERO_FLAG
                }
            }
            Self::Standard {
                host_offset,
                copied, ..
            } => {
                let mut raw = host_offset.0 & L2_STANDARD_OFFSET_MASK;
                if copied {
                    raw |= L2_COPIED_FLAG;
                }
                raw
            }
            Self::Compressed(desc) => L2_COMPRESSED_FLAG | desc.encode(geo.cluster_bits),
        }
    }

    /// Get the subcluster bitmap.
    ///
    /// Returns `all_unallocated()` for `Unallocated` and `Compressed` entries.
    pub fn subclusters(&self) -> SubclusterBitmap {
        match self {
            Self::Standard { subclusters, .. } | Self::Zero { subclusters, .. } => *subclusters,
            Self::Unallocated | Self::Compressed(_) => SubclusterBitmap::all_unallocated(),
        }
    }

    /// Encode the subcluster bitmap as a raw u64 (second word of extended L2).
    /// Returns 0 for unallocated and compressed entries.
    pub fn encode_bitmap(&self) -> u64 {
        self.subclusters().0
    }
}

/// An L2 table: one cluster worth of L2 entries.
///
/// In standard mode, contains `cluster_size / 8` entries (8 bytes each).
/// In extended L2 mode, contains `cluster_size / 16` entries (16 bytes each).
/// Entries are decoded eagerly at parse time for fast subsequent access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Table {
    entries: Vec<L2Entry>,
    geometry: ClusterGeometry,
}

impl L2Table {
    /// The size of each L2 entry in bytes for this table.
    pub fn entry_size(&self) -> usize {
        self.geometry.l2_entry_size()
    }

    /// Parse an L2 table from raw bytes.
    ///
    /// The byte slice should be exactly one cluster in size.
    pub fn read_from(bytes: &[u8], geometry: ClusterGeometry) -> Result<Self> {
        let cluster_size = geometry.cluster_size() as usize;
        let entry_size = geometry.l2_entry_size();
        let entry_count = cluster_size / entry_size;

        if bytes.len() < cluster_size {
            return Err(Error::BufferTooSmall {
                expected: cluster_size,
                actual: bytes.len(),
            });
        }

        let entries = (0..entry_count)
            .map(|i| {
                let raw = BigEndian::read_u64(&bytes[i * entry_size..]);
                let bitmap_raw = if geometry.extended_l2 {
                    BigEndian::read_u64(&bytes[i * entry_size + 8..])
                } else {
                    0
                };
                L2Entry::decode_extended(raw, bitmap_raw, geometry.cluster_bits, geometry.extended_l2)
            })
            .collect();

        Ok(Self {
            entries,
            geometry,
        })
    }

    /// Serialize the L2 table to bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let entry_size = self.entry_size();
        let needed = self.entries.len() * entry_size;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                expected: needed,
                actual: buf.len(),
            });
        }

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i * entry_size;
            BigEndian::write_u64(&mut buf[offset..], entry.encode(self.geometry));
            if self.geometry.extended_l2 {
                BigEndian::write_u64(&mut buf[offset + 8..], entry.encode_bitmap());
            }
        }

        Ok(())
    }

    /// Look up an entry by L2 index, with bounds checking.
    pub fn get(&self, index: L2Index) -> Result<L2Entry> {
        self.entries
            .get(index.0 as usize)
            .copied()
            .ok_or(Error::L2IndexOutOfBounds {
                index: index.0,
                table_size: self.entries.len() as u32,
            })
    }

    /// Number of entries in this table.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Set an entry at the given index, with bounds checking.
    pub fn set(&mut self, index: L2Index, entry: L2Entry) -> Result<()> {
        let table_size = self.entries.len() as u32;
        let slot = self
            .entries
            .get_mut(index.0 as usize)
            .ok_or(Error::L2IndexOutOfBounds {
                index: index.0,
                table_size,
            })?;
        *slot = entry;
        Ok(())
    }

    /// Create a new L2 table with all entries unallocated.
    pub fn new_empty(geometry: ClusterGeometry) -> Self {
        let entry_count = geometry.l2_entries_per_table() as usize;
        Self {
            entries: vec![L2Entry::Unallocated; entry_count],
            geometry,
        }
    }

    /// The cluster geometry used by this table.
    pub fn geometry(&self) -> ClusterGeometry {
        self.geometry
    }

    /// The cluster_bits used by this table.
    pub fn cluster_bits(&self) -> u32 {
        self.geometry.cluster_bits
    }

    /// Whether this table uses extended L2 entries.
    pub fn extended_l2(&self) -> bool {
        self.geometry.extended_l2
    }

    /// Iterate over all entries in the table.
    pub fn iter(&self) -> impl Iterator<Item = L2Entry> + '_ {
        self.entries.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_BITS: u32 = 16; // 64 KB clusters
    const GEO_STD: ClusterGeometry = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false };

    #[test]
    fn decode_unallocated() {
        let entry = L2Entry::decode(0, CLUSTER_BITS);
        assert_eq!(entry, L2Entry::Unallocated);
    }

    #[test]
    fn decode_zero_without_preallocation() {
        let raw = L2_ZERO_FLAG; // bit 0 only
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Zero {
                preallocated_offset: None,
                subclusters: SubclusterBitmap::all_zero(),
            }
        );
    }

    #[test]
    fn decode_zero_with_preallocation() {
        let raw = L2_ZERO_FLAG | 0x0000_0000_0001_0000; // zero + offset
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Zero {
                preallocated_offset: Some(ClusterOffset(0x10000)),
                subclusters: SubclusterBitmap::all_zero(),
            }
        );
    }

    #[test]
    fn decode_standard_without_copied() {
        let raw = 0x0000_0000_0002_0000u64; // offset at 0x20000
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Standard {
                host_offset: ClusterOffset(0x20000),
                copied: false,
                subclusters: SubclusterBitmap::all_allocated(),
            }
        );
    }

    #[test]
    fn decode_standard_with_copied() {
        let raw = L2_COPIED_FLAG | 0x0000_0000_0002_0000u64;
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Standard {
                host_offset: ClusterOffset(0x20000),
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            }
        );
    }

    #[test]
    fn decode_compressed() {
        // Build a compressed entry: flag bit 62 + encoded offset/size
        let desc = CompressedClusterDescriptor {
            host_offset: 0x5000,
            compressed_size: 2 * 512,
        };
        let raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(entry, L2Entry::Compressed(desc));
    }

    #[test]
    fn round_trip_all_variants() {
        let variants = vec![
            L2Entry::Unallocated,
            L2Entry::Zero {
                preallocated_offset: None,
                subclusters: SubclusterBitmap::all_zero(),
            },
            L2Entry::Zero {
                preallocated_offset: Some(ClusterOffset(0x30000)),
                subclusters: SubclusterBitmap::all_zero(),
            },
            L2Entry::Standard {
                host_offset: ClusterOffset(0x40000),
                copied: false,
                subclusters: SubclusterBitmap::all_allocated(),
            },
            L2Entry::Standard {
                host_offset: ClusterOffset(0x50000),
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            },
            L2Entry::Compressed(CompressedClusterDescriptor {
                host_offset: 0x6000,
                compressed_size: 3 * 512,
            }),
        ];

        for original in &variants {
            let encoded = original.encode(GEO_STD);
            let decoded = L2Entry::decode(encoded, GEO_STD.cluster_bits);
            assert_eq!(*original, decoded, "round-trip failed for {original:?}");
        }
    }

    #[test]
    fn l2_table_round_trip() {
        let cluster_size = 1usize << CLUSTER_BITS;
        let entry_count = cluster_size / L2_ENTRY_SIZE;

        // Build a table with mixed entries
        let mut entries = vec![L2Entry::Unallocated; entry_count];
        entries[0] = L2Entry::Standard {
            host_offset: ClusterOffset(0x10000),
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        entries[1] = L2Entry::Zero {
            preallocated_offset: None,
            subclusters: SubclusterBitmap::all_zero(),
        };
        entries[2] = L2Entry::Compressed(CompressedClusterDescriptor {
            host_offset: 0x2000,
            compressed_size: 512,
        });

        let table = L2Table {
            entries,
            geometry: GEO_STD,
        };

        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();

        let parsed = L2Table::read_from(&buf, GEO_STD).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn l2_table_get_out_of_bounds() {
        let cluster_size = 1usize << CLUSTER_BITS;
        let buf = vec![0u8; cluster_size];
        let table = L2Table::read_from(&buf, GEO_STD).unwrap();

        let bad_index = table.len();
        match table.get(L2Index(bad_index)) {
            Err(Error::L2IndexOutOfBounds { .. }) => {}
            other => panic!("expected L2IndexOutOfBounds, got {other:?}"),
        }
    }

    // ---- Edge cases: extreme values and flag combinations ----

    #[test]
    fn zero_with_maximum_preallocated_offset() {
        let max_offset = L2_STANDARD_OFFSET_MASK;
        let raw = L2_ZERO_FLAG | max_offset;
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Zero {
                preallocated_offset: Some(ClusterOffset(max_offset)),
                subclusters: SubclusterBitmap::all_zero(),
            }
        );
    }

    #[test]
    fn standard_with_maximum_offset() {
        let max_offset = L2_STANDARD_OFFSET_MASK;
        let raw = L2_COPIED_FLAG | max_offset;
        let entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert_eq!(
            entry,
            L2Entry::Standard {
                host_offset: ClusterOffset(max_offset),
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            }
        );
    }

    #[test]
    fn l2_table_round_trip_min_cluster_bits() {
        let cluster_bits = 9u32; // 512 byte clusters, 64 entries
        let cluster_size = 1usize << cluster_bits;
        let entry_count = cluster_size / L2_ENTRY_SIZE;

        let mut entries = vec![L2Entry::Unallocated; entry_count];
        entries[0] = L2Entry::Standard {
            host_offset: ClusterOffset(0x200), // cluster-aligned for 512
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        entries[1] = L2Entry::Zero {
            preallocated_offset: None,
            subclusters: SubclusterBitmap::all_zero(),
        };

        let table = L2Table {
            entries,
            geometry: ClusterGeometry { cluster_bits, extended_l2: false },
        };

        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();
        let parsed = L2Table::read_from(&buf, ClusterGeometry { cluster_bits, extended_l2: false }).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn l2_table_round_trip_max_cluster_bits() {
        // cluster_bits=21 would need a 2MB buffer. Use a smaller subset.
        let cluster_bits = 21u32;
        let entry_count = 4; // Just test a few entries
        let buf_size = entry_count * L2_ENTRY_SIZE;

        let entries = vec![
            L2Entry::Standard {
                host_offset: ClusterOffset(1u64 << 21),
                copied: false,
                subclusters: SubclusterBitmap::all_allocated(),
            },
            L2Entry::Zero {
                preallocated_offset: None,
                subclusters: SubclusterBitmap::all_zero(),
            },
            L2Entry::Compressed(CompressedClusterDescriptor {
                host_offset: 0x1000,
                compressed_size: 512,
            }),
            L2Entry::Unallocated,
        ];

        let table = L2Table {
            entries: entries.clone(),
            geometry: ClusterGeometry { cluster_bits, extended_l2: false },
        };

        let mut buf = vec![0u8; buf_size];
        table.write_to(&mut buf).unwrap();

        // Read back (need to use the exact buffer size)
        let parsed_entries: Vec<L2Entry> = (0..entry_count)
            .map(|i| {
                let raw = BigEndian::read_u64(&buf[i * L2_ENTRY_SIZE..]);
                L2Entry::decode(raw, cluster_bits)
            })
            .collect();

        assert_eq!(entries, parsed_entries);
    }

    #[test]
    fn compressed_entry_at_min_cluster_bits() {
        let cluster_bits = 9u32;
        // Use a sector-aligned offset so compressed_size is a clean sector multiple
        let desc = CompressedClusterDescriptor {
            host_offset: 0x200,
            compressed_size: 512,
        };
        let raw = L2_COMPRESSED_FLAG | desc.encode(cluster_bits);
        let entry = L2Entry::decode(raw, cluster_bits);
        assert_eq!(entry, L2Entry::Compressed(desc));
    }

    // ---- Mutation methods ----

    #[test]
    fn set_valid_index() {
        let mut table = L2Table::new_empty(GEO_STD);
        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x40000),
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        table.set(L2Index(10), entry).unwrap();
        assert_eq!(table.get(L2Index(10)).unwrap(), entry);
    }

    #[test]
    fn set_out_of_bounds() {
        let mut table = L2Table::new_empty(GEO_STD);
        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x10000),
            copied: false,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        let bad_index = table.len();
        match table.set(L2Index(bad_index), entry) {
            Err(Error::L2IndexOutOfBounds { .. }) => {}
            other => panic!("expected L2IndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn new_empty_correct_size() {
        let table = L2Table::new_empty(GEO_STD);
        let expected = (1usize << CLUSTER_BITS) / L2_ENTRY_SIZE;
        assert_eq!(table.len(), expected as u32);
        assert_eq!(table.cluster_bits(), CLUSTER_BITS);
        for i in 0..table.len() {
            assert_eq!(table.get(L2Index(i)).unwrap(), L2Entry::Unallocated);
        }
    }

    #[test]
    fn set_then_write_round_trip() {
        let mut table = L2Table::new_empty(GEO_STD);
        table
            .set(
                L2Index(0),
                L2Entry::Standard {
                    host_offset: ClusterOffset(0x10000),
                    copied: true,
                    subclusters: SubclusterBitmap::all_allocated(),
                },
            )
            .unwrap();
        table
            .set(
                L2Index(5),
                L2Entry::Zero {
                    preallocated_offset: None,
                    subclusters: SubclusterBitmap::all_zero(),
                },
            )
            .unwrap();

        let cluster_size = 1usize << CLUSTER_BITS;
        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();

        let parsed = L2Table::read_from(&buf, GEO_STD).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn cluster_bits_accessor() {
        let table = L2Table::new_empty(ClusterGeometry { cluster_bits: 12, extended_l2: false });
        assert_eq!(table.cluster_bits(), 12);
    }

    // ---- Iterator tests ----

    #[test]
    fn iter_matches_get() {
        let mut table = L2Table::new_empty(GEO_STD);
        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x20000),
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        table.set(L2Index(5), entry).unwrap();

        let entries: Vec<L2Entry> = table.iter().collect();
        assert_eq!(entries.len(), table.len() as usize);
        assert_eq!(entries[0], L2Entry::Unallocated);
        assert_eq!(entries[5], entry);
    }

    // ---- SubclusterBitmap tests ----

    #[test]
    fn bitmap_all_unallocated() {
        let bm = SubclusterBitmap::all_unallocated();
        assert_eq!(bm.0, 0);
        assert!(bm.is_all_unallocated());
        assert!(!bm.is_all_allocated());
        assert!(bm.validate());
        for i in 0..32 {
            assert_eq!(bm.get(i), SubclusterState::Unallocated);
        }
    }

    #[test]
    fn bitmap_all_allocated() {
        let bm = SubclusterBitmap::all_allocated();
        assert!(!bm.is_all_unallocated());
        assert!(bm.is_all_allocated());
        assert!(bm.validate());
        assert_eq!(bm.allocation_mask(), 0xFFFF_FFFF);
        assert_eq!(bm.zero_mask(), 0);
        for i in 0..32 {
            assert_eq!(bm.get(i), SubclusterState::Allocated);
        }
    }

    #[test]
    fn bitmap_get_set_individual() {
        let mut bm = SubclusterBitmap::all_unallocated();

        bm.set(0, SubclusterState::Allocated);
        assert_eq!(bm.get(0), SubclusterState::Allocated);
        assert_eq!(bm.get(1), SubclusterState::Unallocated);

        bm.set(15, SubclusterState::Zero);
        assert_eq!(bm.get(15), SubclusterState::Zero);

        bm.set(31, SubclusterState::Allocated);
        assert_eq!(bm.get(31), SubclusterState::Allocated);

        assert!(bm.validate());
    }

    #[test]
    fn bitmap_set_range() {
        let mut bm = SubclusterBitmap::all_unallocated();
        bm.set_range(4, 8, SubclusterState::Allocated);

        for i in 0..4 {
            assert_eq!(bm.get(i), SubclusterState::Unallocated);
        }
        for i in 4..12 {
            assert_eq!(bm.get(i), SubclusterState::Allocated);
        }
        for i in 12..32 {
            assert_eq!(bm.get(i), SubclusterState::Unallocated);
        }
        assert!(bm.validate());
    }

    #[test]
    fn bitmap_validate_detects_invalid() {
        let mut bm = SubclusterBitmap::all_unallocated();
        bm.set(5, SubclusterState::Invalid);
        assert!(!bm.validate());
    }

    #[test]
    fn bitmap_masks() {
        let mut bm = SubclusterBitmap::all_unallocated();
        bm.set(0, SubclusterState::Allocated);
        bm.set(1, SubclusterState::Zero);

        // Bit x → subcluster x: SC 0 → bit 0 alloc, SC 1 → bit 1 zero
        assert_eq!(bm.allocation_mask() & (1 << 0), 1 << 0);
        assert_eq!(bm.zero_mask() & (1 << 1), 1 << 1);
    }

    #[test]
    fn bitmap_bit_ordering() {
        // Verify: subcluster x maps to bit x of each half
        let mut bm = SubclusterBitmap(0);
        bm.set(0, SubclusterState::Allocated);
        // Bit 0 of lower 32 bits should be set
        assert_eq!(bm.0, 1u64);

        let mut bm = SubclusterBitmap(0);
        bm.set(31, SubclusterState::Allocated);
        // Bit 31 of lower 32 bits should be set
        assert_eq!(bm.0, 1u64 << 31);

        let mut bm = SubclusterBitmap(0);
        bm.set(0, SubclusterState::Zero);
        // Bit 0 of upper 32 bits should be set (bit 32 of u64)
        assert_eq!(bm.0, 1u64 << 32);
    }

    // ---- Extended L2 decode/encode tests ----

    #[test]
    fn extended_l2_decode_standard() {
        // Extended L2: 16-byte entry with host_offset and bitmap
        let host_offset = 0x30000u64;
        let word0 = host_offset | L2_COPIED_FLAG; // bit 0 must be 0 in extended mode
        let word0 = word0 & !1; // clear bit 0
        let bitmap = SubclusterBitmap::all_allocated();

        let entry = L2Entry::decode_extended(word0, bitmap.0, CLUSTER_BITS, true);
        match entry {
            L2Entry::Standard { host_offset: ho, copied, subclusters } => {
                assert_eq!(ho.0, 0x30000);
                assert!(copied);
                assert_eq!(subclusters, SubclusterBitmap::all_allocated());
            }
            other => panic!("expected Standard, got {:?}", other),
        }
    }

    #[test]
    fn extended_l2_decode_unallocated() {
        // Extended: word0=0, bitmap=0 → Unallocated
        let entry = L2Entry::decode_extended(0, 0, CLUSTER_BITS, true);
        assert_eq!(entry, L2Entry::Unallocated);
    }

    #[test]
    fn extended_l2_decode_zero_all_zero() {
        // Extended: word0=0, bitmap has all zero-bits set
        let bitmap = 0xFFFF_FFFF_0000_0000u64; // all 32 zero-bits set
        let entry = L2Entry::decode_extended(0, bitmap, CLUSTER_BITS, true);
        match entry {
            L2Entry::Zero { preallocated_offset, subclusters } => {
                assert!(preallocated_offset.is_none());
                for i in 0..32 {
                    assert_eq!(subclusters.get(i), SubclusterState::Zero);
                }
            }
            other => panic!("expected Zero, got {:?}", other),
        }
    }

    #[test]
    fn extended_l2_decode_zero_mixed() {
        // Extended: word0=0, bitmap has some zero and some unallocated
        let mut bm = SubclusterBitmap::all_unallocated();
        bm.set(0, SubclusterState::Zero);
        bm.set(5, SubclusterState::Zero);
        let entry = L2Entry::decode_extended(0, bm.0, CLUSTER_BITS, true);
        match entry {
            L2Entry::Zero { subclusters, .. } => {
                assert_eq!(subclusters.get(0), SubclusterState::Zero);
                assert_eq!(subclusters.get(1), SubclusterState::Unallocated);
                assert_eq!(subclusters.get(5), SubclusterState::Zero);
            }
            other => panic!("expected Zero, got {:?}", other),
        }
    }

    #[test]
    fn extended_l2_encode_decode_roundtrip() {
        // Standard entry with partial bitmap
        let mut bm = SubclusterBitmap::all_unallocated();
        bm.set_range(0, 16, SubclusterState::Allocated);
        bm.set_range(16, 16, SubclusterState::Zero);

        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x50000),
            copied: true,
            subclusters: bm,
        };

        let geo_ext = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: true };
        let encoded_word0 = entry.encode(geo_ext);
        let encoded_bm = entry.encode_bitmap();

        let decoded = L2Entry::decode_extended(encoded_word0, encoded_bm, CLUSTER_BITS, true);
        match decoded {
            L2Entry::Standard { host_offset, copied, subclusters } => {
                assert_eq!(host_offset.0, 0x50000);
                assert!(copied);
                for i in 0..16 {
                    assert_eq!(subclusters.get(i), SubclusterState::Allocated, "sc {i}");
                }
                for i in 16..32 {
                    assert_eq!(subclusters.get(i), SubclusterState::Zero, "sc {i}");
                }
            }
            other => panic!("expected Standard, got {:?}", other),
        }
    }

    #[test]
    fn extended_l2_table_read_write_roundtrip() {
        let cluster_bits: u32 = 16;
        let cluster_size = 1usize << cluster_bits;
        let entries_per_table = cluster_size / L2_ENTRY_SIZE_EXTENDED;

        let mut table = L2Table::new_empty(ClusterGeometry { cluster_bits, extended_l2: true });
        assert_eq!(table.len() as usize, entries_per_table);

        // Set a few entries
        let bm = SubclusterBitmap::all_allocated();
        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x40000),
            copied: true,
            subclusters: bm,
        };
        table.set(L2Index(0), entry).unwrap();

        let mut zero_bm = SubclusterBitmap::all_unallocated();
        zero_bm.set_range(0, 32, SubclusterState::Zero);
        let zero_entry = L2Entry::Zero {
            preallocated_offset: None,
            subclusters: zero_bm,
        };
        table.set(L2Index(10), zero_entry).unwrap();

        // Write and read back
        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();
        let table2 = L2Table::read_from(&buf, ClusterGeometry { cluster_bits, extended_l2: true }).unwrap();

        // Verify
        let e0 = table2.get(L2Index(0)).unwrap();
        match e0 {
            L2Entry::Standard { host_offset, subclusters, .. } => {
                assert_eq!(host_offset.0, 0x40000);
                assert!(subclusters.is_all_allocated());
            }
            other => panic!("expected Standard, got {:?}", other),
        }

        let e10 = table2.get(L2Index(10)).unwrap();
        match e10 {
            L2Entry::Zero { subclusters, .. } => {
                for i in 0..32 {
                    assert_eq!(subclusters.get(i), SubclusterState::Zero);
                }
            }
            other => panic!("expected Zero, got {:?}", other),
        }

        // Unset entries remain Unallocated
        assert_eq!(table2.get(L2Index(1)).unwrap(), L2Entry::Unallocated);
    }

    #[test]
    fn extended_l2_table_correct_entry_count() {
        // Extended L2: 16 bytes per entry → half as many entries
        let cluster_bits: u32 = 16;
        let cluster_size = 1usize << cluster_bits;
        let table = L2Table::new_empty(ClusterGeometry { cluster_bits, extended_l2: true });
        assert_eq!(table.len() as usize, cluster_size / L2_ENTRY_SIZE_EXTENDED);

        // Standard: 8 bytes per entry
        let table_std = L2Table::new_empty(ClusterGeometry { cluster_bits, extended_l2: false });
        assert_eq!(table_std.len() as usize, cluster_size / L2_ENTRY_SIZE);

        // Extended has half the entries
        assert_eq!(table.len() * 2, table_std.len());
    }
}
