//! L2 table entry and table parsing.
//!
//! The L2 table is the second level of the QCOW2 two-level address mapping.
//! Each entry describes the state of a single guest cluster: unallocated,
//! zero-filled, allocated at a host offset, or compressed.
//!
//! The [`L2Entry`] enum makes every cluster state an explicit variant,
//! enabling exhaustive pattern matching in the engine's read path.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::constants::*;
use crate::format::types::{ClusterOffset, L2Index};

/// A decoded L2 table entry representing one of four possible cluster states.
///
/// This is the most important type-design decision in the format layer:
/// every cluster state is an explicit enum variant. The Rust compiler
/// ensures that the engine handles every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Entry {
    /// Cluster is not allocated; reads return zeros or delegate to backing file.
    Unallocated,

    /// Cluster reads as all zeros (v3 zero flag, bit 0).
    ///
    /// May optionally have a preallocated host cluster (for write performance).
    Zero {
        /// If set, a host cluster is preallocated at this offset.
        preallocated_offset: Option<ClusterOffset>,
    },

    /// Standard allocated cluster stored at a specific host offset.
    Standard {
        /// Host file offset of the cluster data.
        host_offset: ClusterOffset,
        /// Whether the COPIED flag (bit 63) is set, indicating refcount is 1.
        copied: bool,
    },

    /// Compressed cluster (bit 62 set in the raw entry).
    Compressed(CompressedClusterDescriptor),
}

impl L2Entry {
    /// Decode a raw 64-bit L2 entry value.
    ///
    /// The `cluster_bits` parameter is needed for compressed descriptor decoding.
    pub fn decode(raw: u64, cluster_bits: u32) -> Self {
        // Check compressed flag first (bit 62)
        if raw & L2_COMPRESSED_FLAG != 0 {
            return Self::Compressed(CompressedClusterDescriptor::decode(raw, cluster_bits));
        }

        let offset = raw & L2_STANDARD_OFFSET_MASK;
        let is_zero = raw & L2_ZERO_FLAG != 0;
        let is_copied = raw & L2_COPIED_FLAG != 0;

        match (offset == 0, is_zero) {
            // No offset, no zero flag => unallocated
            (true, false) => Self::Unallocated,
            // Zero flag set (with or without preallocated offset)
            (_, true) => Self::Zero {
                preallocated_offset: if offset != 0 {
                    Some(ClusterOffset(offset))
                } else {
                    None
                },
            },
            // Offset present, no zero flag => standard allocated
            (false, false) => Self::Standard {
                host_offset: ClusterOffset(offset),
                copied: is_copied,
            },
        }
    }

    /// Encode back to a raw 64-bit L2 entry value.
    pub fn encode(self, cluster_bits: u32) -> u64 {
        match self {
            Self::Unallocated => 0,
            Self::Zero {
                preallocated_offset,
            } => {
                let offset = preallocated_offset.map_or(0, |o| o.0 & L2_STANDARD_OFFSET_MASK);
                offset | L2_ZERO_FLAG
            }
            Self::Standard {
                host_offset,
                copied,
            } => {
                let mut raw = host_offset.0 & L2_STANDARD_OFFSET_MASK;
                if copied {
                    raw |= L2_COPIED_FLAG;
                }
                raw
            }
            Self::Compressed(desc) => L2_COMPRESSED_FLAG | desc.encode(cluster_bits),
        }
    }
}

/// An L2 table: one cluster worth of L2 entries.
///
/// Contains `cluster_size / 8` entries (each entry is 8 bytes).
/// Entries are decoded eagerly at parse time for fast subsequent access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Table {
    entries: Vec<L2Entry>,
    cluster_bits: u32,
}

impl L2Table {
    /// Parse an L2 table from raw bytes.
    ///
    /// The byte slice should be exactly one cluster in size
    /// (`1 << cluster_bits` bytes).
    pub fn read_from(bytes: &[u8], cluster_bits: u32) -> Result<Self> {
        let cluster_size = 1usize << cluster_bits;
        let entry_count = cluster_size / L2_ENTRY_SIZE;

        if bytes.len() < cluster_size {
            return Err(Error::BufferTooSmall {
                expected: cluster_size,
                actual: bytes.len(),
            });
        }

        let entries = (0..entry_count)
            .map(|i| {
                let raw = BigEndian::read_u64(&bytes[i * L2_ENTRY_SIZE..]);
                L2Entry::decode(raw, cluster_bits)
            })
            .collect();

        Ok(Self {
            entries,
            cluster_bits,
        })
    }

    /// Serialize the L2 table to bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let needed = self.entries.len() * L2_ENTRY_SIZE;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                expected: needed,
                actual: buf.len(),
            });
        }

        for (i, entry) in self.entries.iter().enumerate() {
            BigEndian::write_u64(
                &mut buf[i * L2_ENTRY_SIZE..],
                entry.encode(self.cluster_bits),
            );
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_BITS: u32 = 16; // 64 KB clusters

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
                preallocated_offset: None
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
                preallocated_offset: Some(ClusterOffset(0x10000))
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
            },
            L2Entry::Zero {
                preallocated_offset: Some(ClusterOffset(0x30000)),
            },
            L2Entry::Standard {
                host_offset: ClusterOffset(0x40000),
                copied: false,
            },
            L2Entry::Standard {
                host_offset: ClusterOffset(0x50000),
                copied: true,
            },
            L2Entry::Compressed(CompressedClusterDescriptor {
                host_offset: 0x6000,
                compressed_size: 3 * 512,
            }),
        ];

        for original in &variants {
            let encoded = original.encode(CLUSTER_BITS);
            let decoded = L2Entry::decode(encoded, CLUSTER_BITS);
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
        };
        entries[1] = L2Entry::Zero {
            preallocated_offset: None,
        };
        entries[2] = L2Entry::Compressed(CompressedClusterDescriptor {
            host_offset: 0x2000,
            compressed_size: 512,
        });

        let table = L2Table {
            entries,
            cluster_bits: CLUSTER_BITS,
        };

        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();

        let parsed = L2Table::read_from(&buf, CLUSTER_BITS).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn l2_table_get_out_of_bounds() {
        let cluster_size = 1usize << CLUSTER_BITS;
        let buf = vec![0u8; cluster_size];
        let table = L2Table::read_from(&buf, CLUSTER_BITS).unwrap();

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
                preallocated_offset: Some(ClusterOffset(max_offset))
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
        };
        entries[1] = L2Entry::Zero {
            preallocated_offset: None,
        };

        let table = L2Table {
            entries,
            cluster_bits,
        };

        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf).unwrap();
        let parsed = L2Table::read_from(&buf, cluster_bits).unwrap();
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
            },
            L2Entry::Zero {
                preallocated_offset: None,
            },
            L2Entry::Compressed(CompressedClusterDescriptor {
                host_offset: 0x1000,
                compressed_size: 512,
            }),
            L2Entry::Unallocated,
        ];

        let table = L2Table {
            entries: entries.clone(),
            cluster_bits,
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
        let desc = CompressedClusterDescriptor {
            host_offset: 0x100,
            compressed_size: 512, // minimum
        };
        let raw = L2_COMPRESSED_FLAG | desc.encode(cluster_bits);
        let entry = L2Entry::decode(raw, cluster_bits);
        assert_eq!(entry, L2Entry::Compressed(desc));
    }
}
