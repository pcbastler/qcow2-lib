//! L1 table entry and table parsing.
//!
//! The L1 table is the first level of the QCOW2 two-level address mapping.
//! Each 64-bit entry either points to an L2 table or indicates that the
//! entire range covered by that L2 table is unallocated.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::types::{ClusterOffset, L1Index};

/// A single L1 table entry (64 bits on disk, big-endian).
///
/// Bit layout:
/// - Bits 9..=55: L2 table offset (cluster-aligned)
/// - Bit 63: COPIED flag (refcount is exactly one)
/// - All other bits: reserved (must be zero)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L1Entry(u64);

impl L1Entry {
    /// Create an L1 entry from a raw 64-bit value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw 64-bit value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Extract the L2 table offset (bits 9..=55, cluster-aligned).
    ///
    /// Returns `None` if the entry is unallocated (all offset bits are zero).
    pub fn l2_table_offset(self) -> Option<ClusterOffset> {
        let offset = self.0 & L1_OFFSET_MASK;
        if offset == 0 {
            None
        } else {
            Some(ClusterOffset(offset))
        }
    }

    /// Whether the COPIED flag is set (bit 63), indicating refcount is exactly one.
    pub fn is_copied(self) -> bool {
        self.0 & L1_COPIED_FLAG != 0
    }

    /// Whether this entry is unallocated (offset bits all zero).
    pub fn is_unallocated(self) -> bool {
        self.0 & L1_OFFSET_MASK == 0
    }

    /// Create an unallocated L1 entry.
    pub fn unallocated() -> Self {
        Self(0)
    }

    /// Create an L1 entry pointing to an L2 table at the given offset.
    pub fn with_l2_offset(offset: ClusterOffset, copied: bool) -> Self {
        let mut raw = offset.0 & L1_OFFSET_MASK;
        if copied {
            raw |= L1_COPIED_FLAG;
        }
        Self(raw)
    }
}

/// The L1 table: an ordered sequence of L1 entries.
///
/// One L1 entry covers `l2_entries_per_table * cluster_size` bytes of guest space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Table {
    entries: Vec<L1Entry>,
}

impl L1Table {
    /// Parse an L1 table from raw bytes.
    ///
    /// Each entry is 8 bytes big-endian. The byte slice length must equal
    /// `entry_count * 8`.
    pub fn read_from(bytes: &[u8], entry_count: u32) -> Result<Self> {
        let expected_len = entry_count as usize * L1_ENTRY_SIZE;
        if bytes.len() < expected_len {
            return Err(Error::BufferTooSmall {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let entries = (0..entry_count as usize)
            .map(|i| {
                let raw = BigEndian::read_u64(&bytes[i * L1_ENTRY_SIZE..]);
                L1Entry::from_raw(raw)
            })
            .collect();

        Ok(Self { entries })
    }

    /// Serialize the L1 table to bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let needed = self.entries.len() * L1_ENTRY_SIZE;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                expected: needed,
                actual: buf.len(),
            });
        }

        for (i, entry) in self.entries.iter().enumerate() {
            BigEndian::write_u64(&mut buf[i * L1_ENTRY_SIZE..], entry.raw());
        }

        Ok(())
    }

    /// Look up an entry by L1 index, with bounds checking.
    pub fn get(&self, index: L1Index) -> Result<L1Entry> {
        self.entries
            .get(index.0 as usize)
            .copied()
            .ok_or(Error::L1IndexOutOfBounds {
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
    pub fn set(&mut self, index: L1Index, entry: L1Entry) -> Result<()> {
        let table_size = self.entries.len() as u32;
        let slot = self
            .entries
            .get_mut(index.0 as usize)
            .ok_or(Error::L1IndexOutOfBounds {
                index: index.0,
                table_size,
            })?;
        *slot = entry;
        Ok(())
    }

    /// Create a new L1 table with all entries unallocated.
    pub fn new_empty(entry_count: u32) -> Self {
        Self {
            entries: vec![L1Entry::unallocated(); entry_count as usize],
        }
    }

    /// Iterate over all entries in the table.
    pub fn iter(&self) -> impl Iterator<Item = L1Entry> + '_ {
        self.entries.iter().copied()
    }

    /// Number of entries as usize (convenience for iteration bounds).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unallocated_entry() {
        let entry = L1Entry::unallocated();
        assert!(entry.is_unallocated());
        assert_eq!(entry.l2_table_offset(), None);
        assert!(!entry.is_copied());
    }

    #[test]
    fn entry_with_offset() {
        let offset = ClusterOffset(0x10000);
        let entry = L1Entry::with_l2_offset(offset, false);
        assert!(!entry.is_unallocated());
        assert_eq!(entry.l2_table_offset(), Some(offset));
        assert!(!entry.is_copied());
    }

    #[test]
    fn entry_with_offset_and_copied() {
        let offset = ClusterOffset(0x20000);
        let entry = L1Entry::with_l2_offset(offset, true);
        assert_eq!(entry.l2_table_offset(), Some(offset));
        assert!(entry.is_copied());
    }

    #[test]
    fn offset_mask_strips_flag_bits() {
        // Raw value with both COPIED flag and offset
        let raw = L1_COPIED_FLAG | 0x0000_0000_0001_0000;
        let entry = L1Entry::from_raw(raw);
        assert_eq!(entry.l2_table_offset(), Some(ClusterOffset(0x10000)));
        assert!(entry.is_copied());
    }

    #[test]
    fn round_trip_table() {
        let entries = vec![
            L1Entry::unallocated(),
            L1Entry::with_l2_offset(ClusterOffset(0x10000), true),
            L1Entry::with_l2_offset(ClusterOffset(0x20000), false),
            L1Entry::unallocated(),
        ];
        let table = L1Table {
            entries: entries.clone(),
        };

        let mut buf = vec![0u8; 4 * L1_ENTRY_SIZE];
        table.write_to(&mut buf).unwrap();

        let parsed = L1Table::read_from(&buf, 4).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn get_valid_index() {
        let table = L1Table {
            entries: vec![
                L1Entry::unallocated(),
                L1Entry::with_l2_offset(ClusterOffset(0x10000), false),
            ],
        };

        assert!(table.get(L1Index(0)).unwrap().is_unallocated());
        assert_eq!(
            table.get(L1Index(1)).unwrap().l2_table_offset(),
            Some(ClusterOffset(0x10000))
        );
    }

    #[test]
    fn get_out_of_bounds() {
        let table = L1Table {
            entries: vec![L1Entry::unallocated()],
        };

        match table.get(L1Index(5)) {
            Err(Error::L1IndexOutOfBounds {
                index: 5,
                table_size: 1,
            }) => {}
            other => panic!("expected L1IndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn read_from_buffer_too_small() {
        let buf = vec![0u8; 4]; // Only 4 bytes, need 8
        match L1Table::read_from(&buf, 1) {
            Err(Error::BufferTooSmall { .. }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn table_len() {
        let table = L1Table {
            entries: vec![L1Entry::unallocated(); 10],
        };
        assert_eq!(table.len(), 10);
        assert!(!table.is_empty());
    }

    // ---- Edge cases: reserved bits and extreme values ----

    #[test]
    fn reserved_bits_preserved_in_raw() {
        // Set bits that are neither OFFSET_MASK nor COPIED_FLAG
        // Bit 0-8 are reserved in L1 entries (below offset range)
        let raw = 0x0000_0000_0001_01FF; // offset + reserved bits 0-8
        let entry = L1Entry::from_raw(raw);
        // Offset should be masked correctly
        let expected_offset = raw & L1_OFFSET_MASK;
        assert_eq!(
            entry.l2_table_offset(),
            Some(ClusterOffset(expected_offset))
        );
        // Raw value should preserve everything
        assert_eq!(entry.raw(), raw);
    }

    #[test]
    fn maximum_offset_value() {
        // All bits in L1_OFFSET_MASK set
        let raw = L1_OFFSET_MASK;
        let entry = L1Entry::from_raw(raw);
        assert_eq!(
            entry.l2_table_offset(),
            Some(ClusterOffset(L1_OFFSET_MASK))
        );
        assert!(!entry.is_copied());
    }

    #[test]
    fn copied_with_zero_offset() {
        // COPIED=1 but offset=0 — contradictory but L1Entry doesn't validate
        let raw = L1_COPIED_FLAG;
        let entry = L1Entry::from_raw(raw);
        assert!(entry.is_copied());
        // Offset after masking should be 0 → unallocated
        assert_eq!(entry.l2_table_offset(), None);
    }

    #[test]
    fn empty_table_read_write() {
        let table = L1Table::read_from(&[], 0).unwrap();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let mut buf = vec![];
        table.write_to(&mut buf).unwrap();
    }

    // ---- Mutation methods ----

    #[test]
    fn set_valid_index() {
        let mut table = L1Table::new_empty(4);
        assert!(table.get(L1Index(2)).unwrap().is_unallocated());

        let entry = L1Entry::with_l2_offset(ClusterOffset(0x30000), true);
        table.set(L1Index(2), entry).unwrap();
        assert_eq!(table.get(L1Index(2)).unwrap(), entry);
    }

    #[test]
    fn set_out_of_bounds() {
        let mut table = L1Table::new_empty(2);
        let entry = L1Entry::with_l2_offset(ClusterOffset(0x10000), false);
        match table.set(L1Index(5), entry) {
            Err(Error::L1IndexOutOfBounds {
                index: 5,
                table_size: 2,
            }) => {}
            other => panic!("expected L1IndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn new_empty_correct_size() {
        let table = L1Table::new_empty(16);
        assert_eq!(table.len(), 16);
        for i in 0..16 {
            assert!(table.get(L1Index(i)).unwrap().is_unallocated());
        }
    }

    #[test]
    fn set_then_write_round_trip() {
        let mut table = L1Table::new_empty(3);
        table
            .set(L1Index(0), L1Entry::with_l2_offset(ClusterOffset(0x10000), true))
            .unwrap();
        table
            .set(L1Index(2), L1Entry::with_l2_offset(ClusterOffset(0x20000), false))
            .unwrap();

        let mut buf = vec![0u8; 3 * L1_ENTRY_SIZE];
        table.write_to(&mut buf).unwrap();

        let parsed = L1Table::read_from(&buf, 3).unwrap();
        assert_eq!(table, parsed);
    }

    // ---- Iterator tests ----

    #[test]
    fn iter_matches_get() {
        let mut table = L1Table::new_empty(3);
        let e1 = L1Entry::with_l2_offset(ClusterOffset(0x10000), true);
        table.set(L1Index(1), e1).unwrap();

        let entries: Vec<L1Entry> = table.iter().collect();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].is_unallocated());
        assert_eq!(entries[1], e1);
        assert!(entries[2].is_unallocated());
    }

    #[test]
    fn iter_empty_table() {
        let table = L1Table::new_empty(0);
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.entry_count(), 0);
    }

    #[test]
    fn entry_count_matches_len() {
        let table = L1Table::new_empty(7);
        assert_eq!(table.entry_count(), 7);
        assert_eq!(table.entry_count(), table.len() as usize);
    }
}
