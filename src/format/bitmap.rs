//! Persistent bitmap structures for dirty tracking.
//!
//! QCOW2 v3 supports persistent bitmaps stored as a header extension.
//! Each bitmap tracks which regions of the virtual disk have been modified,
//! using a two-level structure: a bitmap table pointing to bitmap data clusters.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::types::{BitmapIndex, ClusterOffset};

// ---- Bitmap header extension ----

/// Parsed bitmaps header extension (type 0x2385_2875).
///
/// Contains metadata about the bitmap directory stored elsewhere in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapExtension {
    /// Number of bitmaps in the image.
    pub nb_bitmaps: u32,
    /// Total size of the bitmap directory in bytes.
    pub bitmap_directory_size: u64,
    /// Host file offset of the bitmap directory (cluster-aligned).
    pub bitmap_directory_offset: u64,
}

impl BitmapExtension {
    /// Parse from header extension raw data (must be exactly 24 bytes).
    ///
    /// Layout:
    /// - bytes 0..4:   nb_bitmaps (u32)
    /// - bytes 4..8:   reserved (u32, must be 0)
    /// - bytes 8..16:  bitmap_directory_size (u64)
    /// - bytes 16..24: bitmap_directory_offset (u64)
    pub fn read_from(data: &[u8]) -> Result<Self> {
        if data.len() < BITMAP_EXTENSION_DATA_SIZE {
            return Err(Error::InvalidBitmapExtension {
                message: format!(
                    "extension data too short: need {} bytes, got {}",
                    BITMAP_EXTENSION_DATA_SIZE,
                    data.len()
                ),
            });
        }

        let nb_bitmaps = BigEndian::read_u32(&data[0..]);
        let reserved = BigEndian::read_u32(&data[4..]);
        let bitmap_directory_size = BigEndian::read_u64(&data[8..]);
        let bitmap_directory_offset = BigEndian::read_u64(&data[16..]);

        if reserved != 0 {
            return Err(Error::InvalidBitmapExtension {
                message: format!("reserved field must be 0, got {reserved}"),
            });
        }

        if nb_bitmaps == 0 {
            return Err(Error::InvalidBitmapExtension {
                message: "nb_bitmaps must be > 0".to_string(),
            });
        }

        if nb_bitmaps > BITMAP_MAX_COUNT {
            return Err(Error::InvalidBitmapExtension {
                message: format!(
                    "nb_bitmaps {} exceeds maximum {}",
                    nb_bitmaps, BITMAP_MAX_COUNT
                ),
            });
        }

        if bitmap_directory_size == 0 {
            return Err(Error::InvalidBitmapExtension {
                message: "bitmap_directory_size must be > 0".to_string(),
            });
        }

        Ok(Self {
            nb_bitmaps,
            bitmap_directory_size,
            bitmap_directory_offset,
        })
    }

    /// Serialize to 24 bytes for the header extension.
    pub fn write_to(&self) -> Vec<u8> {
        let mut buf = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u32(&mut buf[0..], self.nb_bitmaps);
        // bytes 4..8: reserved = 0
        BigEndian::write_u64(&mut buf[8..], self.bitmap_directory_size);
        BigEndian::write_u64(&mut buf[16..], self.bitmap_directory_offset);
        buf
    }
}

// ---- Bitmap directory entry ----

/// A single entry in the bitmap directory.
///
/// Each entry describes one bitmap: its table location, granularity, flags,
/// and name. Entries have a 24-byte fixed header followed by variable-length
/// extra data and name, padded to an 8-byte boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapDirectoryEntry {
    /// Host file offset of the bitmap table (cluster-aligned).
    pub bitmap_table_offset: ClusterOffset,
    /// Number of entries in the bitmap table.
    pub bitmap_table_size: u32,
    /// Flags (IN_USE, AUTO, EXTRA_DATA_COMPATIBLE).
    pub flags: u32,
    /// Bitmap type (1 = dirty tracking).
    pub bitmap_type: u8,
    /// Granularity = 1 << granularity_bits.
    pub granularity_bits: u8,
    /// Bitmap name (unique per image, not null-terminated on disk).
    pub name: String,
    /// Extra data (currently reserved).
    pub extra_data: Vec<u8>,
}

impl BitmapDirectoryEntry {
    /// Parse one entry from a byte slice at the given base offset.
    ///
    /// Returns `(entry, bytes_consumed)` where bytes_consumed includes padding.
    pub fn read_from(bytes: &[u8], base_offset: usize) -> Result<(Self, usize)> {
        if bytes.len() < BITMAP_DIR_ENTRY_FIXED_SIZE {
            return Err(Error::BitmapDirectoryTruncated {
                offset: base_offset,
                expected: BITMAP_DIR_ENTRY_FIXED_SIZE,
                actual: bytes.len(),
            });
        }

        let bitmap_table_offset = ClusterOffset(BigEndian::read_u64(&bytes[0..]));
        let bitmap_table_size = BigEndian::read_u32(&bytes[8..]);
        let flags = BigEndian::read_u32(&bytes[12..]);
        let bitmap_type = bytes[16];
        let granularity_bits = bytes[17];
        let name_size = BigEndian::read_u16(&bytes[18..]) as usize;
        let extra_data_size = BigEndian::read_u32(&bytes[20..]) as usize;

        let variable_start = BITMAP_DIR_ENTRY_FIXED_SIZE;
        let variable_end = variable_start + extra_data_size + name_size;

        if bytes.len() < variable_end {
            return Err(Error::BitmapDirectoryTruncated {
                offset: base_offset,
                expected: variable_end,
                actual: bytes.len(),
            });
        }

        let extra_data = bytes[variable_start..variable_start + extra_data_size].to_vec();
        let name_bytes = &bytes[variable_start + extra_data_size..variable_end];
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        // Pad total consumed bytes to 8-byte alignment
        let consumed = (variable_end + 7) & !7;

        Ok((
            Self {
                bitmap_table_offset,
                bitmap_table_size,
                flags,
                bitmap_type,
                granularity_bits,
                name,
                extra_data,
            },
            consumed,
        ))
    }

    /// Parse the full bitmap directory.
    pub fn read_directory(bytes: &[u8], nb_bitmaps: u32) -> Result<Vec<Self>> {
        let mut entries = Vec::with_capacity(nb_bitmaps as usize);
        let mut pos = 0;

        for _ in 0..nb_bitmaps {
            let remaining = &bytes[pos..];
            let (entry, consumed) = Self::read_from(remaining, pos)?;
            entries.push(entry);
            pos += consumed;
        }

        Ok(entries)
    }

    /// Serialize one entry (including padding) into the output buffer.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        let name_bytes = self.name.as_bytes();
        let name_size = name_bytes.len();
        let extra_data_size = self.extra_data.len();

        let mut fixed = [0u8; BITMAP_DIR_ENTRY_FIXED_SIZE];
        BigEndian::write_u64(&mut fixed[0..], self.bitmap_table_offset.0);
        BigEndian::write_u32(&mut fixed[8..], self.bitmap_table_size);
        BigEndian::write_u32(&mut fixed[12..], self.flags);
        fixed[16] = self.bitmap_type;
        fixed[17] = self.granularity_bits;
        BigEndian::write_u16(&mut fixed[18..], name_size as u16);
        BigEndian::write_u32(&mut fixed[20..], extra_data_size as u32);

        out.extend_from_slice(&fixed);
        out.extend_from_slice(&self.extra_data);
        out.extend_from_slice(name_bytes);

        // Pad to 8-byte alignment
        let total = BITMAP_DIR_ENTRY_FIXED_SIZE + extra_data_size + name_size;
        let padding = (8 - (total % 8)) % 8;
        out.resize(out.len() + padding, 0);
    }

    /// Serialize the full bitmap directory.
    pub fn write_directory(entries: &[Self]) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in entries {
            entry.write_to(&mut buf);
        }
        buf
    }

    /// Whether the IN_USE flag is set (bitmap may be inconsistent).
    pub fn is_in_use(&self) -> bool {
        self.flags & BME_FLAG_IN_USE != 0
    }

    /// Whether the AUTO flag is set (auto-tracking enabled).
    pub fn is_auto(&self) -> bool {
        self.flags & BME_FLAG_AUTO != 0
    }

    /// Granularity in bytes (1 << granularity_bits).
    pub fn granularity(&self) -> u64 {
        1u64 << self.granularity_bits
    }
}

// ---- Bitmap table entry ----

/// Decoded state of a bitmap table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapTableEntryState {
    /// All bits in this range are zero (clean).
    AllZeros,
    /// All bits in this range are one (dirty).
    AllOnes,
    /// Points to a data cluster containing actual bits.
    Data(ClusterOffset),
}

/// A single bitmap table entry (64 bits on disk, big-endian).
///
/// Three states:
/// - offset=0, bit0=0: all-zeros (all clean)
/// - offset=0, bit0=1: all-ones (all dirty)
/// - offset!=0: points to a bitmap data cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapTableEntry(u64);

impl BitmapTableEntry {
    /// Create from a raw 64-bit value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw 64-bit value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Create an all-zeros entry (all clean).
    pub fn all_zeros() -> Self {
        Self(0)
    }

    /// Create an all-ones entry (all dirty).
    pub fn all_ones() -> Self {
        Self(BME_TABLE_ALL_ONES_FLAG)
    }

    /// Create an entry pointing to a bitmap data cluster.
    pub fn with_data_offset(offset: ClusterOffset) -> Self {
        Self(offset.0 & BME_TABLE_OFFSET_MASK)
    }

    /// Decode the entry state.
    pub fn state(self) -> BitmapTableEntryState {
        let offset = self.0 & BME_TABLE_OFFSET_MASK;
        if offset != 0 {
            BitmapTableEntryState::Data(ClusterOffset(offset))
        } else if self.0 & BME_TABLE_ALL_ONES_FLAG != 0 {
            BitmapTableEntryState::AllOnes
        } else {
            BitmapTableEntryState::AllZeros
        }
    }

    /// Extract the data cluster offset, if any.
    pub fn data_cluster_offset(self) -> Option<ClusterOffset> {
        match self.state() {
            BitmapTableEntryState::Data(offset) => Some(offset),
            _ => None,
        }
    }
}

// ---- Bitmap table ----

/// The bitmap table: maps ranges of guest space to bitmap data clusters.
///
/// Analogous to the L1 table, but for bitmap data instead of guest data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapTable {
    entries: Vec<BitmapTableEntry>,
}

impl BitmapTable {
    /// Parse a bitmap table from raw bytes.
    ///
    /// Each entry is 8 bytes big-endian.
    pub fn read_from(bytes: &[u8], entry_count: u32) -> Result<Self> {
        let expected_len = entry_count as usize * BITMAP_TABLE_ENTRY_SIZE;
        if bytes.len() < expected_len {
            return Err(Error::BufferTooSmall {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let entries = (0..entry_count as usize)
            .map(|i| {
                let raw = BigEndian::read_u64(&bytes[i * BITMAP_TABLE_ENTRY_SIZE..]);
                BitmapTableEntry::from_raw(raw)
            })
            .collect();

        Ok(Self { entries })
    }

    /// Serialize the bitmap table into a byte buffer.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let expected_len = self.entries.len() * BITMAP_TABLE_ENTRY_SIZE;
        if buf.len() < expected_len {
            return Err(Error::BufferTooSmall {
                expected: expected_len,
                actual: buf.len(),
            });
        }

        for (i, entry) in self.entries.iter().enumerate() {
            BigEndian::write_u64(&mut buf[i * BITMAP_TABLE_ENTRY_SIZE..], entry.raw());
        }

        Ok(())
    }

    /// Get the entry at the given index.
    pub fn get(&self, index: BitmapIndex) -> Result<BitmapTableEntry> {
        self.entries
            .get(index.0 as usize)
            .copied()
            .ok_or(Error::BitmapIndexOutOfBounds {
                index: index.0,
                table_size: self.entries.len() as u32,
            })
    }

    /// Set the entry at the given index.
    pub fn set(&mut self, index: BitmapIndex, entry: BitmapTableEntry) -> Result<()> {
        let len = self.entries.len() as u32;
        let slot = self
            .entries
            .get_mut(index.0 as usize)
            .ok_or(Error::BitmapIndexOutOfBounds {
                index: index.0,
                table_size: len,
            })?;
        *slot = entry;
        Ok(())
    }

    /// Number of entries in the table.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = BitmapTableEntry> + '_ {
        self.entries.iter().copied()
    }

    /// Create a table with all entries set to all-zeros (all clean).
    pub fn new_all_zeros(entry_count: u32) -> Self {
        Self {
            entries: vec![BitmapTableEntry::all_zeros(); entry_count as usize],
        }
    }

    /// Create a table with all entries set to all-ones (all dirty).
    pub fn new_all_ones(entry_count: u32) -> Self {
        Self {
            entries: vec![BitmapTableEntry::all_ones(); entry_count as usize],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- BitmapExtension tests ----

    #[test]
    fn extension_round_trip() {
        let ext = BitmapExtension {
            nb_bitmaps: 3,
            bitmap_directory_size: 128,
            bitmap_directory_offset: 0x10000,
        };
        let data = ext.write_to();
        assert_eq!(data.len(), BITMAP_EXTENSION_DATA_SIZE);
        let parsed = BitmapExtension::read_from(&data).unwrap();
        assert_eq!(ext, parsed);
    }

    #[test]
    fn extension_rejects_short_data() {
        let data = [0u8; 16];
        match BitmapExtension::read_from(&data) {
            Err(Error::InvalidBitmapExtension { .. }) => {}
            other => panic!("expected InvalidBitmapExtension, got {other:?}"),
        }
    }

    #[test]
    fn extension_rejects_nonzero_reserved() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u32(&mut data[0..], 1); // nb_bitmaps
        BigEndian::write_u32(&mut data[4..], 42); // reserved != 0
        BigEndian::write_u64(&mut data[8..], 24); // dir size
        BigEndian::write_u64(&mut data[16..], 0x10000); // dir offset
        match BitmapExtension::read_from(&data) {
            Err(Error::InvalidBitmapExtension { message }) => {
                assert!(message.contains("reserved"), "{message}");
            }
            other => panic!("expected InvalidBitmapExtension, got {other:?}"),
        }
    }

    #[test]
    fn extension_rejects_zero_bitmaps() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u64(&mut data[8..], 24);
        BigEndian::write_u64(&mut data[16..], 0x10000);
        match BitmapExtension::read_from(&data) {
            Err(Error::InvalidBitmapExtension { message }) => {
                assert!(message.contains("nb_bitmaps"), "{message}");
            }
            other => panic!("expected InvalidBitmapExtension, got {other:?}"),
        }
    }

    #[test]
    fn extension_rejects_too_many_bitmaps() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u32(&mut data[0..], BITMAP_MAX_COUNT + 1);
        BigEndian::write_u64(&mut data[8..], 24);
        BigEndian::write_u64(&mut data[16..], 0x10000);
        match BitmapExtension::read_from(&data) {
            Err(Error::InvalidBitmapExtension { message }) => {
                assert!(message.contains("exceeds maximum"), "{message}");
            }
            other => panic!("expected InvalidBitmapExtension, got {other:?}"),
        }
    }

    #[test]
    fn extension_rejects_zero_directory_size() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u32(&mut data[0..], 1);
        // bitmap_directory_size = 0
        BigEndian::write_u64(&mut data[16..], 0x10000);
        match BitmapExtension::read_from(&data) {
            Err(Error::InvalidBitmapExtension { message }) => {
                assert!(message.contains("bitmap_directory_size"), "{message}");
            }
            other => panic!("expected InvalidBitmapExtension, got {other:?}"),
        }
    }

    // ---- BitmapDirectoryEntry tests ----

    #[test]
    fn directory_entry_round_trip() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x20000),
            bitmap_table_size: 16,
            flags: BME_FLAG_AUTO,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: "dirty-bitmap".to_string(),
            extra_data: vec![],
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf);
        let (parsed, consumed) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(entry, parsed);
        assert_eq!(consumed % 8, 0, "consumed must be 8-byte aligned");
    }

    #[test]
    fn directory_entry_with_extra_data() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x30000),
            bitmap_table_size: 8,
            flags: BME_FLAG_IN_USE | BME_FLAG_AUTO,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 20,
            name: "test".to_string(),
            extra_data: vec![1, 2, 3, 4],
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf);
        let (parsed, consumed) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(entry, parsed);
        assert_eq!(consumed % 8, 0);
    }

    #[test]
    fn directory_round_trip_multiple() {
        let entries = vec![
            BitmapDirectoryEntry {
                bitmap_table_offset: ClusterOffset(0x10000),
                bitmap_table_size: 4,
                flags: 0,
                bitmap_type: BITMAP_TYPE_DIRTY,
                granularity_bits: 16,
                name: "a".to_string(),
                extra_data: vec![],
            },
            BitmapDirectoryEntry {
                bitmap_table_offset: ClusterOffset(0x20000),
                bitmap_table_size: 8,
                flags: BME_FLAG_AUTO,
                bitmap_type: BITMAP_TYPE_DIRTY,
                granularity_bits: 20,
                name: "bitmap-two".to_string(),
                extra_data: vec![],
            },
        ];

        let buf = BitmapDirectoryEntry::write_directory(&entries);
        let parsed = BitmapDirectoryEntry::read_directory(&buf, 2).unwrap();
        assert_eq!(entries, parsed);
    }

    #[test]
    fn directory_entry_truncated() {
        let data = [0u8; 10];
        match BitmapDirectoryEntry::read_from(&data, 0) {
            Err(Error::BitmapDirectoryTruncated { expected: 24, .. }) => {}
            other => panic!("expected BitmapDirectoryTruncated, got {other:?}"),
        }
    }

    #[test]
    fn directory_entry_truncated_variable_part() {
        let mut buf = vec![0u8; BITMAP_DIR_ENTRY_FIXED_SIZE];
        // Set name_size to 100 but provide no data beyond fixed header
        BigEndian::write_u16(&mut buf[18..], 100);
        match BitmapDirectoryEntry::read_from(&buf, 0) {
            Err(Error::BitmapDirectoryTruncated { .. }) => {}
            other => panic!("expected BitmapDirectoryTruncated, got {other:?}"),
        }
    }

    #[test]
    fn directory_entry_flags() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0),
            bitmap_table_size: 0,
            flags: BME_FLAG_IN_USE | BME_FLAG_AUTO,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: "x".to_string(),
            extra_data: vec![],
        };
        assert!(entry.is_in_use());
        assert!(entry.is_auto());
        assert_eq!(entry.granularity(), 65536);
    }

    #[test]
    fn directory_entry_padding_various_name_lengths() {
        for name_len in 1..=16 {
            let name: String = "x".repeat(name_len);
            let entry = BitmapDirectoryEntry {
                bitmap_table_offset: ClusterOffset(0x10000),
                bitmap_table_size: 1,
                flags: 0,
                bitmap_type: BITMAP_TYPE_DIRTY,
                granularity_bits: 16,
                name: name.clone(),
                extra_data: vec![],
            };

            let mut buf = Vec::new();
            entry.write_to(&mut buf);
            assert_eq!(buf.len() % 8, 0, "name_len={name_len}: not 8-byte aligned");

            let (parsed, consumed) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
            assert_eq!(parsed.name, name);
            assert_eq!(consumed, buf.len());
        }
    }

    // ---- BitmapTableEntry tests ----

    #[test]
    fn entry_all_zeros() {
        let entry = BitmapTableEntry::all_zeros();
        assert_eq!(entry.raw(), 0);
        assert_eq!(entry.state(), BitmapTableEntryState::AllZeros);
        assert_eq!(entry.data_cluster_offset(), None);
    }

    #[test]
    fn entry_all_ones() {
        let entry = BitmapTableEntry::all_ones();
        assert_eq!(entry.raw(), 1);
        assert_eq!(entry.state(), BitmapTableEntryState::AllOnes);
        assert_eq!(entry.data_cluster_offset(), None);
    }

    #[test]
    fn entry_with_data_offset() {
        let offset = ClusterOffset(0x30000);
        let entry = BitmapTableEntry::with_data_offset(offset);
        assert_eq!(
            entry.state(),
            BitmapTableEntryState::Data(ClusterOffset(0x30000))
        );
        assert_eq!(entry.data_cluster_offset(), Some(ClusterOffset(0x30000)));
    }

    #[test]
    fn entry_from_raw_data() {
        // Offset in bits 9..=55
        let raw = 0x00_0000_0001_0000_00u64; // cluster at 0x10000 (bits 9..=55 encode this)
        let entry = BitmapTableEntry::from_raw(raw);
        match entry.state() {
            BitmapTableEntryState::Data(offset) => {
                assert_eq!(offset.0, raw & BME_TABLE_OFFSET_MASK);
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn entry_round_trip_raw() {
        for raw in [0u64, 1u64, 0x10000u64, 0x00ff_ffff_ffff_fe00u64] {
            let entry = BitmapTableEntry::from_raw(raw);
            assert_eq!(entry.raw(), raw);
        }
    }

    // ---- BitmapTable tests ----

    #[test]
    fn table_read_write_round_trip() {
        let mut table = BitmapTable::new_all_zeros(4);
        table
            .set(BitmapIndex(1), BitmapTableEntry::all_ones())
            .unwrap();
        table
            .set(
                BitmapIndex(3),
                BitmapTableEntry::with_data_offset(ClusterOffset(0x20000)),
            )
            .unwrap();

        let mut buf = vec![0u8; 4 * BITMAP_TABLE_ENTRY_SIZE];
        table.write_to(&mut buf).unwrap();

        let parsed = BitmapTable::read_from(&buf, 4).unwrap();
        assert_eq!(table, parsed);
    }

    #[test]
    fn table_get_out_of_bounds() {
        let table = BitmapTable::new_all_zeros(2);
        match table.get(BitmapIndex(2)) {
            Err(Error::BitmapIndexOutOfBounds {
                index: 2,
                table_size: 2,
            }) => {}
            other => panic!("expected BitmapIndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn table_set_out_of_bounds() {
        let mut table = BitmapTable::new_all_zeros(2);
        match table.set(BitmapIndex(5), BitmapTableEntry::all_ones()) {
            Err(Error::BitmapIndexOutOfBounds {
                index: 5,
                table_size: 2,
            }) => {}
            other => panic!("expected BitmapIndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn table_new_all_ones() {
        let table = BitmapTable::new_all_ones(3);
        assert_eq!(table.len(), 3);
        for entry in table.iter() {
            assert_eq!(entry.state(), BitmapTableEntryState::AllOnes);
        }
    }

    #[test]
    fn table_len_and_empty() {
        let table = BitmapTable::new_all_zeros(0);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let table = BitmapTable::new_all_zeros(5);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 5);
    }

    #[test]
    fn table_buffer_too_small() {
        let buf = [0u8; 4];
        match BitmapTable::read_from(&buf, 2) {
            Err(Error::BufferTooSmall {
                expected: 16,
                actual: 4,
            }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn table_write_buffer_too_small() {
        let table = BitmapTable::new_all_zeros(2);
        let mut buf = [0u8; 4];
        match table.write_to(&mut buf) {
            Err(Error::BufferTooSmall {
                expected: 16,
                actual: 4,
            }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn table_iter_entries() {
        let mut table = BitmapTable::new_all_zeros(3);
        table
            .set(BitmapIndex(1), BitmapTableEntry::all_ones())
            .unwrap();

        let states: Vec<_> = table.iter().map(|e| e.state()).collect();
        assert_eq!(
            states,
            vec![
                BitmapTableEntryState::AllZeros,
                BitmapTableEntryState::AllOnes,
                BitmapTableEntryState::AllZeros,
            ]
        );
    }

    // ---- Boundary & edge cases ----

    #[test]
    fn extension_max_bitmap_count_accepted() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_SIZE];
        BigEndian::write_u32(&mut data[0..], BITMAP_MAX_COUNT); // exactly at max
        BigEndian::write_u64(&mut data[8..], 1024); // dir size
        BigEndian::write_u64(&mut data[16..], 0x10000); // dir offset
        assert!(BitmapExtension::read_from(&data).is_ok());
    }

    #[test]
    fn directory_entry_max_name_length() {
        let name = "x".repeat(BITMAP_MAX_NAME_SIZE as usize);
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: 0,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: name.clone(),
            extra_data: Vec::new(),
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf);

        let (parsed, _) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.name, name);
        assert_eq!(parsed.name.len(), BITMAP_MAX_NAME_SIZE as usize);
    }

    #[test]
    fn directory_entry_name_one_byte() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: 0,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: "a".into(),
            extra_data: Vec::new(),
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf);

        let (parsed, consumed) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.name, "a");
        // 24 fixed + 0 extra + 1 name = 25, padded to 32 (8-byte aligned)
        assert_eq!(consumed, 32);
    }

    #[test]
    fn entry_data_offset_with_maximum_value() {
        // Maximum valid offset: bits 9..=55 all set
        let offset = ClusterOffset(BME_TABLE_OFFSET_MASK);
        let entry = BitmapTableEntry::with_data_offset(offset);
        assert_eq!(entry.state(), BitmapTableEntryState::Data(offset));
    }

    #[test]
    fn entry_data_offset_minimum_nonzero() {
        // Minimum nonzero cluster-aligned offset: bit 9 set = 0x200
        let offset = ClusterOffset(0x200);
        let entry = BitmapTableEntry::with_data_offset(offset);
        assert_eq!(entry.state(), BitmapTableEntryState::Data(offset));
    }

    #[test]
    fn table_large_entry_count() {
        // Hundreds of entries
        let count = 500;
        let table = BitmapTable::new_all_zeros(count);
        assert_eq!(table.len(), count);

        let mut buf = vec![0u8; count as usize * BITMAP_TABLE_ENTRY_SIZE];
        table.write_to(&mut buf).unwrap();
        let parsed = BitmapTable::read_from(&buf, count).unwrap();
        assert_eq!(parsed.len(), count);
    }

    #[test]
    fn entry_all_ones_flag_only_when_offset_zero() {
        // bit 0 set but with nonzero offset = Data, not AllOnes
        let raw = BME_TABLE_OFFSET_MASK | BME_TABLE_ALL_ONES_FLAG;
        let entry = BitmapTableEntry::from_raw(raw);
        // Should be Data, not AllOnes (all-ones flag only valid when offset = 0)
        match entry.state() {
            BitmapTableEntryState::Data(_) => {}
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn directory_entry_all_flags_set() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: BME_FLAG_IN_USE | BME_FLAG_AUTO | BME_FLAG_EXTRA_DATA_COMPATIBLE,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: "all-flags".into(),
            extra_data: Vec::new(),
        };

        assert!(entry.is_in_use());
        assert!(entry.is_auto());

        let mut buf = Vec::new();
        entry.write_to(&mut buf);
        let (parsed, _) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.flags, entry.flags);
    }

    #[test]
    fn directory_entry_granularity_min_max() {
        let min = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: 0,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: BITMAP_MIN_GRANULARITY_BITS,
            name: "min".into(),
            extra_data: Vec::new(),
        };
        assert_eq!(min.granularity(), 512); // 1 << 9

        let max = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: 0,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: BITMAP_MAX_GRANULARITY_BITS,
            name: "max".into(),
            extra_data: Vec::new(),
        };
        assert_eq!(max.granularity(), 1u64 << 31); // 2 GiB
    }

    #[test]
    fn table_overwrite_entry_preserves_others() {
        let mut table = BitmapTable::new_all_zeros(4);
        table
            .set(BitmapIndex(1), BitmapTableEntry::all_ones())
            .unwrap();
        table
            .set(
                BitmapIndex(2),
                BitmapTableEntry::with_data_offset(ClusterOffset(0x10000)),
            )
            .unwrap();

        // Entry 0 and 3 still zeros
        assert_eq!(
            table.get(BitmapIndex(0)).unwrap().state(),
            BitmapTableEntryState::AllZeros
        );
        assert_eq!(
            table.get(BitmapIndex(3)).unwrap().state(),
            BitmapTableEntryState::AllZeros
        );
        // 1 is ones, 2 is data
        assert_eq!(
            table.get(BitmapIndex(1)).unwrap().state(),
            BitmapTableEntryState::AllOnes
        );
        assert_eq!(
            table.get(BitmapIndex(2)).unwrap().state(),
            BitmapTableEntryState::Data(ClusterOffset(0x10000))
        );

        // Now overwrite 1 back to zeros
        table
            .set(BitmapIndex(1), BitmapTableEntry::all_zeros())
            .unwrap();
        assert_eq!(
            table.get(BitmapIndex(1)).unwrap().state(),
            BitmapTableEntryState::AllZeros
        );
        // 2 unchanged
        assert_eq!(
            table.get(BitmapIndex(2)).unwrap().state(),
            BitmapTableEntryState::Data(ClusterOffset(0x10000))
        );
    }

    #[test]
    fn directory_entry_with_large_extra_data() {
        let entry = BitmapDirectoryEntry {
            bitmap_table_offset: ClusterOffset(0x10000),
            bitmap_table_size: 1,
            flags: BME_FLAG_EXTRA_DATA_COMPATIBLE,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits: 16,
            name: "with-extra".into(),
            extra_data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf);
        let (parsed, _) = BitmapDirectoryEntry::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.extra_data, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(parsed.name, "with-extra");
    }

    #[test]
    fn extension_write_round_trip_preserves_all_fields() {
        let ext = BitmapExtension {
            nb_bitmaps: 42,
            bitmap_directory_size: 8192,
            bitmap_directory_offset: 0x1234_5678_0000,
        };

        let data = ext.write_to();
        let parsed = BitmapExtension::read_from(&data).unwrap();
        assert_eq!(parsed.nb_bitmaps, 42);
        assert_eq!(parsed.bitmap_directory_size, 8192);
        assert_eq!(parsed.bitmap_directory_offset, 0x1234_5678_0000);
    }
}
