//! Refcount table and refcount block parsing.
//!
//! QCOW2 uses reference counting to track how many L1/L2/snapshot entries
//! point to each cluster. The refcount table is a two-level structure:
//! the refcount table maps cluster groups to refcount blocks, and each
//! refcount block stores individual cluster refcounts.
//!
//! Refcount width is variable in v3 (1, 2, 4, 8, 16, 32, or 64 bits)
//! and fixed at 16 bits in v2.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::types::ClusterOffset;

/// A single refcount table entry (64 bits on disk, big-endian).
///
/// Points to a refcount block or is zero (unallocated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefcountTableEntry(u64);

impl RefcountTableEntry {
    /// Create from a raw 64-bit value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw 64-bit value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Refcount block offset (bits 9..=63), cluster-aligned.
    ///
    /// Returns `None` if the entry is unallocated (offset is zero).
    pub fn block_offset(self) -> Option<ClusterOffset> {
        let offset = self.0 & REFCOUNT_TABLE_OFFSET_MASK;
        if offset == 0 {
            None
        } else {
            Some(ClusterOffset(offset))
        }
    }

    /// Whether this entry is unallocated.
    pub fn is_unallocated(self) -> bool {
        self.0 & REFCOUNT_TABLE_OFFSET_MASK == 0
    }
}

/// A refcount block: one cluster of refcount entries.
///
/// Entry width is `1 << refcount_order` bits (1, 2, 4, 8, 16, 32, or 64).
/// All widths are normalized to `u64` during parsing for uniform access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefcountBlock {
    /// Refcount values, normalized to u64 regardless of on-disk width.
    refcounts: Vec<u64>,
    /// The refcount order used for serialization.
    refcount_order: u32,
}

impl RefcountBlock {
    /// Parse a refcount block from raw bytes.
    ///
    /// The block is one full cluster (`bytes.len()` should equal the cluster size).
    /// The `refcount_order` determines the entry width: `1 << refcount_order` bits.
    pub fn read_from(bytes: &[u8], refcount_order: u32) -> Result<Self> {
        if refcount_order > MAX_REFCOUNT_ORDER {
            return Err(Error::InvalidRefcountOrder {
                order: refcount_order,
                max: MAX_REFCOUNT_ORDER,
            });
        }

        let refcount_bits = 1u32 << refcount_order;
        let entry_count = bytes.len() * 8 / refcount_bits as usize;
        let mut refcounts = Vec::with_capacity(entry_count);

        match refcount_bits {
            1 => {
                for &byte in bytes {
                    for bit in (0..8).rev() {
                        refcounts.push(((byte >> bit) & 1) as u64);
                    }
                }
            }
            2 => {
                for &byte in bytes {
                    for i in 0..4 {
                        let shift = 6 - i * 2;
                        refcounts.push(((byte >> shift) & 0x3) as u64);
                    }
                }
            }
            4 => {
                for &byte in bytes {
                    refcounts.push(((byte >> 4) & 0xF) as u64);
                    refcounts.push((byte & 0xF) as u64);
                }
            }
            8 => {
                for &byte in bytes {
                    refcounts.push(byte as u64);
                }
            }
            16 => {
                for chunk in bytes.chunks_exact(2) {
                    refcounts.push(BigEndian::read_u16(chunk) as u64);
                }
            }
            32 => {
                for chunk in bytes.chunks_exact(4) {
                    refcounts.push(BigEndian::read_u32(chunk) as u64);
                }
            }
            64 => {
                for chunk in bytes.chunks_exact(8) {
                    refcounts.push(BigEndian::read_u64(chunk));
                }
            }
            _ => unreachable!("refcount_order validated above"),
        }

        Ok(Self {
            refcounts,
            refcount_order,
        })
    }

    /// Serialize the refcount block to bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<()> {
        let refcount_bits = 1u32 << self.refcount_order;
        let needed = self.refcounts.len() * refcount_bits as usize / 8;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                expected: needed,
                actual: buf.len(),
            });
        }

        buf[..needed].fill(0);

        match refcount_bits {
            1 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    let byte_idx = i / 8;
                    let bit_idx = 7 - (i % 8);
                    if rc != 0 {
                        buf[byte_idx] |= 1 << bit_idx;
                    }
                }
            }
            2 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    let byte_idx = i / 4;
                    let shift = 6 - (i % 4) * 2;
                    buf[byte_idx] |= ((rc & 0x3) as u8) << shift;
                }
            }
            4 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    let byte_idx = i / 2;
                    if i % 2 == 0 {
                        buf[byte_idx] |= ((rc & 0xF) as u8) << 4;
                    } else {
                        buf[byte_idx] |= (rc & 0xF) as u8;
                    }
                }
            }
            8 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    buf[i] = rc as u8;
                }
            }
            16 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    BigEndian::write_u16(&mut buf[i * 2..], rc as u16);
                }
            }
            32 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    BigEndian::write_u32(&mut buf[i * 4..], rc as u32);
                }
            }
            64 => {
                for (i, &rc) in self.refcounts.iter().enumerate() {
                    BigEndian::write_u64(&mut buf[i * 8..], rc);
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Get the refcount for a given index within this block.
    pub fn get(&self, index: u32) -> Result<u64> {
        self.refcounts
            .get(index as usize)
            .copied()
            .ok_or(Error::RefcountIndexOutOfBounds {
                index,
                block_size: self.refcounts.len() as u32,
            })
    }

    /// Number of entries in this block.
    pub fn len(&self) -> u32 {
        self.refcounts.len() as u32
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.refcounts.is_empty()
    }

    /// The refcount order (for informational purposes).
    pub fn refcount_order(&self) -> u32 {
        self.refcount_order
    }
}

/// Parse a refcount table from raw bytes.
///
/// Returns a vector of [`RefcountTableEntry`] values.
pub fn read_refcount_table(bytes: &[u8], entry_count: u32) -> Result<Vec<RefcountTableEntry>> {
    let expected = entry_count as usize * REFCOUNT_TABLE_ENTRY_SIZE;
    if bytes.len() < expected {
        return Err(Error::BufferTooSmall {
            expected,
            actual: bytes.len(),
        });
    }

    Ok((0..entry_count as usize)
        .map(|i| {
            let raw = BigEndian::read_u64(&bytes[i * REFCOUNT_TABLE_ENTRY_SIZE..]);
            RefcountTableEntry::from_raw(raw)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- RefcountTableEntry tests ----

    #[test]
    fn table_entry_unallocated() {
        let entry = RefcountTableEntry::from_raw(0);
        assert!(entry.is_unallocated());
        assert_eq!(entry.block_offset(), None);
    }

    #[test]
    fn table_entry_with_offset() {
        let entry = RefcountTableEntry::from_raw(0x10000);
        assert!(!entry.is_unallocated());
        assert_eq!(entry.block_offset(), Some(ClusterOffset(0x10000)));
    }

    // ---- RefcountBlock 16-bit (default) ----

    #[test]
    fn refcount_block_16bit_round_trip() {
        let mut block_data = vec![0u8; 64]; // Small block for testing
        // Set refcount[0] = 1, refcount[1] = 42
        BigEndian::write_u16(&mut block_data[0..], 1);
        BigEndian::write_u16(&mut block_data[2..], 42);

        let block = RefcountBlock::read_from(&block_data, 4).unwrap(); // order=4 => 16-bit
        assert_eq!(block.get(0).unwrap(), 1);
        assert_eq!(block.get(1).unwrap(), 42);
        assert_eq!(block.len(), 32); // 64 bytes / 2 bytes per entry

        let mut buf = vec![0u8; 64];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, block_data);
    }

    // ---- RefcountBlock 1-bit ----

    #[test]
    fn refcount_block_1bit_round_trip() {
        // 4 bytes = 32 entries at 1 bit each
        let data = vec![0b1010_0000, 0b0000_0001, 0, 0];
        let block = RefcountBlock::read_from(&data, 0).unwrap(); // order=0 => 1-bit
        assert_eq!(block.len(), 32);
        assert_eq!(block.get(0).unwrap(), 1); // MSB of first byte
        assert_eq!(block.get(1).unwrap(), 0);
        assert_eq!(block.get(2).unwrap(), 1);
        assert_eq!(block.get(3).unwrap(), 0);
        assert_eq!(block.get(15).unwrap(), 1); // LSB of second byte

        let mut buf = vec![0u8; 4];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- RefcountBlock 2-bit ----

    #[test]
    fn refcount_block_2bit_round_trip() {
        // 2 bytes = 8 entries at 2 bits each
        let data = vec![0b11_10_01_00, 0b00_01_10_11];
        let block = RefcountBlock::read_from(&data, 1).unwrap(); // order=1 => 2-bit
        assert_eq!(block.len(), 8);
        assert_eq!(block.get(0).unwrap(), 3); // 0b11
        assert_eq!(block.get(1).unwrap(), 2); // 0b10
        assert_eq!(block.get(2).unwrap(), 1); // 0b01
        assert_eq!(block.get(3).unwrap(), 0); // 0b00
        assert_eq!(block.get(4).unwrap(), 0);
        assert_eq!(block.get(5).unwrap(), 1);
        assert_eq!(block.get(6).unwrap(), 2);
        assert_eq!(block.get(7).unwrap(), 3);

        let mut buf = vec![0u8; 2];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- RefcountBlock 4-bit ----

    #[test]
    fn refcount_block_4bit_round_trip() {
        let data = vec![0xA5, 0x3C]; // entries: 10, 5, 3, 12
        let block = RefcountBlock::read_from(&data, 2).unwrap(); // order=2 => 4-bit
        assert_eq!(block.len(), 4);
        assert_eq!(block.get(0).unwrap(), 0xA);
        assert_eq!(block.get(1).unwrap(), 0x5);
        assert_eq!(block.get(2).unwrap(), 0x3);
        assert_eq!(block.get(3).unwrap(), 0xC);

        let mut buf = vec![0u8; 2];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- RefcountBlock 8-bit ----

    #[test]
    fn refcount_block_8bit_round_trip() {
        let data = vec![0, 1, 42, 255];
        let block = RefcountBlock::read_from(&data, 3).unwrap(); // order=3 => 8-bit
        assert_eq!(block.len(), 4);
        assert_eq!(block.get(0).unwrap(), 0);
        assert_eq!(block.get(1).unwrap(), 1);
        assert_eq!(block.get(2).unwrap(), 42);
        assert_eq!(block.get(3).unwrap(), 255);

        let mut buf = vec![0u8; 4];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- RefcountBlock 32-bit ----

    #[test]
    fn refcount_block_32bit_round_trip() {
        let mut data = vec![0u8; 8];
        BigEndian::write_u32(&mut data[0..], 100);
        BigEndian::write_u32(&mut data[4..], 200);

        let block = RefcountBlock::read_from(&data, 5).unwrap(); // order=5 => 32-bit
        assert_eq!(block.len(), 2);
        assert_eq!(block.get(0).unwrap(), 100);
        assert_eq!(block.get(1).unwrap(), 200);

        let mut buf = vec![0u8; 8];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- RefcountBlock 64-bit ----

    #[test]
    fn refcount_block_64bit_round_trip() {
        let mut data = vec![0u8; 16];
        BigEndian::write_u64(&mut data[0..], 1_000_000);
        BigEndian::write_u64(&mut data[8..], u64::MAX);

        let block = RefcountBlock::read_from(&data, 6).unwrap(); // order=6 => 64-bit
        assert_eq!(block.len(), 2);
        assert_eq!(block.get(0).unwrap(), 1_000_000);
        assert_eq!(block.get(1).unwrap(), u64::MAX);

        let mut buf = vec![0u8; 16];
        block.write_to(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ---- Error cases ----

    #[test]
    fn invalid_refcount_order() {
        let data = vec![0u8; 16];
        match RefcountBlock::read_from(&data, 7) {
            Err(Error::InvalidRefcountOrder { order: 7, max: 6 }) => {}
            other => panic!("expected InvalidRefcountOrder, got {other:?}"),
        }
    }

    #[test]
    fn get_out_of_bounds() {
        let data = vec![0u8; 4];
        let block = RefcountBlock::read_from(&data, 4).unwrap(); // 2 entries (16-bit)
        match block.get(5) {
            Err(Error::RefcountIndexOutOfBounds { .. }) => {}
            other => panic!("expected RefcountIndexOutOfBounds, got {other:?}"),
        }
    }

    // ---- Entries per cluster arithmetic ----

    #[test]
    fn entries_per_cluster_16bit() {
        // 65536-byte cluster / 2 bytes per entry = 32768 entries
        let data = vec![0u8; 65536];
        let block = RefcountBlock::read_from(&data, 4).unwrap();
        assert_eq!(block.len(), 32768);
    }

    // ---- Refcount table parsing ----

    #[test]
    fn read_refcount_table_round_trip() {
        let mut buf = vec![0u8; 3 * REFCOUNT_TABLE_ENTRY_SIZE];
        BigEndian::write_u64(&mut buf[0..], 0x10000);
        BigEndian::write_u64(&mut buf[8..], 0);
        BigEndian::write_u64(&mut buf[16..], 0x20000);

        let entries = read_refcount_table(&buf, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].block_offset(), Some(ClusterOffset(0x10000)));
        assert!(entries[1].is_unallocated());
        assert_eq!(entries[2].block_offset(), Some(ClusterOffset(0x20000)));
    }

    // ---- Edge cases ----

    #[test]
    fn max_refcount_per_width() {
        // Each width has a different maximum value. Verify round-trip at max.
        let cases: &[(u32, u64)] = &[
            (0, 1),          // 1-bit: max = 1
            (1, 3),          // 2-bit: max = 3
            (2, 15),         // 4-bit: max = 15
            (3, 255),        // 8-bit: max = 255
            (4, 65535),      // 16-bit: max = 65535
            (5, u32::MAX as u64), // 32-bit: max = 4294967295
            (6, u64::MAX),   // 64-bit: max = u64::MAX
        ];

        for &(order, max_value) in cases {
            let refcount_bits = 1u32 << order;
            let byte_size = (refcount_bits as usize + 7) / 8;
            // At least one entry
            let buf_size = byte_size.max(1);
            let mut data = vec![0u8; buf_size];

            // Write the maximum value into the first entry
            match refcount_bits {
                1 => data[0] = 0x80, // MSB set
                2 => data[0] = 0xC0, // top 2 bits set
                4 => data[0] = 0xF0, // top nibble all 1s
                8 => data[0] = 0xFF,
                16 => BigEndian::write_u16(&mut data, 0xFFFF),
                32 => BigEndian::write_u32(&mut data, u32::MAX),
                64 => BigEndian::write_u64(&mut data, u64::MAX),
                _ => unreachable!(),
            }

            let block = RefcountBlock::read_from(&data, order).unwrap();
            assert_eq!(
                block.get(0).unwrap(),
                max_value,
                "order={order}, bits={refcount_bits}"
            );

            // Round-trip
            let mut out = vec![0u8; buf_size];
            block.write_to(&mut out).unwrap();
            assert_eq!(out, data, "round-trip failed for order={order}");
        }
    }

    #[test]
    fn table_entry_reserved_bits_in_low_9() {
        // Bits 0-8 are reserved in RefcountTableEntry. The offset mask
        // strips them, so only bits 9+ matter for the offset.
        let raw = 0x10000u64 | 0x1FF; // offset=0x10000 with low 9 bits set
        let entry = RefcountTableEntry::from_raw(raw);
        // block_offset should mask out the low bits
        assert_eq!(entry.block_offset(), Some(ClusterOffset(0x10000)));
        // raw() preserves the original value
        assert_eq!(entry.raw(), raw);
    }

    #[test]
    fn refcount_block_1bit_all_ones() {
        // All clusters referenced (every bit = 1)
        let data = vec![0xFF; 4]; // 32 entries, all 1
        let block = RefcountBlock::read_from(&data, 0).unwrap();
        assert_eq!(block.len(), 32);
        for i in 0..32 {
            assert_eq!(block.get(i).unwrap(), 1, "entry {i} should be 1");
        }

        let mut out = vec![0u8; 4];
        block.write_to(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn write_to_buffer_too_small() {
        let data = vec![0u8; 4];
        let block = RefcountBlock::read_from(&data, 4).unwrap(); // 2 entries (16-bit)
        let mut small_buf = vec![0u8; 2]; // needs 4 bytes
        match block.write_to(&mut small_buf) {
            Err(Error::BufferTooSmall {
                expected: 4,
                actual: 2,
            }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn read_refcount_table_buffer_too_small() {
        let buf = vec![0u8; 8]; // only 1 entry worth of data
        match read_refcount_table(&buf, 2) {
            // asking for 2 entries = 16 bytes
            Err(Error::BufferTooSmall {
                expected: 16,
                actual: 8,
            }) => {}
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn refcount_block_empty_buffer() {
        // A zero-length buffer should produce a block with 0 entries.
        let data: Vec<u8> = vec![];
        let block = RefcountBlock::read_from(&data, 4).unwrap(); // 16-bit
        assert_eq!(block.len(), 0);
        assert!(block.is_empty());
    }
}
