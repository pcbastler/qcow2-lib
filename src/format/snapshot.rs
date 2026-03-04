//! QCOW2 snapshot header parsing.
//!
//! Snapshot entries are stored as a variable-length table at the offset
//! given in the main header. Each entry has fixed-length fields followed
//! by variable-length ID and name strings, padded to an 8-byte boundary.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::types::ClusterOffset;

/// Fixed-size portion of a snapshot header (before variable-length strings).
const SNAPSHOT_FIXED_SIZE: usize = 40;

/// Parsed QCOW2 snapshot header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// Host file offset of this snapshot's L1 table copy.
    pub l1_table_offset: ClusterOffset,
    /// Number of entries in this snapshot's L1 table.
    pub l1_table_entries: u32,
    /// Unique snapshot ID (numeric string, e.g., "1", "2").
    pub unique_id: String,
    /// Human-readable snapshot name.
    pub name: String,
    /// Seconds since epoch when the snapshot was taken.
    pub timestamp_seconds: u32,
    /// Nanosecond component of the timestamp.
    pub timestamp_nanoseconds: u32,
    /// Total guest CPU time in nanoseconds at snapshot time.
    pub vm_clock_nanoseconds: u64,
    /// Size of VM state data associated with the snapshot.
    pub vm_state_size: u64,
    /// Virtual disk size at snapshot time (from extra data, if available).
    pub virtual_disk_size: Option<u64>,
    /// Hash table offset for this snapshot's BLAKE3 hashes (from extra data, if available).
    pub hash_table_offset: Option<u64>,
    /// Number of hash table entries for this snapshot (from extra data, if available).
    pub hash_table_entries: Option<u32>,
    /// Hash size in bytes for this snapshot (from extra data, if available).
    pub hash_size: Option<u8>,
    /// Hash chunk bits for this snapshot (from extra data byte 29, if available).
    pub hash_chunk_bits: Option<u8>,
    /// Size of extra data that was present on disk.
    pub extra_data_size: u32,
}

impl SnapshotHeader {
    /// Parse a single snapshot entry from a byte slice.
    ///
    /// Returns `(header, bytes_consumed)` where `bytes_consumed` includes
    /// padding to the next 8-byte boundary.
    pub fn read_from(bytes: &[u8], base_offset: u64) -> Result<(Self, usize)> {
        if bytes.len() < SNAPSHOT_FIXED_SIZE {
            return Err(Error::SnapshotTruncated {
                offset: base_offset,
                expected: SNAPSHOT_FIXED_SIZE,
                actual: bytes.len(),
            });
        }

        let l1_table_offset = ClusterOffset(BigEndian::read_u64(&bytes[0..]));
        let l1_table_entries = BigEndian::read_u32(&bytes[8..]);
        let id_str_size = BigEndian::read_u16(&bytes[12..]) as usize;
        let name_size = BigEndian::read_u16(&bytes[14..]) as usize;
        let timestamp_seconds = BigEndian::read_u32(&bytes[16..]);
        let timestamp_nanoseconds = BigEndian::read_u32(&bytes[20..]);
        let vm_clock_nanoseconds = BigEndian::read_u64(&bytes[24..]);
        let vm_state_size_32 = BigEndian::read_u32(&bytes[32..]) as u64;
        let extra_data_size = BigEndian::read_u32(&bytes[36..]);

        // Read extra data fields
        let extra_start = SNAPSHOT_FIXED_SIZE;
        let extra_end = extra_start
            .checked_add(extra_data_size as usize)
            .ok_or(Error::ArithmeticOverflow {
                context: "snapshot extra_data_size",
            })?;

        if bytes.len() < extra_end {
            return Err(Error::SnapshotTruncated {
                offset: base_offset,
                expected: extra_end,
                actual: bytes.len(),
            });
        }

        // If extra_data_size >= 8, use the 64-bit vm_state_size
        let vm_state_size = if extra_data_size >= 8 {
            BigEndian::read_u64(&bytes[extra_start..])
        } else {
            vm_state_size_32
        };

        // If extra_data_size >= 16, read virtual_disk_size
        let virtual_disk_size = if extra_data_size >= 16 {
            Some(BigEndian::read_u64(&bytes[extra_start + 8..]))
        } else {
            None
        };

        // If extra_data_size >= 32, read BLAKE3 hash table fields
        let (hash_table_offset, hash_table_entries, hash_size, hash_chunk_bits) =
            if extra_data_size >= 32 {
                let ht_offset = BigEndian::read_u64(&bytes[extra_start + 16..]);
                let ht_entries = BigEndian::read_u32(&bytes[extra_start + 24..]);
                let hs = bytes[extra_start + 28];
                let hcb = bytes[extra_start + 29];
                if ht_offset != 0 {
                    (Some(ht_offset), Some(ht_entries), Some(hs), Some(hcb))
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        // Variable-length strings follow extra data
        let strings_start = extra_end;
        let id_end = strings_start
            .checked_add(id_str_size)
            .ok_or(Error::ArithmeticOverflow {
                context: "snapshot id_str_size",
            })?;
        let name_end = id_end
            .checked_add(name_size)
            .ok_or(Error::ArithmeticOverflow {
                context: "snapshot name_size",
            })?;

        if bytes.len() < name_end {
            return Err(Error::SnapshotTruncated {
                offset: base_offset,
                expected: name_end,
                actual: bytes.len(),
            });
        }

        let unique_id =
            String::from_utf8_lossy(&bytes[strings_start..id_end]).into_owned();
        let name = String::from_utf8_lossy(&bytes[id_end..name_end]).into_owned();

        // Total consumed = name_end padded to 8-byte boundary
        let padded = name_end.checked_add(7).ok_or(Error::ArithmeticOverflow {
            context: "snapshot padding",
        })?;
        let consumed = padded & !7;

        Ok((
            Self {
                l1_table_offset,
                l1_table_entries,
                unique_id,
                name,
                timestamp_seconds,
                timestamp_nanoseconds,
                vm_clock_nanoseconds,
                vm_state_size,
                virtual_disk_size,
                hash_table_offset,
                hash_table_entries,
                hash_size,
                hash_chunk_bits,
                extra_data_size,
            },
            consumed,
        ))
    }

    /// Parse the entire snapshot table.
    pub fn read_table(bytes: &[u8], count: u32, base_offset: u64) -> Result<Vec<Self>> {
        let mut snapshots = Vec::with_capacity(count as usize);
        let mut pos = 0;

        for _ in 0..count {
            let (snapshot, consumed) =
                Self::read_from(&bytes[pos..], base_offset + pos as u64)?;
            snapshots.push(snapshot);
            pos = pos
                .checked_add(consumed)
                .ok_or(Error::ArithmeticOverflow {
                    context: "snapshot table position",
                })?;
        }

        Ok(snapshots)
    }

    /// Serialize a single snapshot entry to a byte vector.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        let id_bytes = self.unique_id.as_bytes();
        let name_bytes = self.name.as_bytes();

        // Fixed fields
        let mut fixed = [0u8; SNAPSHOT_FIXED_SIZE];
        BigEndian::write_u64(&mut fixed[0..], self.l1_table_offset.0);
        BigEndian::write_u32(&mut fixed[8..], self.l1_table_entries);
        BigEndian::write_u16(&mut fixed[12..], id_bytes.len() as u16);
        BigEndian::write_u16(&mut fixed[14..], name_bytes.len() as u16);
        BigEndian::write_u32(&mut fixed[16..], self.timestamp_seconds);
        BigEndian::write_u32(&mut fixed[20..], self.timestamp_nanoseconds);
        BigEndian::write_u64(&mut fixed[24..], self.vm_clock_nanoseconds);
        BigEndian::write_u32(&mut fixed[32..], self.vm_state_size as u32);
        BigEndian::write_u32(&mut fixed[36..], self.extra_data_size);
        out.extend_from_slice(&fixed);

        // Extra data
        if self.extra_data_size >= 8 {
            let mut extra = vec![0u8; self.extra_data_size as usize];
            BigEndian::write_u64(&mut extra[0..], self.vm_state_size);
            if self.extra_data_size >= 16 {
                if let Some(vds) = self.virtual_disk_size {
                    BigEndian::write_u64(&mut extra[8..], vds);
                }
            }
            if self.extra_data_size >= 32 {
                if let Some(ht_offset) = self.hash_table_offset {
                    BigEndian::write_u64(&mut extra[16..], ht_offset);
                    BigEndian::write_u32(
                        &mut extra[24..],
                        self.hash_table_entries.unwrap_or(0),
                    );
                    extra[28] = self.hash_size.unwrap_or(0);
                    extra[29] = self.hash_chunk_bits.unwrap_or(0);
                }
            }
            out.extend_from_slice(&extra);
        }

        // Variable-length strings
        out.extend_from_slice(id_bytes);
        out.extend_from_slice(name_bytes);

        // Pad to 8-byte boundary
        let total = SNAPSHOT_FIXED_SIZE
            + self.extra_data_size as usize
            + id_bytes.len()
            + name_bytes.len();
        let padding = (8 - (total % 8)) % 8;
        out.resize(out.len() + padding, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_snapshot() -> SnapshotHeader {
        SnapshotHeader {
            l1_table_offset: ClusterOffset(0x5_0000),
            l1_table_entries: 8,
            unique_id: "1".to_string(),
            name: "test-snap".to_string(),
            timestamp_seconds: 1700000000,
            timestamp_nanoseconds: 123456,
            vm_clock_nanoseconds: 5_000_000_000,
            vm_state_size: 0,
            virtual_disk_size: None,
            hash_table_offset: None,
            hash_table_entries: None,
            hash_size: None,
            hash_chunk_bits: None,
            extra_data_size: 0,
        }
    }

    #[test]
    fn round_trip_minimal_snapshot() {
        let original = make_test_snapshot();
        let mut buf = Vec::new();
        original.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(consumed % 8, 0, "consumed should be 8-byte aligned");
    }

    #[test]
    fn round_trip_with_extra_data() {
        let original = SnapshotHeader {
            l1_table_offset: ClusterOffset(0x6_0000),
            l1_table_entries: 16,
            unique_id: "2".to_string(),
            name: "snapshot-with-extras".to_string(),
            timestamp_seconds: 1700001000,
            timestamp_nanoseconds: 0,
            vm_clock_nanoseconds: 10_000_000_000,
            vm_state_size: 4096,
            virtual_disk_size: Some(1024 * 1024 * 1024),
            hash_table_offset: None,
            hash_table_entries: None,
            hash_size: None,
            hash_chunk_bits: None,
            extra_data_size: 16,
        };

        let mut buf = Vec::new();
        original.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(consumed % 8, 0);
    }

    #[test]
    fn parse_multiple_snapshots() {
        let snap1 = make_test_snapshot();
        let snap2 = SnapshotHeader {
            unique_id: "2".to_string(),
            name: "second".to_string(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap1.write_to(&mut buf);
        snap2.write_to(&mut buf);

        let table = SnapshotHeader::read_table(&buf, 2, 0).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table[0], snap1);
        assert_eq!(table[1], snap2);
    }

    #[test]
    fn truncated_snapshot_returns_error() {
        let buf = vec![0u8; 20]; // Less than SNAPSHOT_FIXED_SIZE
        match SnapshotHeader::read_from(&buf, 0x1000) {
            Err(Error::SnapshotTruncated { offset: 0x1000, .. }) => {}
            other => panic!("expected SnapshotTruncated, got {other:?}"),
        }
    }

    #[test]
    fn consumed_is_8_byte_aligned() {
        // ID "1" + name "ab" = 3 bytes of strings
        // Fixed 40 + strings 3 = 43, padded to 48
        let snap = SnapshotHeader {
            unique_id: "1".to_string(),
            name: "ab".to_string(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (_, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(consumed % 8, 0, "consumed ({consumed}) should be 8-byte aligned");
    }

    // ---- Edge cases ----

    #[test]
    fn empty_id_string() {
        let snap = SnapshotHeader {
            unique_id: String::new(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.unique_id, "");
        assert_eq!(consumed % 8, 0);
    }

    #[test]
    fn empty_name_string() {
        let snap = SnapshotHeader {
            name: String::new(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.name, "");
        assert_eq!(consumed % 8, 0);
    }

    #[test]
    fn both_strings_empty() {
        let snap = SnapshotHeader {
            unique_id: String::new(),
            name: String::new(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(parsed, snap);
        // Fixed 40 + 0 strings = 40 → padded to 40 (already 8-aligned)
        assert_eq!(consumed, 40);
    }

    #[test]
    fn long_name_255_chars() {
        let long_name = "x".repeat(255);
        let snap = SnapshotHeader {
            name: long_name.clone(),
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.name, long_name);
        assert_eq!(consumed % 8, 0);
    }

    #[test]
    fn extra_data_size_8_gives_64bit_vm_state() {
        let snap = SnapshotHeader {
            vm_state_size: 0x1_0000_0000, // > u32::MAX, needs 64-bit
            extra_data_size: 8,
            virtual_disk_size: None,
            ..make_test_snapshot()
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        let (parsed, _) = SnapshotHeader::read_from(&buf, 0).unwrap();
        assert_eq!(parsed.vm_state_size, 0x1_0000_0000);
        assert_eq!(parsed.virtual_disk_size, None);
    }

    #[test]
    fn extra_data_small_odd_sizes() {
        // extra_data_size < 8 means no 64-bit vm_state_size field.
        // The parser falls back to the 32-bit field at offset 32.
        // Build buffers manually since write_to only writes extra data for size >= 8.
        for extra_size in 0..8u32 {
            let mut buf = vec![0u8; 256]; // Plenty of room

            // Fixed fields: l1_table_offset=0x50000, l1_entries=8
            BigEndian::write_u64(&mut buf[0..], 0x5_0000);
            BigEndian::write_u32(&mut buf[8..], 8);
            // id_str_size=1, name_size=1
            BigEndian::write_u16(&mut buf[12..], 1);
            BigEndian::write_u16(&mut buf[14..], 1);
            // vm_state_size (32-bit at offset 32)
            BigEndian::write_u32(&mut buf[32..], 42);
            // extra_data_size
            BigEndian::write_u32(&mut buf[36..], extra_size);
            // extra data bytes (all zeros, which is fine)
            // strings start at 40 + extra_size
            let strings_start = 40 + extra_size as usize;
            buf[strings_start] = b'1';     // id
            buf[strings_start + 1] = b'T'; // name

            let (parsed, consumed) = SnapshotHeader::read_from(&buf, 0).unwrap();
            assert_eq!(consumed % 8, 0, "alignment for extra_data_size={extra_size}");
            assert_eq!(parsed.vm_state_size, 42, "vm_state for extra_data_size={extra_size}");
            assert_eq!(parsed.extra_data_size, extra_size);
        }
    }

    #[test]
    fn reject_overflow_extra_data_size() {
        // extra_data_size set to u32::MAX → SNAPSHOT_FIXED_SIZE + u32::MAX overflows on 32-bit
        // and causes a huge allocation on 64-bit. The checked_add catches it
        // via the truncation check (extra_end > bytes.len()).
        let mut buf = vec![0u8; 256];
        BigEndian::write_u64(&mut buf[0..], 0x5_0000); // l1_table_offset
        BigEndian::write_u32(&mut buf[8..], 8); // l1_table_entries
        BigEndian::write_u16(&mut buf[12..], 1); // id_str_size
        BigEndian::write_u16(&mut buf[14..], 1); // name_size
        BigEndian::write_u32(&mut buf[36..], u32::MAX); // extra_data_size

        let result = SnapshotHeader::read_from(&buf, 0);
        assert!(result.is_err(), "should reject overflowing extra_data_size");
    }

    #[test]
    fn reject_overflow_string_sizes() {
        // Set id_str_size to u16::MAX and name_size to u16::MAX.
        // strings_start + id_str_size + name_size should still be caught
        // by the truncation check even on 64-bit.
        let mut buf = vec![0u8; 256];
        BigEndian::write_u64(&mut buf[0..], 0x5_0000);
        BigEndian::write_u32(&mut buf[8..], 8);
        BigEndian::write_u16(&mut buf[12..], u16::MAX); // id_str_size
        BigEndian::write_u16(&mut buf[14..], u16::MAX); // name_size
        BigEndian::write_u32(&mut buf[36..], 0); // extra_data_size

        let result = SnapshotHeader::read_from(&buf, 0);
        assert!(result.is_err(), "should reject overflowing string sizes");
    }

    #[test]
    fn truncated_at_extra_data() {
        // Build a snapshot claiming extra_data_size=16 but truncate before extra data
        let snap = SnapshotHeader {
            extra_data_size: 16,
            virtual_disk_size: Some(1 << 30),
            ..make_test_snapshot()
        };
        let mut buf = Vec::new();
        snap.write_to(&mut buf);

        // Truncate to just past the fixed header but before extra data ends
        let truncated = &buf[..SNAPSHOT_FIXED_SIZE + 4];
        match SnapshotHeader::read_from(truncated, 0x2000) {
            Err(Error::SnapshotTruncated { offset: 0x2000, .. }) => {}
            other => panic!("expected SnapshotTruncated, got {other:?}"),
        }
    }
}
