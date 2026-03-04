//! BLAKE3 per-cluster hash extension parsing.
//!
//! A custom QCOW2 header extension that stores BLAKE3 hashes for each
//! allocated cluster. Uses a two-level structure: a hash table (Level 1)
//! pointing to hash data clusters (Level 2), similar to bitmap tables.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::constants::*;

/// Parsed BLAKE3 hash extension header (24 bytes in the header extension area).
///
/// Points to a hash table stored in separate cluster(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blake3Extension {
    /// Cluster-aligned offset of the hash table in the image file.
    pub hash_table_offset: u64,
    /// Number of u64 entries in the hash table.
    pub hash_table_entries: u32,
    /// Hash size in bytes (16 or 32).
    pub hash_size: u8,
}

impl Blake3Extension {
    /// Parse the extension from raw bytes (must be exactly 24 bytes).
    pub fn read_from(data: &[u8]) -> Result<Self> {
        if data.len() < BLAKE3_EXTENSION_DATA_SIZE {
            return Err(Error::InvalidHashExtension {
                message: format!(
                    "extension data too short: expected {} bytes, got {}",
                    BLAKE3_EXTENSION_DATA_SIZE,
                    data.len()
                ),
            });
        }

        let hash_table_offset = BigEndian::read_u64(&data[0..]);
        let hash_table_entries = BigEndian::read_u32(&data[8..]);
        let hash_size = data[12];

        // Validate hash_size
        if hash_size != BLAKE3_MIN_HASH_SIZE && hash_size != BLAKE3_MAX_HASH_SIZE {
            return Err(Error::InvalidHashSize { size: hash_size });
        }

        // Validate alignment (offset must be cluster-aligned, bits 0-8 must be 0)
        if hash_table_offset != 0 && (hash_table_offset & 0x1FF) != 0 {
            return Err(Error::HashTableMisaligned {
                offset: hash_table_offset,
            });
        }

        // Validate reserved fields are zero
        if data[13] != 0 || data[14] != 0 || data[15] != 0 {
            return Err(Error::InvalidHashExtension {
                message: "reserved bytes 13-15 must be zero".to_string(),
            });
        }
        let reserved2 = BigEndian::read_u64(&data[16..]);
        if reserved2 != 0 {
            return Err(Error::InvalidHashExtension {
                message: "reserved bytes 16-23 must be zero".to_string(),
            });
        }

        Ok(Self {
            hash_table_offset,
            hash_table_entries,
            hash_size,
        })
    }

    /// Serialize the extension to a 24-byte vector.
    pub fn write_to(&self) -> Vec<u8> {
        let mut buf = vec![0u8; BLAKE3_EXTENSION_DATA_SIZE];
        BigEndian::write_u64(&mut buf[0..], self.hash_table_offset);
        BigEndian::write_u32(&mut buf[8..], self.hash_table_entries);
        buf[12] = self.hash_size;
        // bytes 13-15: reserved (already zero)
        // bytes 16-23: reserved (already zero)
        buf
    }
}

/// A single entry in the hash table (Level 1).
///
/// Either empty (0) or a cluster-aligned offset to a hash data cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashTableEntry(u64);

impl HashTableEntry {
    /// Create an entry from a raw u64 value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw u64 value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Create an empty entry (no hash data cluster).
    pub fn empty() -> Self {
        Self(0)
    }

    /// Create an entry pointing to a hash data cluster.
    pub fn with_offset(offset: u64) -> Self {
        Self(offset)
    }

    /// Returns the data cluster offset, or `None` if the entry is empty.
    pub fn data_offset(self) -> Option<u64> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0)
        }
    }

    /// Whether this entry is empty (no hash data cluster allocated).
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The hash table: an array of entries pointing to hash data clusters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashTable {
    entries: Vec<HashTableEntry>,
}

impl HashTable {
    /// Parse a hash table from bytes.
    pub fn read_from(bytes: &[u8], entry_count: u32) -> Result<Self> {
        let expected_size = entry_count as usize * HASH_TABLE_ENTRY_SIZE;
        if bytes.len() < expected_size {
            return Err(Error::BufferTooSmall {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut entries = Vec::with_capacity(entry_count as usize);
        for i in 0..entry_count as usize {
            let offset = i * HASH_TABLE_ENTRY_SIZE;
            let raw = BigEndian::read_u64(&bytes[offset..]);
            entries.push(HashTableEntry::from_raw(raw));
        }

        Ok(Self { entries })
    }

    /// Serialize the hash table to a byte vector.
    pub fn write_to(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.entries.len() * HASH_TABLE_ENTRY_SIZE];
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i * HASH_TABLE_ENTRY_SIZE;
            BigEndian::write_u64(&mut buf[offset..], entry.raw());
        }
        buf
    }

    /// Create a new all-empty hash table with the given number of entries.
    pub fn new_empty(entry_count: u32) -> Self {
        Self {
            entries: vec![HashTableEntry::empty(); entry_count as usize],
        }
    }

    /// Get the entry at the given index.
    pub fn get(&self, index: u32) -> Option<&HashTableEntry> {
        self.entries.get(index as usize)
    }

    /// Set the entry at the given index.
    pub fn set(&mut self, index: u32, entry: HashTableEntry) {
        if let Some(slot) = self.entries.get_mut(index as usize) {
            *slot = entry;
        }
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
    pub fn iter(&self) -> impl Iterator<Item = &HashTableEntry> {
        self.entries.iter()
    }
}

/// Compute the number of hash table entries needed for a given image configuration.
pub fn compute_hash_table_entries(virtual_size: u64, cluster_size: u64, hash_size: u8) -> u32 {
    if virtual_size == 0 {
        return 0;
    }
    let total_clusters = (virtual_size + cluster_size - 1) / cluster_size;
    let hashes_per_data_cluster = cluster_size / hash_size as u64;
    let entries = (total_clusters + hashes_per_data_cluster - 1) / hashes_per_data_cluster;
    entries as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Blake3Extension tests ----

    #[test]
    fn extension_round_trip_32() {
        let ext = Blake3Extension {
            hash_table_offset: 0x10_0000,
            hash_table_entries: 42,
            hash_size: 32,
        };
        let bytes = ext.write_to();
        assert_eq!(bytes.len(), BLAKE3_EXTENSION_DATA_SIZE);
        let parsed = Blake3Extension::read_from(&bytes).unwrap();
        assert_eq!(ext, parsed);
    }

    #[test]
    fn extension_round_trip_16() {
        let ext = Blake3Extension {
            hash_table_offset: 0x20_0000,
            hash_table_entries: 8192,
            hash_size: 16,
        };
        let bytes = ext.write_to();
        let parsed = Blake3Extension::read_from(&bytes).unwrap();
        assert_eq!(ext, parsed);
    }

    #[test]
    fn extension_rejects_short_data() {
        let data = vec![0u8; 20]; // too short
        assert!(matches!(
            Blake3Extension::read_from(&data),
            Err(Error::InvalidHashExtension { .. })
        ));
    }

    #[test]
    fn extension_rejects_invalid_hash_size() {
        let mut data = vec![0u8; 24];
        BigEndian::write_u64(&mut data[0..], 0x1_0000); // aligned offset
        BigEndian::write_u32(&mut data[8..], 1);
        data[12] = 24; // invalid hash_size
        assert!(matches!(
            Blake3Extension::read_from(&data),
            Err(Error::InvalidHashSize { size: 24 })
        ));
    }

    #[test]
    fn extension_rejects_misaligned_offset() {
        let mut data = vec![0u8; 24];
        BigEndian::write_u64(&mut data[0..], 0x1_0001); // not aligned
        BigEndian::write_u32(&mut data[8..], 1);
        data[12] = 32;
        assert!(matches!(
            Blake3Extension::read_from(&data),
            Err(Error::HashTableMisaligned { .. })
        ));
    }

    #[test]
    fn extension_allows_zero_offset() {
        // Zero offset is valid (hash table not yet allocated)
        let mut data = vec![0u8; 24];
        BigEndian::write_u32(&mut data[8..], 0);
        data[12] = 32;
        let ext = Blake3Extension::read_from(&data).unwrap();
        assert_eq!(ext.hash_table_offset, 0);
        assert_eq!(ext.hash_table_entries, 0);
    }

    #[test]
    fn extension_rejects_nonzero_reserved() {
        let mut data = vec![0u8; 24];
        data[12] = 32;
        data[13] = 1; // reserved byte not zero
        assert!(matches!(
            Blake3Extension::read_from(&data),
            Err(Error::InvalidHashExtension { .. })
        ));
    }

    #[test]
    fn extension_rejects_nonzero_reserved2() {
        let mut data = vec![0u8; 24];
        data[12] = 32;
        BigEndian::write_u64(&mut data[16..], 1); // reserved u64 not zero
        assert!(matches!(
            Blake3Extension::read_from(&data),
            Err(Error::InvalidHashExtension { .. })
        ));
    }

    // ---- HashTableEntry tests ----

    #[test]
    fn entry_empty() {
        let entry = HashTableEntry::empty();
        assert!(entry.is_empty());
        assert_eq!(entry.data_offset(), None);
        assert_eq!(entry.raw(), 0);
    }

    #[test]
    fn entry_with_offset() {
        let entry = HashTableEntry::with_offset(0x5_0000);
        assert!(!entry.is_empty());
        assert_eq!(entry.data_offset(), Some(0x5_0000));
        assert_eq!(entry.raw(), 0x5_0000);
    }

    #[test]
    fn entry_from_raw_round_trip() {
        let raw = 0xDEAD_BEEF_0000u64;
        let entry = HashTableEntry::from_raw(raw);
        assert_eq!(entry.raw(), raw);
    }

    // ---- HashTable tests ----

    #[test]
    fn table_new_empty() {
        let table = HashTable::new_empty(16);
        assert_eq!(table.len(), 16);
        for entry in table.iter() {
            assert!(entry.is_empty());
        }
    }

    #[test]
    fn table_round_trip() {
        let mut table = HashTable::new_empty(4);
        table.set(0, HashTableEntry::with_offset(0x1_0000));
        table.set(2, HashTableEntry::with_offset(0x2_0000));

        let bytes = table.write_to();
        assert_eq!(bytes.len(), 4 * HASH_TABLE_ENTRY_SIZE);

        let parsed = HashTable::read_from(&bytes, 4).unwrap();
        assert_eq!(table, parsed);
        assert_eq!(parsed.get(0).unwrap().data_offset(), Some(0x1_0000));
        assert!(parsed.get(1).unwrap().is_empty());
        assert_eq!(parsed.get(2).unwrap().data_offset(), Some(0x2_0000));
        assert!(parsed.get(3).unwrap().is_empty());
    }

    #[test]
    fn table_read_rejects_short_buffer() {
        let buf = vec![0u8; 16]; // only 2 entries
        assert!(matches!(
            HashTable::read_from(&buf, 4),
            Err(Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn table_get_out_of_bounds() {
        let table = HashTable::new_empty(2);
        assert!(table.get(2).is_none());
        assert!(table.get(100).is_none());
    }

    #[test]
    fn table_set_out_of_bounds_is_noop() {
        let mut table = HashTable::new_empty(2);
        table.set(5, HashTableEntry::with_offset(0x1_0000));
        // Should not panic, entry is not stored
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn table_zero_entries() {
        let table = HashTable::new_empty(0);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.write_to().len(), 0);
    }

    // ---- compute_hash_table_entries tests ----

    #[test]
    fn compute_entries_1tb_64k_32b() {
        // 1 TB image, 64 KB clusters, 32 byte hashes
        let entries = compute_hash_table_entries(1 << 40, 1 << 16, 32);
        // 16M clusters / 2048 hashes per data cluster = 8192
        assert_eq!(entries, 8192);
    }

    #[test]
    fn compute_entries_1tb_64k_16b() {
        // 1 TB image, 64 KB clusters, 16 byte hashes
        let entries = compute_hash_table_entries(1 << 40, 1 << 16, 16);
        // 16M clusters / 4096 hashes per data cluster = 4096
        assert_eq!(entries, 4096);
    }

    #[test]
    fn compute_entries_1mb_64k() {
        // 1 MB image, 64 KB clusters → 16 clusters
        // hashes_per_data_cluster = 65536 / 32 = 2048
        // 16 / 2048 = 1 (rounded up)
        let entries = compute_hash_table_entries(1 << 20, 1 << 16, 32);
        assert_eq!(entries, 1);
    }

    #[test]
    fn compute_entries_zero_size() {
        assert_eq!(compute_hash_table_entries(0, 1 << 16, 32), 0);
    }

    #[test]
    fn compute_entries_not_cluster_aligned_size() {
        // 100 KB = not a multiple of 64 KB → 2 clusters → 1 entry
        let entries = compute_hash_table_entries(100 * 1024, 1 << 16, 32);
        assert_eq!(entries, 1);
    }
}
