//! Two-level cluster address translation.
//!
//! The heart of QCOW2: translates a guest virtual offset into a
//! [`ClusterResolution`] that tells the caller where to find (or not find)
//! the actual data.

use crate::engine::cache::MetadataCache;
use crate::error::Result;
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::l1::L1Table;
use crate::format::l2::{L2Entry, L2Table};
use crate::format::types::*;
use crate::io::IoBackend;

/// The result of resolving a guest offset to its physical location.
///
/// This enum drives the reader's main dispatch: each variant requires
/// a different strategy to produce guest data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterResolution {
    /// Data is stored at a specific host offset.
    Allocated {
        /// Host file offset of the start of the cluster.
        host_offset: ClusterOffset,
        /// Byte offset within the cluster where the requested data starts.
        intra_cluster_offset: IntraClusterOffset,
    },

    /// The cluster reads as all zeros.
    Zero,

    /// The cluster is not allocated in this image; check the backing file.
    Unallocated,

    /// The cluster data is compressed.
    Compressed {
        /// Decoded compressed cluster descriptor.
        descriptor: CompressedClusterDescriptor,
        /// Byte offset within the decompressed cluster.
        intra_cluster_offset: IntraClusterOffset,
    },
}

/// Resolves guest offsets to physical cluster locations.
///
/// Encapsulates the QCOW2 two-level lookup algorithm:
/// `guest_offset -> L1[i] -> L2_table -> L2[j] -> ClusterResolution`
pub struct ClusterMapper {
    l1_table: L1Table,
    cluster_bits: u32,
    file_size: u64,
}

impl ClusterMapper {
    /// Create a new cluster mapper.
    pub fn new(l1_table: L1Table, cluster_bits: u32, file_size: u64) -> Self {
        Self {
            l1_table,
            cluster_bits,
            file_size,
        }
    }

    /// Resolve a guest offset to a [`ClusterResolution`].
    ///
    /// May perform I/O to load L2 tables that are not in the cache.
    pub fn resolve(
        &self,
        guest_offset: GuestOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<ClusterResolution> {
        let (l1_index, l2_index, intra) = guest_offset.split(self.cluster_bits);

        // Step 1: L1 lookup
        let l1_entry = self.l1_table.get(l1_index)?;
        let l2_offset = match l1_entry.l2_table_offset() {
            Some(offset) => offset,
            None => return Ok(ClusterResolution::Unallocated),
        };

        // Step 2: Load L2 table (cache-first)
        let l2_table = self.load_l2_table(l2_offset, backend, cache)?;

        // Step 3: L2 lookup
        let l2_entry = l2_table.get(l2_index)?;

        // Step 4: Map L2Entry to ClusterResolution
        match l2_entry {
            L2Entry::Unallocated => Ok(ClusterResolution::Unallocated),
            L2Entry::Zero { .. } => Ok(ClusterResolution::Zero),
            L2Entry::Standard { host_offset, .. } => Ok(ClusterResolution::Allocated {
                host_offset,
                intra_cluster_offset: intra,
            }),
            L2Entry::Compressed(descriptor) => Ok(ClusterResolution::Compressed {
                descriptor,
                intra_cluster_offset: intra,
            }),
        }
    }

    /// Load an L2 table, checking the cache first.
    fn load_l2_table(
        &self,
        offset: ClusterOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<L2Table> {
        // Check cache first
        if let Some(table) = cache.get_l2_table(offset) {
            return Ok(table.clone());
        }

        // Validate L2 table offset against file size
        let cluster_size = 1u64 << self.cluster_bits;
        let l2_end = offset
            .0
            .checked_add(cluster_size)
            .ok_or(crate::error::Error::ArithmeticOverflow {
                context: "L2 table offset + cluster_size",
            })?;
        if l2_end > self.file_size {
            return Err(crate::error::Error::MetadataOffsetBeyondEof {
                offset: offset.0,
                size: cluster_size,
                file_size: self.file_size,
                context: "L2 table",
            });
        }

        // Cache miss: read from backend
        let mut buf = vec![0u8; cluster_size as usize];
        backend.read_exact_at(&mut buf, offset.0)?;
        let table = L2Table::read_from(&buf, self.cluster_bits)?;

        // Insert into cache
        cache.insert_l2_table(offset, table.clone());
        Ok(table)
    }

    /// Access the L1 table (for inspection/diagnostics).
    pub fn l1_table(&self) -> &L1Table {
        &self.l1_table
    }

    /// The cluster_bits value used for address decomposition.
    pub fn cluster_bits(&self) -> u32 {
        self.cluster_bits
    }

    /// Read an L1 entry by index.
    pub fn l1_entry(&self, index: L1Index) -> Result<crate::format::l1::L1Entry> {
        self.l1_table.get(index)
    }

    /// Update an L1 entry at the given index.
    pub fn set_l1_entry(
        &mut self,
        index: L1Index,
        entry: crate::format::l1::L1Entry,
    ) -> Result<()> {
        self.l1_table.set(index, entry)
    }

    /// Update the known file size (after extending the image file).
    pub fn set_file_size(&mut self, file_size: u64) {
        self.file_size = file_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cache::CacheConfig;
    use crate::format::constants::*;
    use crate::format::l1::L1Entry;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << 16; // 65536
    const IMAGE_SIZE: u64 = 10 * CLUSTER_SIZE as u64;

    /// Build a minimal QCOW2 image in memory with specific L1/L2 entries.
    fn build_test_image(l2_entries: &[(u32, u64)]) -> (MemoryBackend, L1Table) {
        // Layout:
        // Cluster 0: header (unused in this test)
        // Cluster 1: L1 table
        // Cluster 2: L2 table
        // Cluster 3+: data clusters

        let l1_offset = CLUSTER_SIZE; // cluster 1
        let l2_offset = 2 * CLUSTER_SIZE; // cluster 2

        // Build L1 table with one entry pointing to L2 at cluster 2
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        // Build L2 table
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        for &(index, raw_entry) in l2_entries {
            let offset = index as usize * L2_ENTRY_SIZE;
            BigEndian::write_u64(&mut l2_buf[offset..], raw_entry);
        }

        // Assemble image
        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];
        image_data[l1_offset..l1_offset + l1_buf.len()].copy_from_slice(&l1_buf);
        image_data[l2_offset..l2_offset + CLUSTER_SIZE].copy_from_slice(&l2_buf);

        (MemoryBackend::new(image_data), l1_table)
    }

    #[test]
    fn resolve_unallocated_l1() {
        // L1 entry is zero (unallocated)
        let l1_buf = vec![0u8; L1_ENTRY_SIZE];
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(CLUSTER_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper
            .resolve(GuestOffset(0), &backend, &mut cache)
            .unwrap();
        assert_eq!(result, ClusterResolution::Unallocated);
    }

    #[test]
    fn resolve_standard_allocated() {
        let data_cluster_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_cluster_offset | L2_COPIED_FLAG;
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper
            .resolve(GuestOffset(42), &backend, &mut cache)
            .unwrap();
        assert_eq!(
            result,
            ClusterResolution::Allocated {
                host_offset: ClusterOffset(data_cluster_offset),
                intra_cluster_offset: IntraClusterOffset(42),
            }
        );
    }

    #[test]
    fn resolve_zero_cluster() {
        let l2_raw = L2_ZERO_FLAG;
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper
            .resolve(GuestOffset(100), &backend, &mut cache)
            .unwrap();
        assert_eq!(result, ClusterResolution::Zero);
    }

    #[test]
    fn resolve_unallocated_l2() {
        let (backend, l1_table) = build_test_image(&[]); // All L2 entries are 0
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper
            .resolve(GuestOffset(0), &backend, &mut cache)
            .unwrap();
        assert_eq!(result, ClusterResolution::Unallocated);
    }

    #[test]
    fn resolve_compressed_cluster() {
        let desc = CompressedClusterDescriptor {
            host_offset: 0x5000,
            compressed_size: 2 * 512,
        };
        let l2_raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper
            .resolve(GuestOffset(256), &backend, &mut cache)
            .unwrap();
        assert_eq!(
            result,
            ClusterResolution::Compressed {
                descriptor: desc,
                intra_cluster_offset: IntraClusterOffset(256),
            }
        );
    }

    #[test]
    fn l2_table_is_cached() {
        let data_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_offset | L2_COPIED_FLAG;
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        // First resolve: cache miss
        mapper
            .resolve(GuestOffset(0), &backend, &mut cache)
            .unwrap();
        assert_eq!(cache.stats().l2_misses, 1);
        assert_eq!(cache.stats().l2_hits, 0);

        // Second resolve: cache hit
        mapper
            .resolve(GuestOffset(0), &backend, &mut cache)
            .unwrap();
        assert_eq!(cache.stats().l2_hits, 1);
    }

    // ---- Edge cases ----

    #[test]
    fn l1_index_out_of_bounds() {
        // L1 table has only 1 entry. A guest offset that maps to L1 index >= 1
        // should fail.
        let l1_buf = vec![0u8; L1_ENTRY_SIZE];
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(10 * CLUSTER_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        // cluster_bits=16 → l2_entries=8192 → L1 boundary at 8192 * 65536 = 0x2000_0000
        let beyond_l1 = 8192u64 * 65536;
        let result = mapper.resolve(GuestOffset(beyond_l1), &backend, &mut cache);
        assert!(result.is_err(), "should fail for L1 index out of bounds");
    }

    #[test]
    fn same_offset_resolves_identically_twice() {
        // Verify that resolving the same offset twice (cache hit path)
        // returns the same result.
        let data_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_offset | L2_COPIED_FLAG;
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result1 = mapper
            .resolve(GuestOffset(42), &backend, &mut cache)
            .unwrap();
        let result2 = mapper
            .resolve(GuestOffset(42), &backend, &mut cache)
            .unwrap();
        assert_eq!(result1, result2);
        assert_eq!(cache.stats().l2_misses, 1);
        assert_eq!(cache.stats().l2_hits, 1);
    }

    #[test]
    fn intra_cluster_offset_propagated_correctly() {
        let data_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_offset | L2_COPIED_FLAG;
        let (backend, l1_table) = build_test_image(&[(0, l2_raw)]);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Guest offset 12345 → intra = 12345 (within first cluster)
        let result = mapper
            .resolve(GuestOffset(12345), &backend, &mut cache)
            .unwrap();
        assert_eq!(
            result,
            ClusterResolution::Allocated {
                host_offset: ClusterOffset(data_offset),
                intra_cluster_offset: IntraClusterOffset(12345),
            }
        );
    }

    // ---- L2 bounds-checking tests ----

    #[test]
    fn reject_l2_table_beyond_file() {
        // L1 points to an L2 table whose offset exceeds the file size.
        let fake_l2_offset = 20 * CLUSTER_SIZE as u64; // well beyond IMAGE_SIZE
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(fake_l2_offset), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
        assert!(result.is_err(), "should reject L2 table beyond file");
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::MetadataOffsetBeyondEof { .. }),
            "expected MetadataOffsetBeyondEof, got {err:?}"
        );
    }

    #[test]
    fn reject_l2_table_offset_overflow() {
        // L1 points to an L2 offset so large that offset + cluster_size overflows u64.
        let huge_offset = u64::MAX - 100;
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(huge_offset), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
        assert!(result.is_err(), "should reject overflowing L2 offset");
    }

    // ---- Write-support methods ----

    #[test]
    fn l1_entry_read() {
        let entry = L1Entry::with_l2_offset(ClusterOffset(0x20000), true);
        let mut l1_buf = vec![0u8; 2 * L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf[L1_ENTRY_SIZE..], entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 2).unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);

        assert!(mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());
        assert_eq!(mapper.l1_entry(L1Index(1)).unwrap(), entry);
    }

    #[test]
    fn set_l1_entry_updates_table() {
        let l1_table = L1Table::new_empty(4);
        let mut mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);

        let entry = L1Entry::with_l2_offset(ClusterOffset(0x30000), true);
        mapper.set_l1_entry(L1Index(2), entry).unwrap();
        assert_eq!(mapper.l1_entry(L1Index(2)).unwrap(), entry);
    }

    #[test]
    fn set_file_size_extends_boundary() {
        let l2_offset = 12 * CLUSTER_SIZE as u64; // beyond original IMAGE_SIZE
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let mut mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(20 * CLUSTER_SIZE);
        let mut cache = MetadataCache::new(CacheConfig::default());

        // Should fail with original file size
        assert!(mapper.resolve(GuestOffset(0), &backend, &mut cache).is_err());

        // After extending file size, should succeed
        mapper.set_file_size(20 * CLUSTER_SIZE as u64);
        let result = mapper.resolve(GuestOffset(0), &backend, &mut cache).unwrap();
        assert_eq!(result, ClusterResolution::Unallocated);
    }

    #[test]
    fn valid_l2_table_at_file_boundary_ok() {
        // L2 table starts exactly at the last valid position: file_size - cluster_size.
        // This should succeed.
        let l2_offset = IMAGE_SIZE - CLUSTER_SIZE as u64; // cluster 9
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, IMAGE_SIZE);
        let backend = MemoryBackend::zeroed(IMAGE_SIZE as usize);
        let mut cache = MetadataCache::new(CacheConfig::default());

        // All L2 entries are zero → Unallocated
        let result = mapper.resolve(GuestOffset(0), &backend, &mut cache);
        assert_eq!(result.unwrap(), ClusterResolution::Unallocated);
    }
}
