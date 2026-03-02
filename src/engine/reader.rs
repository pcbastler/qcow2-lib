//! QCOW2 read engine: translates guest reads into host data.
//!
//! Composes cluster mapping, decompression, and backing chain fallback
//! to serve arbitrary guest reads that may span multiple clusters.

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::{ClusterMapper, ClusterResolution};
use crate::engine::compression;
use crate::error::{Error, Result};
use crate::format::types::GuestOffset;
use crate::io::IoBackend;

/// Reads guest data from a QCOW2 image, handling all cluster types.
///
/// The reader does not own the backend or cache — it borrows them for
/// the duration of a read operation. This allows `Qcow2Image` to
/// maintain ownership and create readers on demand.
pub struct Qcow2Reader<'a> {
    mapper: &'a ClusterMapper,
    backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    cluster_bits: u32,
    virtual_size: u64,
}

impl<'a> Qcow2Reader<'a> {
    /// Create a new reader.
    pub fn new(
        mapper: &'a ClusterMapper,
        backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        cluster_bits: u32,
        virtual_size: u64,
    ) -> Self {
        Self {
            mapper,
            backend,
            cache,
            cluster_bits,
            virtual_size,
        }
    }

    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Handles reads that span multiple clusters by splitting them
    /// into per-cluster chunks. Each chunk is resolved independently
    /// through the cluster mapper.
    pub fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        let read_end = guest_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            })?;

        if read_end > self.virtual_size {
            return Err(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            });
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left_in_cluster = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left_in_cluster);
            let (chunk, rest) = remaining.split_at_mut(chunk_size);

            self.read_cluster_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Read a chunk of data from a single cluster.
    fn read_cluster_chunk(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        let resolution =
            self.mapper
                .resolve(GuestOffset(guest_offset), self.backend, self.cache)?;

        match resolution {
            ClusterResolution::Allocated {
                host_offset,
                intra_cluster_offset,
            } => {
                let read_offset = host_offset.0 + intra_cluster_offset.0 as u64;
                self.backend.read_exact_at(buf, read_offset)
            }
            ClusterResolution::Zero => {
                buf.fill(0);
                Ok(())
            }
            ClusterResolution::Unallocated => {
                // No backing file support yet in Phase 1
                // Unallocated without backing = zeros
                buf.fill(0);
                Ok(())
            }
            ClusterResolution::Compressed {
                descriptor,
                intra_cluster_offset,
            } => {
                let cluster_size = 1usize << self.cluster_bits;
                // The compressed_size from the descriptor is the maximum number
                // of sectors the data can span, but may extend past EOF for the
                // last compressed cluster in the file. Clamp to available data.
                let file_size = self.backend.file_size()?;
                let available = file_size.saturating_sub(descriptor.host_offset);
                let read_size = (descriptor.compressed_size as usize).min(available as usize);
                let mut compressed_data = vec![0u8; read_size];
                self.backend
                    .read_exact_at(&mut compressed_data, descriptor.host_offset)?;
                let decompressed =
                    compression::decompress_cluster(&compressed_data, cluster_size, guest_offset)?;
                let intra = intra_cluster_offset.0 as usize;
                buf.copy_from_slice(&decompressed[intra..intra + buf.len()]);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cache::CacheConfig;
    use crate::format::compressed::CompressedClusterDescriptor;
    use crate::format::constants::*;
    use crate::format::l1::{L1Entry, L1Table};
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << 16;

    /// Build a test image with one L1 entry and specific L2 entries.
    /// Returns (backend, mapper) ready for reading.
    fn build_test_setup(
        l2_entries: &[(u32, u64)],
        data_clusters: &[(usize, &[u8])],
    ) -> (MemoryBackend, ClusterMapper) {
        let l2_offset = 2 * CLUSTER_SIZE;

        // L1 table: one entry pointing to L2 at cluster 2
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        // L2 table
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        for &(index, raw_entry) in l2_entries {
            BigEndian::write_u64(&mut l2_buf[index as usize * L2_ENTRY_SIZE..], raw_entry);
        }

        // Assemble image (10 clusters)
        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];
        image_data[l2_offset..l2_offset + CLUSTER_SIZE].copy_from_slice(&l2_buf);

        // Write data clusters
        for &(cluster_idx, data) in data_clusters {
            let offset = cluster_idx * CLUSTER_SIZE;
            let len = data.len().min(CLUSTER_SIZE);
            image_data[offset..offset + len].copy_from_slice(&data[..len]);
        }

        let backend = MemoryBackend::new(image_data);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS);
        (backend, mapper)
    }

    #[test]
    fn read_allocated_cluster() {
        let data_cluster = 3;
        let host_offset = data_cluster * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;

        let test_data = b"Hello, QCOW2!";
        let (backend, mapper) =
            build_test_setup(&[(0, l2_raw)], &[(data_cluster as usize, test_data)]);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        let mut buf = vec![0u8; test_data.len()];
        reader.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, test_data);
    }

    #[test]
    fn read_zero_cluster() {
        let l2_raw = L2_ZERO_FLAG;
        let (backend, mapper) = build_test_setup(&[(0, l2_raw)], &[]);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        let mut buf = vec![0xFFu8; 512];
        reader.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_unallocated_cluster() {
        let (backend, mapper) = build_test_setup(&[], &[]); // All L2 entries zero
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        let mut buf = vec![0xFFu8; 256];
        reader.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_spanning_two_clusters() {
        let data1 = vec![0xAAu8; CLUSTER_SIZE];
        let data2 = vec![0xBBu8; CLUSTER_SIZE];
        let host1 = 3 * CLUSTER_SIZE as u64;
        let host2 = 4 * CLUSTER_SIZE as u64;

        let (backend, mapper) = build_test_setup(
            &[
                (0, host1 | L2_COPIED_FLAG),
                (1, host2 | L2_COPIED_FLAG),
            ],
            &[(3, &data1), (4, &data2)],
        );
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        // Read 512 bytes spanning the boundary: last 256 of cluster 0 + first 256 of cluster 1
        let read_offset = CLUSTER_SIZE as u64 - 256;
        let mut buf = vec![0u8; 512];
        reader.read_at(&mut buf, read_offset).unwrap();

        assert!(buf[..256].iter().all(|&b| b == 0xAA));
        assert!(buf[256..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_compressed_cluster() {
        // Create compressed data
        let original: Vec<u8> = (0..CLUSTER_SIZE).map(|i| (i % 256) as u8).collect();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Place compressed data at a non-aligned offset in cluster 5
        let compressed_host_offset = 5 * CLUSTER_SIZE as u64 + 100;
        let desc = CompressedClusterDescriptor {
            host_offset: compressed_host_offset,
            compressed_size: ((compressed.len() / 512) as u64 + 1) * 512,
        };

        let l2_raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);

        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];

        // Write L2 table
        let l2_offset = 2 * CLUSTER_SIZE;
        BigEndian::write_u64(&mut image_data[l2_offset..], l2_raw);

        // Write compressed data
        let co = compressed_host_offset as usize;
        image_data[co..co + compressed.len()].copy_from_slice(&compressed);

        // Build L1
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let backend = MemoryBackend::new(image_data);
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        // Read first 100 bytes
        let mut buf = vec![0u8; 100];
        reader.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, &original[..100]);
    }

    #[test]
    fn read_beyond_virtual_size() {
        let (backend, mapper) = build_test_setup(&[], &[]);
        let mut cache = MetadataCache::new(CacheConfig::default());
        let virtual_size = 1024u64;

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, virtual_size);

        let mut buf = vec![0u8; 100];
        let result = reader.read_at(&mut buf, 1000);
        assert!(result.is_err());
        match result {
            Err(Error::OffsetBeyondDiskSize { .. }) => {}
            other => panic!("expected OffsetBeyondDiskSize, got {other:?}"),
        }
    }

    // ---- Edge cases ----

    #[test]
    fn read_zero_length_buffer() {
        let (backend, mapper) = build_test_setup(&[], &[]);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        // A zero-length read should succeed immediately.
        let mut buf = vec![];
        reader.read_at(&mut buf, 0).unwrap();
    }

    #[test]
    fn read_at_exact_virtual_size_fails() {
        let (backend, mapper) = build_test_setup(&[], &[]);
        let mut cache = MetadataCache::new(CacheConfig::default());
        let virtual_size = 65536u64; // exactly 1 cluster

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, virtual_size);

        // offset = virtual_size → reading even 1 byte should fail
        let mut buf = vec![0u8; 1];
        let result = reader.read_at(&mut buf, virtual_size);
        assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
    }

    #[test]
    fn read_u64_overflow_is_caught() {
        let (backend, mapper) = build_test_setup(&[], &[]);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, u64::MAX);

        // offset near u64::MAX + buf.len() would overflow
        let mut buf = vec![0u8; 1024];
        let result = reader.read_at(&mut buf, u64::MAX - 100);
        assert!(result.is_err());
    }

    #[test]
    fn read_single_byte_at_cluster_boundary() {
        // Read exactly 1 byte at the last position of a cluster.
        let data = vec![0xEEu8; CLUSTER_SIZE];
        let host_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;

        let (backend, mapper) = build_test_setup(&[(0, l2_raw)], &[(3, &data)]);
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        let mut buf = vec![0u8; 1];
        reader.read_at(&mut buf, CLUSTER_SIZE as u64 - 1).unwrap();
        assert_eq!(buf[0], 0xEE);
    }

    #[test]
    fn read_spanning_three_clusters() {
        let data1 = vec![0x11u8; CLUSTER_SIZE];
        let data2 = vec![0x22u8; CLUSTER_SIZE];
        let data3 = vec![0x33u8; CLUSTER_SIZE];
        let host1 = 3 * CLUSTER_SIZE as u64;
        let host2 = 4 * CLUSTER_SIZE as u64;
        let host3 = 5 * CLUSTER_SIZE as u64;

        let (backend, mapper) = build_test_setup(
            &[
                (0, host1 | L2_COPIED_FLAG),
                (1, host2 | L2_COPIED_FLAG),
                (2, host3 | L2_COPIED_FLAG),
            ],
            &[(3, &data1), (4, &data2), (5, &data3)],
        );
        let mut cache = MetadataCache::new(CacheConfig::default());

        let mut reader = Qcow2Reader::new(&mapper, &backend, &mut cache, CLUSTER_BITS, 1 << 30);

        // Read from middle of cluster 0 through all of cluster 1 into cluster 2
        let start = CLUSTER_SIZE as u64 - 256;
        let read_len = 256 + CLUSTER_SIZE + 256;
        let mut buf = vec![0u8; read_len];
        reader.read_at(&mut buf, start).unwrap();

        assert!(buf[..256].iter().all(|&b| b == 0x11), "tail of cluster 0");
        assert!(buf[256..256 + CLUSTER_SIZE].iter().all(|&b| b == 0x22), "all of cluster 1");
        assert!(buf[256 + CLUSTER_SIZE..].iter().all(|&b| b == 0x33), "start of cluster 2");
    }
}
