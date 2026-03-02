//! Main entry point for opening and reading QCOW2 images.
//!
//! [`Qcow2Image`] is the public facade that ties together header parsing,
//! cluster mapping, caching, and the read engine. Users of this crate
//! typically interact only with this type.

use std::path::Path;

use crate::engine::backing::{self, BackingChain};
use crate::engine::cache::{CacheConfig, CacheStats, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::reader::Qcow2Reader;
use crate::error::Result;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::L1Table;
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

/// A read-only QCOW2 image.
///
/// Owns the I/O backend, header, L1 table, and metadata cache. Provides
/// a high-level `read_at` method that handles all cluster types including
/// compressed and zero clusters.
///
/// # Example
///
/// ```no_run
/// use qcow2_lib::engine::image::Qcow2Image;
///
/// let mut image = Qcow2Image::open("disk.qcow2").unwrap();
/// let mut buf = vec![0u8; 512];
/// image.read_at(&mut buf, 0).unwrap();
/// ```
pub struct Qcow2Image {
    header: Header,
    extensions: Vec<HeaderExtension>,
    backend: Box<dyn IoBackend>,
    mapper: ClusterMapper,
    cache: MetadataCache,
    backing_chain: Option<BackingChain>,
}

impl Qcow2Image {
    /// Open a QCOW2 image file at the given path.
    ///
    /// Parses the header, loads the L1 table, and optionally resolves
    /// the backing file chain.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_backend_with_dir(Box::new(backend), Some(image_dir))
    }

    /// Create a `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Useful for testing with [`MemoryBackend`](crate::io::MemoryBackend)
    /// or for custom I/O implementations. Backing file resolution is
    /// skipped since no filesystem path is available.
    pub fn from_backend(backend: Box<dyn IoBackend>) -> Result<Self> {
        Self::from_backend_with_dir(backend, None)
    }

    /// Internal constructor that handles both file and backend paths.
    fn from_backend_with_dir(
        backend: Box<dyn IoBackend>,
        image_dir: Option<&Path>,
    ) -> Result<Self> {
        // Read header (read enough for the largest possible v3 header)
        let mut header_buf = vec![0u8; 512];
        let file_size = backend.file_size()?;
        let read_size = header_buf.len().min(file_size as usize);
        backend.read_exact_at(&mut header_buf[..read_size], 0)?;
        let header = Header::read_from(&header_buf[..read_size])?;

        // Read header extensions (between header end and first cluster boundary)
        let ext_start = header.header_length as u64;
        let cluster_size = header.cluster_size();
        let ext_end = cluster_size.min(file_size);
        let extensions = if ext_start < ext_end {
            let mut ext_buf = vec![0u8; (ext_end - ext_start) as usize];
            backend.read_exact_at(&mut ext_buf, ext_start)?;
            HeaderExtension::read_all(&ext_buf).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Read L1 table
        let l1_size = header.l1_table_entries as usize * crate::format::constants::L1_ENTRY_SIZE;
        let mut l1_buf = vec![0u8; l1_size];
        backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
        let l1_table = L1Table::read_from(&l1_buf, header.l1_table_entries)?;

        // Build cluster mapper
        let mapper = ClusterMapper::new(l1_table, header.cluster_bits);

        // Resolve backing chain
        let backing_chain = if header.has_backing_file() {
            if let Some(dir) = image_dir {
                let name = backing::read_backing_file_name(
                    backend.as_ref(),
                    header.backing_file_offset,
                    header.backing_file_size,
                )?;
                Some(BackingChain::resolve(&name, dir)?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            header,
            extensions,
            backend,
            mapper,
            cache: MetadataCache::new(CacheConfig::default()),
            backing_chain,
        })
    }

    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Handles reads that span multiple clusters, zero clusters,
    /// compressed clusters, and unallocated regions.
    pub fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        let mut reader = Qcow2Reader::new(
            &self.mapper,
            self.backend.as_ref(),
            &mut self.cache,
            self.header.cluster_bits,
            self.header.virtual_size,
        );
        reader.read_at(buf, guest_offset)
    }

    /// The parsed image header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The header extensions found in the image.
    pub fn extensions(&self) -> &[HeaderExtension] {
        &self.extensions
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> u64 {
        self.header.virtual_size
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.header.cluster_size()
    }

    /// The cluster_bits value from the header.
    pub fn cluster_bits(&self) -> u32 {
        self.header.cluster_bits
    }

    /// The resolved backing file chain, if any.
    pub fn backing_chain(&self) -> Option<&BackingChain> {
        self.backing_chain.as_ref()
    }

    /// Current cache statistics for diagnostics.
    pub fn cache_stats(&self) -> &CacheStats {
        self.cache.stats()
    }

    /// Access the underlying I/O backend.
    ///
    /// Useful for CLI tools that need to read raw metadata directly.
    pub fn backend(&self) -> &dyn IoBackend {
        self.backend.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::constants::*;
    use crate::format::l1::L1Entry;
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << 16;

    /// Build a minimal but valid QCOW2 v3 image in memory.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry)
    ///   Cluster 2: L2 table
    ///   Cluster 3+: data clusters
    fn build_test_image(
        l2_entries: &[(u32, u64)],
        data_clusters: &[(usize, &[u8])],
    ) -> MemoryBackend {
        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];

        let l1_offset = 1 * CLUSTER_SIZE;
        let l2_offset = 2 * CLUSTER_SIZE;

        // Write header
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30, // 1 GB
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(l1_offset as u64),
            refcount_table_offset: ClusterOffset(0), // not used in read tests
            refcount_table_clusters: 0,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header.write_to(&mut image_data[..HEADER_V3_MIN_LENGTH]).unwrap();

        // Write L1 table: one entry pointing to L2 at cluster 2
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        BigEndian::write_u64(&mut image_data[l1_offset..], l1_entry.raw());

        // Write L2 entries
        for &(index, raw_entry) in l2_entries {
            let offset = l2_offset + index as usize * L2_ENTRY_SIZE;
            BigEndian::write_u64(&mut image_data[offset..], raw_entry);
        }

        // Write data clusters
        for &(cluster_idx, data) in data_clusters {
            let offset = cluster_idx * CLUSTER_SIZE;
            let len = data.len().min(CLUSTER_SIZE);
            image_data[offset..offset + len].copy_from_slice(&data[..len]);
        }

        MemoryBackend::new(image_data)
    }

    #[test]
    fn open_from_backend_reads_header() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        assert_eq!(image.header().version, 3);
        assert_eq!(image.header().cluster_bits, CLUSTER_BITS);
        assert_eq!(image.virtual_size(), 1 << 30);
        assert_eq!(image.cluster_size(), CLUSTER_SIZE as u64);
    }

    #[test]
    fn read_allocated_data() {
        let data_cluster = 3;
        let host_offset = data_cluster as u64 * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;
        let test_data = b"Hello from Qcow2Image!";

        let backend = build_test_image(
            &[(0, l2_raw)],
            &[(data_cluster, test_data)],
        );
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0u8; test_data.len()];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, test_data);
    }

    #[test]
    fn read_unallocated_returns_zeros() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_zero_cluster() {
        let l2_raw = L2_ZERO_FLAG;
        let backend = build_test_image(&[(0, l2_raw)], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0xFFu8; 256];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_beyond_virtual_size_fails() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let vs = image.virtual_size();
        let mut buf = vec![0u8; 512];
        let result = image.read_at(&mut buf, vs);
        assert!(result.is_err());
    }

    #[test]
    fn cache_stats_are_accessible() {
        let data_cluster = 3;
        let host_offset = data_cluster as u64 * CLUSTER_SIZE as u64;
        let l2_raw = host_offset | L2_COPIED_FLAG;

        let backend = build_test_image(
            &[(0, l2_raw)],
            &[(data_cluster, &[0xAA; 64])],
        );
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();

        let mut buf = vec![0u8; 64];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(image.cache_stats().l2_misses, 1);

        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(image.cache_stats().l2_hits, 1);
    }
}
