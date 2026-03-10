// ---- Test helpers shared across sub-module tests ----

pub(crate) mod test_helpers {
    use crate::format::constants::*;
    use crate::format::header::Header;
    use crate::format::l1::L1Entry;
    use crate::format::types::ClusterOffset;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};

    pub const CLUSTER_BITS: u32 = 16;
    pub const CLUSTER_SIZE: usize = 1 << 16;

    /// Build a minimal but valid QCOW2 v3 image in memory.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry)
    ///   Cluster 2: L2 table
    ///   Cluster 3+: data clusters
    pub fn build_test_image(
        l2_entries: &[(u32, u64)],
        data_clusters: &[(usize, &[u8])],
    ) -> MemoryBackend {
        let image_size = 10 * CLUSTER_SIZE;
        let mut image_data = vec![0u8; image_size];

        let l1_offset = CLUSTER_SIZE;
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

    /// Build a writable QCOW2 v3 image with a proper refcount table.
    ///
    /// Layout:
    ///   Cluster 0: header
    ///   Cluster 1: L1 table (1 entry, unallocated)
    ///   Cluster 2: refcount table (1 cluster)
    ///   Cluster 3: refcount block 0
    ///   Cluster 4+: free
    pub fn build_writable_test_image() -> MemoryBackend {
        let l1_offset = CLUSTER_SIZE;
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;
        let total_size = 4 * CLUSTER_SIZE;

        let mut data = vec![0u8; total_size];

        // Write header
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(l1_offset as u64),
            refcount_table_offset: ClusterOffset(rt_offset as u64),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };
        header.write_to(&mut data[..HEADER_V3_MIN_LENGTH]).unwrap();

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-3 have refcount 1
        for i in 0..4 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }

        MemoryBackend::new(data)
    }
}

mod unit_tests {
    use super::super::*;
    use crate::engine::read_mode::ReadMode;
    use crate::format::constants::*;
    use crate::io::MemoryBackend;
    use byteorder::{BigEndian, ByteOrder};
    use super::test_helpers::*;

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

    // ---- Edge cases: opening invalid files ----

    #[test]
    fn reject_non_qcow2_data() {
        let backend = MemoryBackend::zeroed(4096);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_short_for_header() {
        let backend = MemoryBackend::new(vec![0u8; 40]);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_file() {
        let backend = MemoryBackend::new(vec![]);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn reject_garbage_data() {
        let backend = MemoryBackend::new(b"hello world, this is not a qcow2 image!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!".to_vec());
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn extensions_accessor_works() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let _exts = image.extensions();
    }

    #[test]
    fn backend_accessor_works() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let b = image.backend();
        assert!(b.file_size().unwrap() > 0);
    }

    // ---- ReadMode + validation tests ----

    #[test]
    fn default_read_mode_is_strict() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Strict);
    }

    #[test]
    fn set_read_mode_changes_behavior() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Strict);

        image.set_read_mode(ReadMode::Lenient);
        assert_eq!(image.read_mode(), ReadMode::Lenient);
    }

    #[test]
    fn warnings_initially_empty() {
        let backend = build_test_image(&[], &[]);
        let image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert!(image.warnings().is_empty());
    }

    #[test]
    fn clear_warnings_works() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        image.clear_warnings();
        assert!(image.warnings().is_empty());
    }

    #[test]
    fn from_backend_with_mode_sets_mode() {
        let backend = build_test_image(&[], &[]);
        let image =
            Qcow2Image::from_backend_with_mode(Box::new(backend), ReadMode::Lenient).unwrap();
        assert_eq!(image.read_mode(), ReadMode::Lenient);
    }

    #[test]
    fn strict_mode_rejects_l1_beyond_eof() {
        let mut image_data = vec![0u8; 2 * CLUSTER_SIZE];
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: 100,
            l1_table_offset: ClusterOffset(0x100_0000),
            refcount_table_offset: ClusterOffset(0),
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
        header
            .write_to(&mut image_data[..HEADER_V3_MIN_LENGTH])
            .unwrap();

        let backend = MemoryBackend::new(image_data);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn strict_mode_rejects_huge_l1_entries() {
        let mut image_data = vec![0u8; 2 * CLUSTER_SIZE];
        let header = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: 1 << 30,
            crypt_method: 0,
            l1_table_entries: u32::MAX,
            l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
            refcount_table_offset: ClusterOffset(0),
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
        header
            .write_to(&mut image_data[..HEADER_V3_MIN_LENGTH])
            .unwrap();

        let backend = MemoryBackend::new(image_data);
        let result = Qcow2Image::from_backend(Box::new(backend));
        assert!(result.is_err());
    }

    #[test]
    fn lenient_mode_reads_zeros_for_unallocated() {
        let backend = build_test_image(&[], &[]);
        let mut image =
            Qcow2Image::from_backend_with_mode(Box::new(backend), ReadMode::Lenient).unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
        assert!(image.warnings().is_empty());
    }

    // ---- Write API tests ----

    #[test]
    fn from_backend_rw_enables_writing() {
        let backend = build_writable_test_image();
        let image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert!(image.is_writable());
        assert!(!image.is_dirty());
    }

    #[test]
    fn read_only_image_rejects_write() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let result = image.write_at(&[0x42; 64], 0);
        assert!(matches!(result, Err(Error::ReadOnly)));
    }

    #[test]
    fn read_only_image_rejects_flush() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        let result = image.flush();
        assert!(matches!(result, Err(Error::ReadOnly)));
    }

    #[test]
    fn write_sets_dirty_flag() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert!(!image.is_dirty());

        image.write_at(&[0xAA; 64], 0).unwrap();
        assert!(image.is_dirty());
    }

    #[test]
    fn dirty_flag_persisted_to_disk_header() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0xBB; 64], 0).unwrap();

        let mut buf = [0u8; 8];
        image.backend().read_exact_at(&mut buf, 72).unwrap();
        let features = BigEndian::read_u64(&buf);
        assert_ne!(features & 1, 0, "DIRTY bit should be set on disk");
    }

    #[test]
    fn flush_clears_dirty_flag() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0xCC; 64], 0).unwrap();
        assert!(image.is_dirty());

        image.flush().unwrap();
        assert!(!image.is_dirty());

        let mut buf = [0u8; 8];
        image.backend().read_exact_at(&mut buf, 72).unwrap();
        let features = BigEndian::read_u64(&buf);
        assert_eq!(features & 1, 0, "DIRTY bit should be cleared on disk");
    }

    #[test]
    fn write_then_read_back() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let write_data = vec![0xDD; 1024];
        image.write_at(&write_data, 0).unwrap();

        let mut read_buf = vec![0u8; 1024];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn write_partial_then_read_full_cluster() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let write_data = vec![0xEE; 100];
        image.write_at(&write_data, 200).unwrap();

        let mut cluster_buf = vec![0u8; CLUSTER_SIZE];
        image.read_at(&mut cluster_buf, 0).unwrap();

        assert!(cluster_buf[..200].iter().all(|&b| b == 0));
        assert_eq!(&cluster_buf[200..300], &write_data[..]);
        assert!(cluster_buf[300..].iter().all(|&b| b == 0));
    }

    #[test]
    fn multiple_writes_then_read() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0x11; 50], 0).unwrap();
        image.write_at(&[0x22; 50], 50).unwrap();
        image.write_at(&[0x33; 50], 100).unwrap();

        let mut buf = vec![0u8; 150];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf[..50].iter().all(|&b| b == 0x11));
        assert!(buf[50..100].iter().all(|&b| b == 0x22));
        assert!(buf[100..150].iter().all(|&b| b == 0x33));
    }

    #[test]
    fn flush_without_writes_is_noop() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.flush().unwrap();
        assert!(!image.is_dirty());
    }

    #[test]
    fn default_cache_mode_is_writeback() {
        let backend = build_writable_test_image();
        let image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert_eq!(image.cache_mode(), CacheMode::WriteBack);
    }

    #[test]
    fn set_cache_mode_writethrough() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        image.write_at(&[0xAA; 64], 0).unwrap();
        // Switch to WriteThrough — should flush dirty entries
        image.set_cache_mode(CacheMode::WriteThrough).unwrap();
        assert_eq!(image.cache_mode(), CacheMode::WriteThrough);

        // Data should still be readable
        let mut buf = vec![0u8; 64];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn writeback_cache_improves_hit_rate() {
        let backend = build_writable_test_image();
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        assert_eq!(image.cache_mode(), CacheMode::WriteBack);

        // Multiple writes to the same cluster should hit the cached L2 table
        for i in 0..10u8 {
            image.write_at(&[i; 64], i as u64 * 64).unwrap();
        }

        let stats = image.cache_stats();
        assert!(stats.l2_hits >= 9, "expected >= 9 L2 hits, got {}", stats.l2_hits);
        assert_eq!(stats.l2_misses, 1, "expected 1 L2 miss (first load)");
    }
}
