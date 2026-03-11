//! Tests for reader (originally in engine/reader.rs)

use crate::engine::cache::{CacheConfig, MetadataCache};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::reader::Qcow2Reader;
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::constants::*;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::types::{ClusterGeometry, ClusterOffset};
use crate::io::MemoryBackend;
use crate::engine::compression::StdCompressor;
use crate::error::Error;
use byteorder::{BigEndian, ByteOrder};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

const CLUSTER_BITS: u32 = 16;
const CLUSTER_SIZE: usize = 1 << 16;
const GEO_STD: ClusterGeometry = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false };

/// Create a strict-mode reader for testing (most common case).
fn make_strict_reader<'a>(
    mapper: &'a ClusterMapper,
    backend: &'a MemoryBackend,
    cache: &'a mut MetadataCache,
    virtual_size: u64,
    warnings: &'a mut Vec<ReadWarning>,
) -> Qcow2Reader<'a> {
    Qcow2Reader::new(
        mapper,
        backend,
        backend,
        cache,
        CLUSTER_BITS,
        virtual_size,
        COMPRESSION_DEFLATE,
        ReadMode::Strict,
        warnings,
        None,
        None,
        &StdCompressor,
    )
}

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
    let mapper = ClusterMapper::new(l1_table, GEO_STD, image_size as u64);
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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0u8; test_data.len()];
    reader.read_at(&mut buf, 0).unwrap();
    assert_eq!(&buf, test_data);
}

#[test]
fn read_zero_cluster() {
    let l2_raw = L2_ZERO_FLAG;
    let (backend, mapper) = build_test_setup(&[(0, l2_raw)], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn read_unallocated_cluster() {
    let (backend, mapper) = build_test_setup(&[], &[]); // All L2 entries zero
    let mut cache = MetadataCache::new(CacheConfig::default());

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

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
    let mapper = ClusterMapper::new(l1_table, GEO_STD, image_size as u64);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    // A zero-length read should succeed immediately.
    let mut buf = vec![];
    reader.read_at(&mut buf, 0).unwrap();
}

#[test]
fn read_at_exact_virtual_size_fails() {
    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let virtual_size = 65536u64; // exactly 1 cluster

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    // offset = virtual_size -> reading even 1 byte should fail
    let mut buf = vec![0u8; 1];
    let result = reader.read_at(&mut buf, virtual_size);
    assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
}

#[test]
fn read_u64_overflow_is_caught() {
    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, u64::MAX, &mut warnings);

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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

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

    let mut warnings = vec![];
    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    // Read from middle of cluster 0 through all of cluster 1 into cluster 2
    let start = CLUSTER_SIZE as u64 - 256;
    let read_len = 256 + CLUSTER_SIZE + 256;
    let mut buf = vec![0u8; read_len];
    reader.read_at(&mut buf, start).unwrap();

    assert!(buf[..256].iter().all(|&b| b == 0x11), "tail of cluster 0");
    assert!(buf[256..256 + CLUSTER_SIZE].iter().all(|&b| b == 0x22), "all of cluster 1");
    assert!(buf[256 + CLUSTER_SIZE..].iter().all(|&b| b == 0x33), "start of cluster 2");
}

// ---- Lenient mode helpers ----

/// Create a lenient-mode reader for testing.
fn make_lenient_reader<'a>(
    mapper: &'a ClusterMapper,
    backend: &'a MemoryBackend,
    cache: &'a mut MetadataCache,
    virtual_size: u64,
    warnings: &'a mut Vec<ReadWarning>,
) -> Qcow2Reader<'a> {
    Qcow2Reader::new(
        mapper,
        backend,
        backend,
        cache,
        CLUSTER_BITS,
        virtual_size,
        COMPRESSION_DEFLATE,
        ReadMode::Lenient,
        warnings,
        None,
        None,
        &StdCompressor,
    )
}

/// Build an image where L1 has only 1 entry but virtual_size implies
/// more L1 entries are needed. Accessing guest offset beyond L1 triggers
/// an L1 out-of-bounds error.
fn build_small_l1_setup() -> (MemoryBackend, ClusterMapper) {
    let l1_buf = vec![0u8; L1_ENTRY_SIZE]; // 1 entry, all zeros
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
    let image_size = 10 * CLUSTER_SIZE;
    let backend = MemoryBackend::zeroed(image_size);
    let mapper = ClusterMapper::new(l1_table, GEO_STD, image_size as u64);
    (backend, mapper)
}

/// Build an image where L1 points to an L2 table beyond the file.
fn build_l2_beyond_eof_setup() -> (MemoryBackend, ClusterMapper) {
    let fake_l2_offset = 20 * CLUSTER_SIZE as u64; // beyond the file
    let l1_entry = L1Entry::with_l2_offset(ClusterOffset(fake_l2_offset), true);
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
    let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

    let image_size = 10 * CLUSTER_SIZE;
    let backend = MemoryBackend::zeroed(image_size);
    let mapper = ClusterMapper::new(l1_table, GEO_STD, image_size as u64);
    (backend, mapper)
}

/// Build an image where an L2 entry points to a host offset beyond the file.
/// This passes ClusterMapper (which only validates L2 TABLE offsets) but
/// causes an I/O error when the reader tries to read the actual data.
fn build_allocated_io_error_setup() -> (MemoryBackend, ClusterMapper) {
    let bad_host_offset = 20 * CLUSTER_SIZE as u64; // beyond file
    let l2_raw = bad_host_offset | L2_COPIED_FLAG;
    build_test_setup(&[(0, l2_raw)], &[])
}

/// Build an image with a compressed cluster pointing to garbage data
/// (valid offset, but not valid deflate).
fn build_bad_compressed_setup() -> (MemoryBackend, ClusterMapper, u64) {
    let compressed_host_offset = 5 * CLUSTER_SIZE as u64;
    let desc = CompressedClusterDescriptor {
        host_offset: compressed_host_offset,
        compressed_size: 512,
    };
    let l2_raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);

    // Use build_test_setup -- cluster 5 will contain zeros (invalid deflate)
    let (backend, mapper) = build_test_setup(&[(0, l2_raw)], &[]);
    (backend, mapper, compressed_host_offset)
}

/// Build an image with a compressed cluster descriptor pointing beyond EOF.
fn build_compressed_beyond_eof_setup() -> (MemoryBackend, ClusterMapper) {
    let desc = CompressedClusterDescriptor {
        host_offset: 20 * CLUSTER_SIZE as u64, // beyond file
        compressed_size: 512,
    };
    let l2_raw = L2_COMPRESSED_FLAG | desc.encode(CLUSTER_BITS);
    build_test_setup(&[(0, l2_raw)], &[])
}

// ---- Strict mode error propagation ----

#[test]
fn strict_mode_propagates_l1_out_of_bounds() {
    let (backend, mapper) = build_small_l1_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    // virtual_size large enough to imply L1 index > 0
    let virtual_size = 2 * 8192 * CLUSTER_SIZE as u64;
    let mut reader =
        make_strict_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    // L1 has 1 entry -> guest offset at L1 index 1 fails
    let beyond_l1 = 8192u64 * CLUSTER_SIZE as u64;
    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, beyond_l1);
    assert!(result.is_err());
    assert!(warnings.is_empty());
}

#[test]
fn strict_mode_propagates_decompression_error() {
    let (backend, mapper, _) = build_bad_compressed_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, 0);
    assert!(result.is_err());
    assert!(warnings.is_empty());
}

#[test]
fn strict_mode_propagates_io_error() {
    let (backend, mapper) = build_allocated_io_error_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, 0);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(Error::Io { .. })),
        "expected Io error, got {result:?}"
    );
}

#[test]
fn strict_mode_rejects_compressed_beyond_eof() {
    let (backend, mapper) = build_compressed_beyond_eof_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_strict_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, 0);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(Error::Format(crate::error::FormatError::MetadataOffsetBeyondEof { .. }))),
        "expected MetadataOffsetBeyondEof, got {result:?}"
    );
}

// ---- Lenient mode: zeros on error ----

#[test]
fn lenient_returns_zeros_on_l1_out_of_bounds() {
    let (backend, mapper) = build_small_l1_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let virtual_size = 2 * 8192 * CLUSTER_SIZE as u64;
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    let beyond_l1 = 8192u64 * CLUSTER_SIZE as u64;
    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, beyond_l1).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient should fill zeros");
    assert_eq!(warnings.len(), 1);
}

#[test]
fn lenient_returns_zeros_on_l2_load_failure() {
    let (backend, mapper) = build_l2_beyond_eof_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient should fill zeros");
    assert_eq!(warnings.len(), 1);
}

#[test]
fn lenient_returns_zeros_on_allocated_io_error() {
    let (backend, mapper) = build_allocated_io_error_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient should fill zeros");
    assert_eq!(warnings.len(), 1);
}

#[test]
fn lenient_returns_zeros_on_decompression_failure() {
    let (backend, mapper, _) = build_bad_compressed_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient should fill zeros");
    assert_eq!(warnings.len(), 1);
}

#[test]
fn lenient_returns_zeros_on_compressed_beyond_eof() {
    let (backend, mapper) = build_compressed_beyond_eof_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0xFFu8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient should fill zeros");
    assert_eq!(warnings.len(), 1);
}

// ---- Lenient mode: warning content ----

#[test]
fn lenient_warning_contains_guest_offset() {
    let (backend, mapper) = build_small_l1_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let virtual_size = 2 * 8192 * CLUSTER_SIZE as u64;
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    let beyond_l1 = 8192u64 * CLUSTER_SIZE as u64;
    let mut buf = vec![0u8; 512];
    reader.read_at(&mut buf, beyond_l1).unwrap();

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].guest_offset, beyond_l1);
}

#[test]
fn lenient_warning_contains_descriptive_message() {
    let (backend, mapper) = build_compressed_beyond_eof_setup();
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, 1 << 30, &mut warnings);

    let mut buf = vec![0u8; 512];
    reader.read_at(&mut buf, 0).unwrap();

    assert_eq!(warnings.len(), 1);
    assert!(
        !warnings[0].message.is_empty(),
        "warning message should not be empty"
    );
    assert!(
        warnings[0].message.contains("exceeds"),
        "warning should describe the issue, got: {}",
        warnings[0].message
    );
}

#[test]
fn lenient_multi_cluster_read_partial_corruption() {
    // Build an image with 3 clusters: cluster 0 has valid data, cluster 1
    // has an L2 entry pointing beyond the file (I/O error), cluster 2
    // has valid data.
    let data1 = vec![0xAAu8; CLUSTER_SIZE];
    let data3 = vec![0xCCu8; CLUSTER_SIZE];
    let host1 = 3 * CLUSTER_SIZE as u64;
    let bad_host = 20 * CLUSTER_SIZE as u64; // beyond file
    let host3 = 5 * CLUSTER_SIZE as u64;

    let (backend, mapper) = build_test_setup(
        &[
            (0, host1 | L2_COPIED_FLAG),
            (1, bad_host | L2_COPIED_FLAG), // corrupt
            (2, host3 | L2_COPIED_FLAG),
        ],
        &[(3, &data1), (5, &data3)],
    );
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let virtual_size = 10 * CLUSTER_SIZE as u64;
    let mut reader =
        make_lenient_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    // Read spanning all 3 clusters
    let mut buf = vec![0xFFu8; 3 * CLUSTER_SIZE];
    reader.read_at(&mut buf, 0).unwrap();

    // Cluster 0: valid data
    assert!(
        buf[..CLUSTER_SIZE].iter().all(|&b| b == 0xAA),
        "cluster 0 should have valid data"
    );
    // Cluster 1: zeroed due to corruption
    assert!(
        buf[CLUSTER_SIZE..2 * CLUSTER_SIZE]
            .iter()
            .all(|&b| b == 0),
        "cluster 1 should be zeros (corrupt)"
    );
    // Cluster 2: valid data
    assert!(
        buf[2 * CLUSTER_SIZE..].iter().all(|&b| b == 0xCC),
        "cluster 2 should have valid data"
    );

    // Exactly one warning for the corrupt cluster
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].guest_offset, CLUSTER_SIZE as u64);
}

// ---- Backing bounds tests ----

/// Create a backing Qcow2Image with `backing_vs` virtual size
/// and 0xBB written to the first 512 bytes.
fn make_backing_image(backing_vs: u64) -> crate::engine::image::Qcow2Image {
    let backend = MemoryBackend::zeroed(0);
    let mut img = crate::engine::image::Qcow2Image::create_on_backend(
        Box::new(backend),
        crate::engine::image::CreateOptions {
            virtual_size: backing_vs,
            cluster_bits: Some(CLUSTER_BITS),
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap();
    img.write_at(&[0xBB; 512], 0).unwrap();
    img
}

#[test]
fn unallocated_beyond_backing_returns_zeros() {
    // Backing is 64 KB, read at offset 128 KB (beyond backing)
    let mut backing = make_backing_image(CLUSTER_SIZE as u64);

    // Overlay: all unallocated (L2 entries all zero)
    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let virtual_size = 4 * CLUSTER_SIZE as u64;
    let mut reader = Qcow2Reader::new(
        &mapper,
        &backend,
        &backend,
        &mut cache,
        CLUSTER_BITS,
        virtual_size,
        COMPRESSION_DEFLATE,
        ReadMode::Strict,
        &mut warnings,
        Some(&mut backing),
        None,
        &StdCompressor,
    );

    let mut buf = vec![0xFF; 512];
    reader.read_at(&mut buf, 2 * CLUSTER_SIZE as u64).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "beyond backing should be zeros");
}

#[test]
fn unallocated_partial_overlap_with_backing() {
    // Backing is 256 bytes into the first cluster (virtual_size = 256).
    // Read 512 bytes from offset 0 -- first 256 from backing, rest zeros.
    let backend_mem = MemoryBackend::zeroed(0);
    let mut backing = crate::engine::image::Qcow2Image::create_on_backend(
        Box::new(backend_mem),
        crate::engine::image::CreateOptions {
            virtual_size: 256,
            cluster_bits: Some(CLUSTER_BITS),
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
        },
    )
    .unwrap();
    backing.write_at(&[0xCC; 256], 0).unwrap();

    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let virtual_size = CLUSTER_SIZE as u64;

    let mut reader = Qcow2Reader::new(
        &mapper,
        &backend,
        &backend,
        &mut cache,
        CLUSTER_BITS,
        virtual_size,
        COMPRESSION_DEFLATE,
        ReadMode::Strict,
        &mut warnings,
        Some(&mut backing),
        None,
        &StdCompressor,
    );

    let mut buf = vec![0xFF; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(
        buf[..256].iter().all(|&b| b == 0xCC),
        "first 256 bytes should come from backing"
    );
    assert!(
        buf[256..].iter().all(|&b| b == 0),
        "bytes beyond backing should be zeros"
    );
}

#[test]
fn unallocated_within_backing_reads_data() {
    // Backing is large enough; read entirely from backing
    let mut backing = make_backing_image(CLUSTER_SIZE as u64);

    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];
    let virtual_size = CLUSTER_SIZE as u64;

    let mut reader = Qcow2Reader::new(
        &mapper,
        &backend,
        &backend,
        &mut cache,
        CLUSTER_BITS,
        virtual_size,
        COMPRESSION_DEFLATE,
        ReadMode::Strict,
        &mut warnings,
        Some(&mut backing),
        None,
        &StdCompressor,
    );

    let mut buf = vec![0u8; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "should read 0xBB from backing"
    );
}

// ---- Encrypted read tests ----

#[test]
fn read_encrypted_full_cluster() {
    use crate::engine::encryption::{CryptContext, CipherMode};

    let data_cluster = 3;
    let host_offset = data_cluster * CLUSTER_SIZE as u64;
    let l2_raw = host_offset | L2_COPIED_FLAG;

    let key = vec![0x42u8; 64]; // AES-256-XTS
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    // Write encrypted data to cluster 3
    let plaintext = vec![0xAB; CLUSTER_SIZE];
    let mut encrypted = plaintext.clone();
    crypt.encrypt_cluster(host_offset, &mut encrypted).unwrap();

    let (backend, mapper) =
        build_test_setup(&[(0, l2_raw)], &[(data_cluster as usize, &encrypted)]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let mut reader = Qcow2Reader::new(
        &mapper, &backend, &backend, &mut cache, CLUSTER_BITS,
        1 << 30, COMPRESSION_DEFLATE, ReadMode::Strict, &mut warnings,
        None, Some(&crypt), &StdCompressor,
    );

    // Full cluster read
    let mut buf = vec![0u8; CLUSTER_SIZE];
    reader.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, plaintext, "decrypted data should match original");
}

#[test]
fn read_encrypted_partial_cluster() {
    use crate::engine::encryption::{CryptContext, CipherMode};

    let data_cluster = 3;
    let host_offset = data_cluster * CLUSTER_SIZE as u64;
    let l2_raw = host_offset | L2_COPIED_FLAG;

    let key = vec![0x42u8; 64];
    let crypt = CryptContext::new(key, CipherMode::AesXtsPlain64);

    let mut plaintext = vec![0u8; CLUSTER_SIZE];
    plaintext[256..768].fill(0xCC);
    let mut encrypted = plaintext.clone();
    crypt.encrypt_cluster(host_offset, &mut encrypted).unwrap();

    let (backend, mapper) =
        build_test_setup(&[(0, l2_raw)], &[(data_cluster as usize, &encrypted)]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let mut reader = Qcow2Reader::new(
        &mapper, &backend, &backend, &mut cache, CLUSTER_BITS,
        1 << 30, COMPRESSION_DEFLATE, ReadMode::Strict, &mut warnings,
        None, Some(&crypt), &StdCompressor,
    );

    // Partial read (triggers decrypt-full-cluster then copy slice path)
    let mut buf = vec![0u8; 512];
    reader.read_at(&mut buf, 256).unwrap();
    assert_eq!(buf, plaintext[256..768]);
}

// ---- Lenient mode tests ----

#[test]
fn lenient_mode_returns_zeros_on_read_error() {
    // Create an image where the L2 entry points to an offset beyond the file
    let bogus_host = 999 * CLUSTER_SIZE as u64;
    let l2_raw = bogus_host | L2_COPIED_FLAG;

    let (backend, mapper) = build_test_setup(&[(0, l2_raw)], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let mut reader = Qcow2Reader::new(
        &mapper, &backend, &backend, &mut cache, CLUSTER_BITS,
        1 << 30, COMPRESSION_DEFLATE, ReadMode::Lenient, &mut warnings,
        None, None, &StdCompressor,
    );

    let mut buf = vec![0xFF; 512];
    reader.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "lenient mode should zero-fill on error");
    assert_eq!(warnings.len(), 1, "should record one warning");
}

#[test]
fn read_beyond_virtual_size_returns_error() {
    let virtual_size = CLUSTER_SIZE as u64;
    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, virtual_size, &mut warnings);

    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, virtual_size);
    assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
}

#[test]
fn read_overflow_offset_returns_error() {
    let (backend, mapper) = build_test_setup(&[], &[]);
    let mut cache = MetadataCache::new(CacheConfig::default());
    let mut warnings = vec![];

    let mut reader = make_strict_reader(&mapper, &backend, &mut cache, u64::MAX, &mut warnings);

    let mut buf = vec![0u8; 512];
    let result = reader.read_at(&mut buf, u64::MAX - 10);
    assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
}
