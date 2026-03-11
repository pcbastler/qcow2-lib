//! Tests for metadata_io helper functions.

use crate::engine::cache::{CacheConfig, CacheMode, MetadataCache};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::types::ClusterOffset;
use crate::io::MemoryBackend;
use crate::IoBackend;
use byteorder::{BigEndian, ByteOrder};
use qcow2_core::engine::metadata_io;

const CLUSTER_BITS: u32 = 16;
const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;

fn make_header() -> Header {
    Header {
        version: 3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits: CLUSTER_BITS,
        virtual_size: 1 << 30,
        crypt_method: 0,
        l1_table_entries: 1,
        l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
        refcount_table_offset: ClusterOffset(2 * CLUSTER_SIZE as u64),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: IncompatibleFeatures::empty(),
        compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
        autoclear_features: AutoclearFeatures::empty(),
        refcount_order: 4,
        header_length: 104,
        compression_type: 0,
    }
}

// ---- write_header_extensions ----

#[test]
fn write_header_extensions_success() {
    let backend = MemoryBackend::new(vec![0u8; CLUSTER_SIZE]);
    let header = make_header();
    let extensions = vec![]; // Empty extensions = just the terminator

    metadata_io::write_header_extensions(&backend, &header, &extensions, CLUSTER_SIZE as u64)
        .unwrap();

    // Verify the terminator was written at header_length offset
    let mut buf = vec![0u8; 8];
    backend.read_exact_at(&mut buf, header.header_length as u64).unwrap();
    // Terminator extension: type=0, length=0
    assert_eq!(BigEndian::read_u32(&buf[0..4]), 0);
    assert_eq!(BigEndian::read_u32(&buf[4..8]), 0);
}

#[test]
fn write_header_extensions_overflow_error() {
    let backend = MemoryBackend::new(vec![0u8; CLUSTER_SIZE]);
    let mut header = make_header();
    // Set header_length to nearly the cluster size so extensions don't fit
    header.header_length = (CLUSTER_SIZE - 4) as u32;

    // Create an extension that will overflow
    let ext = HeaderExtension::Unknown {
        extension_type: 0x12345678,
        data: vec![0xAA; 100],
    };

    let result = metadata_io::write_header_extensions(
        &backend,
        &header,
        &[ext],
        CLUSTER_SIZE as u64,
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("header extensions")
        || err.to_string().contains("exceed cluster"),
        "unexpected error: {err}");
}

// ---- write_autoclear_features ----

#[test]
fn write_autoclear_features_roundtrip() {
    let data = vec![0u8; 256];
    let backend = MemoryBackend::new(data);

    let features = AutoclearFeatures::BITMAPS;
    metadata_io::write_autoclear_features(&backend, features).unwrap();

    // Read back from offset 88
    let mut buf = [0u8; 8];
    backend.read_exact_at(&mut buf, 88).unwrap();
    let value = BigEndian::read_u64(&buf);
    assert_eq!(value, features.bits());
}

#[test]
fn write_autoclear_features_empty() {
    let data = vec![0xFF; 256];
    let backend = MemoryBackend::new(data);

    metadata_io::write_autoclear_features(&backend, AutoclearFeatures::empty()).unwrap();

    let mut buf = [0u8; 8];
    backend.read_exact_at(&mut buf, 88).unwrap();
    assert_eq!(BigEndian::read_u64(&buf), 0);
}

// ---- write_incompatible_features ----

#[test]
fn write_incompatible_features_roundtrip() {
    let data = vec![0u8; 256];
    let backend = MemoryBackend::new(data);

    let features = IncompatibleFeatures::DIRTY;
    metadata_io::write_incompatible_features(&backend, features).unwrap();

    // Read back from offset 72
    let mut buf = [0u8; 8];
    backend.read_exact_at(&mut buf, 72).unwrap();
    let value = BigEndian::read_u64(&buf);
    assert_eq!(value, features.bits());
}

#[test]
fn write_incompatible_features_multiple_flags() {
    let data = vec![0u8; 256];
    let backend = MemoryBackend::new(data);

    let features = IncompatibleFeatures::DIRTY | IncompatibleFeatures::CORRUPT;
    metadata_io::write_incompatible_features(&backend, features).unwrap();

    let mut buf = [0u8; 8];
    backend.read_exact_at(&mut buf, 72).unwrap();
    let value = BigEndian::read_u64(&buf);
    assert_eq!(value, features.bits());
    assert_ne!(value, 0);
}

// ---- flush_dirty_metadata ----

#[test]
fn flush_dirty_metadata_empty_cache() {
    let data = vec![0u8; 4 * CLUSTER_SIZE];
    let backend = MemoryBackend::new(data);
    let mut cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteBack,
        ..CacheConfig::default()
    });

    // Flush empty cache should succeed (no-op)
    metadata_io::flush_dirty_metadata(&backend, &mut cache, CLUSTER_BITS).unwrap();
}

#[test]
fn flush_dirty_metadata_writes_dirty_l2() {
    use crate::format::l2::L2Table;
    use crate::format::types::ClusterGeometry;

    let data = vec![0u8; 8 * CLUSTER_SIZE];
    let backend = MemoryBackend::new(data);
    let mut cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteBack,
        ..CacheConfig::default()
    });

    // Create and insert a dirty L2 table
    let geo = ClusterGeometry { cluster_bits: CLUSTER_BITS, extended_l2: false };
    let l2_table = L2Table::new_empty(geo);
    let l2_offset = ClusterOffset(4 * CLUSTER_SIZE as u64);
    cache.insert_l2_table(l2_offset, l2_table, true);

    // Flush should write the dirty L2 table
    metadata_io::flush_dirty_metadata(&backend, &mut cache, CLUSTER_BITS).unwrap();

    // Read back and verify — after flush, the entry should no longer be dirty
    let (dirty_l2, _) = cache.drain_dirty();
    assert!(dirty_l2.is_empty(), "no dirty entries should remain after flush");
}

#[test]
fn flush_dirty_metadata_writes_dirty_refcount_block() {
    use crate::format::refcount::RefcountBlock;

    let data = vec![0u8; 8 * CLUSTER_SIZE];
    let backend = MemoryBackend::new(data);
    let mut cache = MetadataCache::new(CacheConfig {
        mode: CacheMode::WriteBack,
        ..CacheConfig::default()
    });

    // Create and insert a dirty refcount block
    let rc_block = RefcountBlock::new_empty(CLUSTER_SIZE, 4);
    let rc_offset = ClusterOffset(3 * CLUSTER_SIZE as u64);
    cache.insert_refcount_block(rc_offset, rc_block, true);

    // Flush should write the dirty refcount block
    metadata_io::flush_dirty_metadata(&backend, &mut cache, CLUSTER_BITS).unwrap();

    // Verify no dirty entries remain
    let (_, dirty_rc) = cache.drain_dirty();
    assert!(dirty_rc.is_empty(), "no dirty refcount entries should remain after flush");
}
