//! Tests for corrupt compressed data handling.
//!
//! Verifies that decompress_cluster returns proper errors for invalid data,
//! and that CompressedClusterDescriptor encode/decode round-trips correctly.

use qcow2_lib::engine::compression::{compress_cluster, decompress_cluster};
use qcow2_lib::format::compressed::CompressedClusterDescriptor;
use qcow2_lib::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};

const CLUSTER_SIZE: usize = 65536;

// ---- Decompression error handling ----

#[test]
fn decompress_bad_deflate_data() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
    let result = decompress_cluster(&garbage, CLUSTER_SIZE, 0, COMPRESSION_DEFLATE);
    assert!(result.is_err(), "garbage data should fail deflate decompression");
}

#[test]
fn decompress_bad_zstd_data() {
    let garbage = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x99, 0x88, 0x77, 0x66];
    let result = decompress_cluster(&garbage, CLUSTER_SIZE, 0, COMPRESSION_ZSTD);
    assert!(result.is_err(), "garbage data should fail zstd decompression");
}

#[test]
fn decompress_truncated_deflate() {
    // Compress valid data, then truncate the result
    let data = vec![0xAA; CLUSTER_SIZE];
    if let Ok(Some(compressed)) = compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE) {
        let truncated = &compressed[..compressed.len() / 2];
        let result = decompress_cluster(truncated, CLUSTER_SIZE, 0, COMPRESSION_DEFLATE);
        assert!(result.is_err(), "truncated data should fail decompression");
    }
}

#[test]
fn decompress_truncated_zstd() {
    let data = vec![0xBB; CLUSTER_SIZE];
    if let Ok(Some(compressed)) = compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_ZSTD) {
        let truncated = &compressed[..compressed.len() / 2];
        let result = decompress_cluster(truncated, CLUSTER_SIZE, 0, COMPRESSION_ZSTD);
        assert!(result.is_err(), "truncated zstd data should fail decompression");
    }
}

#[test]
fn decompress_empty_data_deflate() {
    let result = decompress_cluster(&[], CLUSTER_SIZE, 0, COMPRESSION_DEFLATE);
    assert!(result.is_err(), "empty data should fail deflate decompression");
}

#[test]
fn decompress_empty_data_zstd() {
    let result = decompress_cluster(&[], CLUSTER_SIZE, 0, COMPRESSION_ZSTD);
    assert!(result.is_err(), "empty data should fail zstd decompression");
}

#[test]
fn decompress_single_byte_deflate() {
    let result = decompress_cluster(&[0x00], CLUSTER_SIZE, 0, COMPRESSION_DEFLATE);
    assert!(result.is_err(), "single byte should fail deflate decompression");
}

#[test]
fn decompress_single_byte_zstd() {
    let result = decompress_cluster(&[0x00], CLUSTER_SIZE, 0, COMPRESSION_ZSTD);
    assert!(result.is_err(), "single byte should fail zstd decompression");
}

// ---- Valid round-trips ----

#[test]
fn valid_compressed_roundtrip_deflate() {
    let mut data = vec![0u8; CLUSTER_SIZE];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 127) as u8;
    }
    let compressed = compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_DEFLATE)
        .unwrap()
        .expect("data should be compressible");
    let decompressed = decompress_cluster(&compressed, CLUSTER_SIZE, 0, COMPRESSION_DEFLATE).unwrap();
    assert_eq!(data, decompressed);
}

#[test]
fn valid_compressed_roundtrip_zstd() {
    let mut data = vec![0u8; CLUSTER_SIZE];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 127) as u8;
    }
    let compressed = compress_cluster(&data, CLUSTER_SIZE, COMPRESSION_ZSTD)
        .unwrap()
        .expect("data should be compressible");
    let decompressed = decompress_cluster(&compressed, CLUSTER_SIZE, 0, COMPRESSION_ZSTD).unwrap();
    assert_eq!(data, decompressed);
}

// ---- CompressedClusterDescriptor encode/decode ----

#[test]
fn compressed_descriptor_roundtrip_all_cluster_bits() {
    // Use minimum compressed size (1 sector = 512 bytes) which fits all cluster_bits
    for cluster_bits in 9..=21u32 {
        let desc = CompressedClusterDescriptor {
            host_offset: 0x1000,
            compressed_size: 512, // 1 sector — always fits
        };
        let encoded = desc.encode(cluster_bits);
        let decoded = CompressedClusterDescriptor::decode(encoded, cluster_bits);
        assert_eq!(
            desc.host_offset, decoded.host_offset,
            "host_offset mismatch at cluster_bits={cluster_bits}"
        );
        assert_eq!(
            desc.compressed_size, decoded.compressed_size,
            "compressed_size mismatch at cluster_bits={cluster_bits}"
        );
    }
}

#[test]
fn compressed_descriptor_various_offsets() {
    let cluster_bits = 16u32;
    // compressed_size must be a multiple of 512 (sector size)
    let test_cases = [
        (0u64, 512u64),
        (65536, 1024),
        (1 << 30, 8192),
        (0, 512),
    ];
    for (offset, size) in test_cases {
        let desc = CompressedClusterDescriptor {
            host_offset: offset,
            compressed_size: size,
        };
        let encoded = desc.encode(cluster_bits);
        let decoded = CompressedClusterDescriptor::decode(encoded, cluster_bits);
        assert_eq!(desc.host_offset, decoded.host_offset);
        assert_eq!(desc.compressed_size, decoded.compressed_size);
    }
}
