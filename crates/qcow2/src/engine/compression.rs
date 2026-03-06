//! Compressed cluster decompression and compression.
//!
//! QCOW2 supports two compression algorithms:
//! - **Deflate** (type 0): Raw deflate (RFC 1951), not zlib/gzip. Default.
//! - **Zstandard** (type 1): Zstd compression. Available since QEMU 5.0.
//!
//! Each compressed cluster decompresses to exactly one cluster of data.

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{Read, Write};

use crate::error::{decompress_error, io_error, Error, FormatError, Result};
use crate::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};
use crate::io::Compressor;

/// Decompress a QCOW2 compressed cluster.
///
/// # Arguments
/// * `compressed_data` - Compressed bytes read from the host file
/// * `cluster_size` - Expected uncompressed size (one full cluster)
/// * `guest_offset` - Guest offset for error context
/// * `compression_type` - 0 = deflate, 1 = zstandard
pub fn decompress_cluster(
    compressed_data: &[u8],
    cluster_size: usize,
    guest_offset: u64,
    compression_type: u8,
) -> Result<Vec<u8>> {
    match compression_type {
        COMPRESSION_DEFLATE => {
            let mut decoder = DeflateDecoder::new(compressed_data);
            let mut decompressed = vec![0u8; cluster_size];
            decoder
                .read_exact(&mut decompressed)
                .map_err(|e| decompress_error(e, guest_offset))?;
            Ok(decompressed)
        }
        COMPRESSION_ZSTD => {
            let cursor = std::io::Cursor::new(compressed_data);
            let mut decoder =
                zstd::Decoder::new(cursor).map_err(|e| decompress_error(e, guest_offset))?;
            let mut decompressed = vec![0u8; cluster_size];
            decoder
                .read_exact(&mut decompressed)
                .map_err(|e| decompress_error(e, guest_offset))?;
            Ok(decompressed)
        }
        _ => Err(FormatError::UnsupportedCompressionType { compression_type }.into()),
    }
}

/// Compress a full cluster of data.
///
/// Returns `Some(compressed_bytes)` if compression reduces the size below
/// `cluster_size`. Returns `None` if the compressed output is not smaller.
pub fn compress_cluster(
    data: &[u8],
    cluster_size: usize,
    compression_type: u8,
) -> Result<Option<Vec<u8>>> {
    let compressed = match compression_type {
        COMPRESSION_DEFLATE => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| io_error(e, 0, "compressing cluster data"))?;
            encoder
                .finish()
                .map_err(|e| io_error(e, 0, "finishing deflate compression"))?
        }
        COMPRESSION_ZSTD => zstd::bulk::compress(data, 3)
            .map_err(|e| io_error(e, 0, "zstd compression"))?,
        _ => return Err(FormatError::UnsupportedCompressionType { compression_type }.into()),
    };

    if compressed.len() >= cluster_size {
        return Ok(None);
    }

    Ok(Some(compressed))
}

/// Standard compression backend implementing the core [`Compressor`] trait.
///
/// Provides deflate (flate2) and zstandard (zstd) support for the core engine.
pub struct StdCompressor;

impl Compressor for StdCompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
        compression_type: u8,
    ) -> qcow2_core::Result<usize> {
        let cluster_size = output.len();
        let decompressed = decompress_cluster(input, cluster_size, 0, compression_type)?;
        output.copy_from_slice(&decompressed);
        Ok(cluster_size)
    }

    fn compress(
        &self,
        input: &[u8],
        output: &mut [u8],
        compression_type: u8,
    ) -> qcow2_core::Result<usize> {
        match compress_cluster(input, input.len(), compression_type)? {
            Some(compressed) => {
                let len = compressed.len();
                output[..len].copy_from_slice(&compressed);
                Ok(len)
            }
            None => Err(Error::CompressionTooLarge {
                compressed_size: input.len(),
                cluster_size: input.len(),
                guest_offset: 0,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Deflate tests ----

    #[test]
    fn deflate_compress_decompress_round_trip() {
        let cluster_size = 4096;
        let original: Vec<u8> = (0..cluster_size).map(|i| (i % 256) as u8).collect();

        let compressed = compress_cluster(&original, cluster_size, COMPRESSION_DEFLATE)
            .unwrap()
            .expect("patterned data should compress");

        assert!(compressed.len() < cluster_size);

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_decompress_all_zeros() {
        let cluster_size = 65536;
        let original = vec![0u8; cluster_size];

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_decompress_bad_data_returns_error() {
        let bad_data = vec![0xFF, 0xFE, 0xFD];
        let result = decompress_cluster(&bad_data, 4096, 0x1000, COMPRESSION_DEFLATE);
        assert!(result.is_err());

        match result {
            Err(Error::DecompressionFailed {
                guest_offset: 0x1000,
                ..
            }) => {}
            other => panic!("expected DecompressionFailed, got {other:?}"),
        }
    }

    #[test]
    fn deflate_decompress_empty_input_fails() {
        let result = decompress_cluster(&[], 4096, 0, COMPRESSION_DEFLATE);
        assert!(matches!(result, Err(Error::DecompressionFailed { .. })));
    }

    #[test]
    fn deflate_decompress_single_byte_input_fails() {
        let result = decompress_cluster(&[0x42], 4096, 0, COMPRESSION_DEFLATE);
        assert!(matches!(result, Err(Error::DecompressionFailed { .. })));
    }

    #[test]
    fn deflate_decompress_with_larger_cluster_size() {
        let original = vec![0xAA; 4096];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_cluster(&compressed, 65536, 0, COMPRESSION_DEFLATE);
        assert!(matches!(result, Err(Error::DecompressionFailed { .. })));
    }

    #[test]
    fn deflate_decompress_random_like_data() {
        let cluster_size = 4096;
        let mut original = vec![0u8; cluster_size];
        let mut val = 0x12345678u32;
        for byte in original.iter_mut() {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (val >> 16) as u8;
        }

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_decompress_max_cluster_size() {
        let cluster_size = 1 << 21; // 2 MB
        let original = vec![0u8; cluster_size];

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_compress_all_zeros_round_trip() {
        let cluster_size = 65536;
        let original = vec![0u8; cluster_size];
        let compressed = compress_cluster(&original, cluster_size, COMPRESSION_DEFLATE)
            .unwrap()
            .unwrap();
        assert!(compressed.len() < cluster_size);

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_compress_incompressible_returns_none() {
        let cluster_size = 4096;
        let mut data = vec![0u8; cluster_size];
        let mut val = 0xDEADBEEFu32;
        for byte in data.iter_mut() {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (val >> 16) as u8;
        }

        let result = compress_cluster(&data, cluster_size, COMPRESSION_DEFLATE).unwrap();
        assert!(result.is_none(), "random data should not compress well");
    }

    #[test]
    fn deflate_compress_repetitive_data_compresses_well() {
        let cluster_size = 65536;
        let data: Vec<u8> = (0..cluster_size).map(|i| (i % 4) as u8).collect();
        let compressed = compress_cluster(&data, cluster_size, COMPRESSION_DEFLATE)
            .unwrap()
            .unwrap();
        assert!(
            compressed.len() < cluster_size / 4,
            "repetitive data should compress significantly: {} vs {}",
            compressed.len(),
            cluster_size
        );
    }

    #[test]
    fn deflate_compress_various_cluster_sizes() {
        for cluster_bits in [9, 12, 16] {
            let cluster_size = 1usize << cluster_bits;
            let data = vec![0xAA; cluster_size];
            let compressed = compress_cluster(&data, cluster_size, COMPRESSION_DEFLATE)
                .unwrap()
                .unwrap();
            let decompressed =
                decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_DEFLATE).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    // ---- Zstandard tests ----

    #[test]
    fn zstd_compress_decompress_round_trip() {
        let cluster_size = 4096;
        let original: Vec<u8> = (0..cluster_size).map(|i| (i % 256) as u8).collect();

        let compressed = compress_cluster(&original, cluster_size, COMPRESSION_ZSTD)
            .unwrap()
            .expect("patterned data should compress");

        assert!(compressed.len() < cluster_size);

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_ZSTD).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn zstd_compress_all_zeros_round_trip() {
        let cluster_size = 65536;
        let original = vec![0u8; cluster_size];
        let compressed = compress_cluster(&original, cluster_size, COMPRESSION_ZSTD)
            .unwrap()
            .unwrap();
        assert!(compressed.len() < cluster_size);

        let decompressed =
            decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_ZSTD).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn zstd_compress_incompressible_returns_none() {
        let cluster_size = 4096;
        let mut data = vec![0u8; cluster_size];
        let mut val = 0xCAFEBABEu32;
        for byte in data.iter_mut() {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (val >> 16) as u8;
        }

        let result = compress_cluster(&data, cluster_size, COMPRESSION_ZSTD).unwrap();
        assert!(result.is_none(), "random data should not compress well");
    }

    #[test]
    fn zstd_decompress_bad_data_returns_error() {
        let bad_data = vec![0xFF, 0xFE, 0xFD];
        let result = decompress_cluster(&bad_data, 4096, 0x2000, COMPRESSION_ZSTD);
        assert!(matches!(result, Err(Error::DecompressionFailed { .. })));
    }

    #[test]
    fn zstd_compress_various_cluster_sizes() {
        for cluster_bits in [12, 16, 18] {
            let cluster_size = 1usize << cluster_bits;
            let data = vec![0xBB; cluster_size];
            let compressed = compress_cluster(&data, cluster_size, COMPRESSION_ZSTD)
                .unwrap()
                .unwrap();
            let decompressed =
                decompress_cluster(&compressed, cluster_size, 0, COMPRESSION_ZSTD).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn zstd_decompress_with_sector_padding() {
        let cluster_size = 65536;
        let original = vec![0xCC; cluster_size];
        let compressed = compress_cluster(&original, cluster_size, COMPRESSION_ZSTD)
            .unwrap()
            .unwrap();

        let sector_aligned = ((compressed.len() + 511) & !511).max(512);
        let mut padded = vec![0u8; sector_aligned];
        padded[..compressed.len()].copy_from_slice(&compressed);

        let decompressed =
            decompress_cluster(&padded, cluster_size, 0, COMPRESSION_ZSTD).unwrap();
        assert_eq!(decompressed, original);
    }

    // ---- Cross-algorithm tests ----

    #[test]
    fn unsupported_compression_type_decompress() {
        let result = decompress_cluster(&[0x00], 4096, 0, 99);
        assert!(matches!(
            result,
            Err(Error::Format(FormatError::UnsupportedCompressionType {
                compression_type: 99
            }))
        ));
    }

    #[test]
    fn unsupported_compression_type_compress() {
        let result = compress_cluster(&[0x00; 4096], 4096, 42);
        assert!(matches!(
            result,
            Err(Error::Format(FormatError::UnsupportedCompressionType {
                compression_type: 42
            }))
        ));
    }
}
