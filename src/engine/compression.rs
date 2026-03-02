//! Compressed cluster decompression.
//!
//! QCOW2 uses raw deflate (not zlib, not gzip) for compressed clusters.
//! Each compressed cluster decompresses to exactly one cluster of data.

use flate2::read::DeflateDecoder;
use std::io::Read;

use crate::error::{Error, Result};

/// Decompress a QCOW2 compressed cluster.
///
/// QCOW2 compression uses raw deflate (RFC 1951). The input is the
/// compressed bytes read from the host file; the output is a full
/// cluster of uncompressed data.
///
/// # Arguments
/// * `compressed_data` - Raw deflate-compressed bytes
/// * `cluster_size` - Expected uncompressed size (one full cluster)
/// * `guest_offset` - Guest offset for error context
pub fn decompress_cluster(
    compressed_data: &[u8],
    cluster_size: usize,
    guest_offset: u64,
) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed_data);
    let mut decompressed = vec![0u8; cluster_size];
    decoder.read_exact(&mut decompressed).map_err(|e| {
        Error::DecompressionFailed {
            source: e,
            guest_offset,
        }
    })?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn compress_decompress_round_trip() {
        let cluster_size = 4096;
        let original: Vec<u8> = (0..cluster_size).map(|i| (i % 256) as u8).collect();

        // Compress with deflate
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Decompress with our function
        let decompressed = decompress_cluster(&compressed, cluster_size, 0).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_all_zeros() {
        let cluster_size = 65536;
        let original = vec![0u8; cluster_size];

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_cluster(&compressed, cluster_size, 0).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_bad_data_returns_error() {
        let bad_data = vec![0xFF, 0xFE, 0xFD]; // Not valid deflate
        let result = decompress_cluster(&bad_data, 4096, 0x1000);
        assert!(result.is_err());

        match result {
            Err(Error::DecompressionFailed {
                guest_offset: 0x1000,
                ..
            }) => {}
            other => panic!("expected DecompressionFailed, got {other:?}"),
        }
    }
}
