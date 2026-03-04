//! Image format conversion: qcow2↔raw and qcow2→qcow2 (compact/compress).
//!
//! All conversions operate in a streaming fashion, reading and writing
//! one cluster at a time. This keeps memory usage bounded regardless
//! of image size.

use std::fs::File;
use std::path::Path;

use crate::engine::image::{CreateOptions, Qcow2Image};
use crate::error::{Error, Result};
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

/// Convert a QCOW2 image to a raw disk image.
///
/// Reads every guest cluster sequentially and writes it to the output file.
/// Unallocated and zero clusters produce zeros in the raw output.
/// If the source has a backing chain, it is resolved transparently.
pub fn convert_to_raw(input_path: &Path, output_path: &Path) -> Result<()> {
    let mut source = Qcow2Image::open(input_path)?;
    let virtual_size = source.virtual_size();
    let cluster_size = source.cluster_size() as usize;

    let output = File::create(output_path).map_err(|e| Error::ConversionFailed {
        message: format!("failed to create output file: {e}"),
    })?;
    output.set_len(virtual_size).map_err(|e| Error::ConversionFailed {
        message: format!("failed to set output file size: {e}"),
    })?;

    let backend = SyncFileBackend::from_file(output);
    let mut buf = vec![0u8; cluster_size];

    let mut offset = 0u64;
    while offset < virtual_size {
        let read_size = cluster_size.min((virtual_size - offset) as usize);
        buf[..read_size].fill(0);
        source.read_at(&mut buf[..read_size], offset)?;
        backend.write_all_at(&buf[..read_size], offset)?;
        offset += read_size as u64;
    }

    backend.flush()?;
    Ok(())
}

/// Convert a raw disk image to a QCOW2 image.
///
/// Reads the raw file in cluster-sized chunks, skips all-zero clusters,
/// and writes non-zero clusters to a fresh QCOW2 image.
/// If `compress` is true, clusters are compressed when possible.
pub fn convert_from_raw(
    input_path: &Path,
    output_path: &Path,
    compress: bool,
    compression_type: Option<u8>,
    data_file: Option<String>,
) -> Result<()> {
    let input = File::open(input_path).map_err(|e| Error::ConversionFailed {
        message: format!("failed to open raw input: {e}"),
    })?;
    let input_size = input
        .metadata()
        .map_err(|e| Error::ConversionFailed {
            message: format!("failed to read raw file size: {e}"),
        })?
        .len();

    let input_backend = SyncFileBackend::from_file(input);

    let mut dest = Qcow2Image::create(
        output_path,
        CreateOptions {
            virtual_size: input_size,
            cluster_bits: None,
            extended_l2: false, compression_type, data_file,
        },
    )?;

    let cluster_size = dest.cluster_size() as usize;
    let mut buf = vec![0u8; cluster_size];

    let mut offset = 0u64;
    while offset < input_size {
        let read_size = cluster_size.min((input_size - offset) as usize);
        buf[..read_size].fill(0);
        input_backend.read_exact_at(&mut buf[..read_size], offset)?;

        // Skip all-zero clusters
        if !is_all_zeros(&buf[..read_size]) {
            if compress {
                dest.write_cluster_maybe_compressed(&buf[..read_size], offset)?;
            } else {
                dest.write_at(&buf[..read_size], offset)?;
            }
        }
        offset += read_size as u64;
    }

    dest.flush()?;
    Ok(())
}

/// Convert (compact) a QCOW2 image to a fresh QCOW2 image.
///
/// Reads all guest data from the source and writes non-zero clusters
/// to a new QCOW2 image. This eliminates fragmentation and reclaims
/// freed cluster space. Optionally compresses clusters.
///
/// If the source has a backing chain, it is flattened into the output.
pub fn convert_qcow2_to_qcow2(
    input_path: &Path,
    output_path: &Path,
    compress: bool,
    compression_type: Option<u8>,
    data_file: Option<String>,
) -> Result<()> {
    let mut source = Qcow2Image::open(input_path)?;
    let virtual_size = source.virtual_size();

    let mut dest = Qcow2Image::create(
        output_path,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(source.cluster_bits()),
            extended_l2: source.header().has_extended_l2(),
            compression_type: Some(compression_type.unwrap_or(source.header().compression_type)),
            data_file,
        },
    )?;

    let cluster_size = source.cluster_size() as usize;
    let mut buf = vec![0u8; cluster_size];

    let mut offset = 0u64;
    while offset < virtual_size {
        let read_size = cluster_size.min((virtual_size - offset) as usize);
        buf[..read_size].fill(0);
        source.read_at(&mut buf[..read_size], offset)?;

        if !is_all_zeros(&buf[..read_size]) {
            if compress {
                dest.write_cluster_maybe_compressed(&buf[..read_size], offset)?;
            } else {
                dest.write_at(&buf[..read_size], offset)?;
            }
        }
        offset += read_size as u64;
    }

    dest.flush()?;
    Ok(())
}

/// Check if a byte slice is entirely zeros.
fn is_all_zeros(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_qcow2(dir: &Path, name: &str, data: &[(u64, &[u8])]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024, // 1 MB
                cluster_bits: None,
                extended_l2: false, compression_type: None,
            data_file: None,
            },
        )
        .unwrap();
        for &(offset, buf) in data {
            image.write_at(buf, offset).unwrap();
        }
        image.flush().unwrap();
        drop(image);
        path
    }

    #[test]
    fn convert_qcow2_to_raw_round_trip() {
        let dir = TempDir::new().unwrap();
        let qcow2_path = create_test_qcow2(dir.path(), "src.qcow2", &[(0, &[0xAA; 512])]);
        let raw_path = dir.path().join("output.raw");

        convert_to_raw(&qcow2_path, &raw_path).unwrap();

        // Verify the raw file
        let raw = std::fs::read(&raw_path).unwrap();
        assert_eq!(raw.len(), 1024 * 1024);
        assert!(raw[..512].iter().all(|&b| b == 0xAA));
        assert!(raw[512..1024].iter().all(|&b| b == 0));
    }

    #[test]
    fn convert_raw_to_qcow2_round_trip() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("input.raw");

        // Create a small raw file with some data
        let mut raw_data = vec![0u8; 1024 * 1024];
        raw_data[..512].fill(0xBB);
        std::fs::write(&raw_path, &raw_data).unwrap();

        let qcow2_path = dir.path().join("output.qcow2");
        convert_from_raw(&raw_path, &qcow2_path, false, None, None).unwrap();

        // Read back with our library
        let mut image = Qcow2Image::open(&qcow2_path).unwrap();
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        // Unwritten area should be zeros
        let mut buf2 = vec![0u8; 512];
        image.read_at(&mut buf2, 65536).unwrap();
        assert!(buf2.iter().all(|&b| b == 0));
    }

    #[test]
    fn convert_qcow2_to_qcow2_preserves_data() {
        let dir = TempDir::new().unwrap();
        let src = create_test_qcow2(
            dir.path(),
            "src.qcow2",
            &[(0, &[0xCC; 4096]), (65536, &[0xDD; 512])],
        );
        let dst = dir.path().join("dst.qcow2");

        convert_qcow2_to_qcow2(&src, &dst, false, None, None).unwrap();

        let mut image = Qcow2Image::open(&dst).unwrap();
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));

        let mut buf2 = vec![0u8; 512];
        image.read_at(&mut buf2, 65536).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn convert_zero_clusters_skipped() {
        let dir = TempDir::new().unwrap();
        // Create a raw file that is mostly zeros (1 MB — large enough that
        // QCOW2 overhead is smaller than the savings from skipping zero clusters).
        let raw_path = dir.path().join("sparse.raw");
        let mut raw_data = vec![0u8; 1024 * 1024]; // 1 MB
        raw_data[..512].fill(0xFF);
        std::fs::write(&raw_path, &raw_data).unwrap();

        let qcow2_path = dir.path().join("sparse.qcow2");
        convert_from_raw(&raw_path, &qcow2_path, false, None, None).unwrap();

        // QCOW2 file should be much smaller than raw (only 1 data cluster allocated)
        let qcow2_size = std::fs::metadata(&qcow2_path).unwrap().len();
        let raw_size = std::fs::metadata(&raw_path).unwrap().len();
        assert!(
            qcow2_size < raw_size,
            "qcow2 ({qcow2_size}) should be smaller than raw ({raw_size})"
        );
    }

    #[test]
    fn convert_raw_to_qcow2_with_compression() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("compressible.raw");

        // Create raw with highly compressible data
        let mut raw_data = vec![0u8; 256 * 1024];
        for (i, byte) in raw_data.iter_mut().enumerate() {
            *byte = (i % 4) as u8; // very repetitive
        }
        std::fs::write(&raw_path, &raw_data).unwrap();

        let uncompressed_path = dir.path().join("uncompressed.qcow2");
        let compressed_path = dir.path().join("compressed.qcow2");

        convert_from_raw(&raw_path, &uncompressed_path, false, None, None).unwrap();
        convert_from_raw(&raw_path, &compressed_path, true, None, None).unwrap();

        let uncompressed_size = std::fs::metadata(&uncompressed_path).unwrap().len();
        let compressed_size = std::fs::metadata(&compressed_path).unwrap().len();

        assert!(
            compressed_size < uncompressed_size,
            "compressed ({compressed_size}) should be smaller than uncompressed ({uncompressed_size})"
        );

        // Verify data integrity of compressed image
        let mut image = Qcow2Image::open(&compressed_path).unwrap();
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        let expected: Vec<u8> = (0..512).map(|i| (i % 4) as u8).collect();
        assert_eq!(&buf, &expected[..]);
    }

    #[test]
    fn is_all_zeros_works() {
        assert!(is_all_zeros(&[0, 0, 0, 0]));
        assert!(!is_all_zeros(&[0, 0, 1, 0]));
        assert!(is_all_zeros(&[]));
    }
}
