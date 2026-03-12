//! Image format conversion: qcow2↔raw and qcow2→qcow2 (compact/compress).
//!
//! All conversions operate in a streaming fashion, reading and writing
//! one cluster at a time. This keeps memory usage bounded regardless
//! of image size.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crate::engine::image::{CreateOptions, EncryptionOptions, Qcow2Image};
use crate::engine::image_async::Qcow2ImageAsync;
use crate::error::{Error, Result};
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

/// Convert a QCOW2 image to a raw disk image.
///
/// Reads every guest cluster sequentially and writes it to the output file.
/// Unallocated and zero clusters produce zeros in the raw output.
/// If the source has a backing chain, it is resolved transparently.
/// Pass `password` to open an encrypted source image.
pub fn convert_to_raw(
    input_path: &Path,
    output_path: &Path,
    password: Option<&[u8]>,
) -> Result<()> {
    let mut source = if let Some(pw) = password {
        Qcow2Image::open_with_password(input_path, pw)?
    } else {
        Qcow2Image::open(input_path)?
    };
    let virtual_size = source.virtual_size();
    let cluster_size = source.cluster_size() as usize;

    let output = File::create(output_path).map_err(|e| Error::ConversionFailed {
        message: format!("failed to create output file: {e}"),
    })?;
    output.set_len(virtual_size).map_err(|e| Error::ConversionFailed {
        message: format!("failed to set output file size: {e}"),
    })?;

    let backend = SyncFileBackend::from_file(output);

    // Read in large batches to reduce syscall overhead
    let batch_clusters = 64; // 4MB at 64KB clusters
    let batch_size = batch_clusters * cluster_size;
    let mut buf = vec![0u8; batch_size];

    let mut offset = 0u64;
    while offset < virtual_size {
        let read_size = batch_size.min((virtual_size - offset) as usize);
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
    encryption: Option<EncryptionOptions>,
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
            extended_l2: false, compression_type, data_file, encryption,
        },
    )?;

    let cluster_size = dest.cluster_size() as usize;

    if compress {
        // Compressed path: must write one cluster at a time
        let mut buf = vec![0u8; cluster_size];
        let mut offset = 0u64;
        while offset < input_size {
            let read_size = cluster_size.min((input_size - offset) as usize);
            buf[..read_size].fill(0);
            input_backend.read_exact_at(&mut buf[..read_size], offset)?;
            if !is_all_zeros(&buf[..read_size]) {
                dest.write_cluster_maybe_compressed(&buf[..read_size], offset)?;
            }
            offset += read_size as u64;
        }
    } else {
        // Uncompressed path: read large batches, write contiguous non-zero runs
        let batch_clusters = 64; // 64 clusters = 4MB at 64KB cluster size
        let batch_size = batch_clusters * cluster_size;
        let mut buf = vec![0u8; batch_size];

        let mut offset = 0u64;
        while offset < input_size {
            let read_size = batch_size.min((input_size - offset) as usize);
            buf[..read_size].fill(0);
            input_backend.read_exact_at(&mut buf[..read_size], offset)?;

            // Find contiguous runs of non-zero clusters and write them as one call
            let mut pos = 0usize;
            while pos < read_size {
                let chunk = cluster_size.min(read_size - pos);

                if is_all_zeros(&buf[pos..pos + chunk]) {
                    pos += chunk;
                    continue;
                }

                // Found a non-zero cluster — extend run as far as possible
                let run_start = pos;
                pos += chunk;
                while pos < read_size {
                    let next_chunk = cluster_size.min(read_size - pos);
                    if is_all_zeros(&buf[pos..pos + next_chunk]) {
                        break;
                    }
                    pos += next_chunk;
                }

                // Write the entire non-zero run in one call
                let run_offset = offset + run_start as u64;
                dest.write_at(&buf[run_start..pos], run_offset)?;
            }
            offset += read_size as u64;
        }
    }

    dest.flush()?;
    Ok(())
}

/// Convert a raw disk image to a QCOW2 image using parallel writes.
///
/// Splits the input into L2-range-sized chunks and processes them in parallel
/// using `thread::scope`. Each thread reads from the raw input (lock-free pread)
/// and writes to the QCOW2 output via `Qcow2ImageAsync` (per-L2 locking).
///
/// Compressed writes are also parallelized: each thread compresses clusters
/// independently (CPU-bound), then writes the compressed data under the meta
/// mutex with full packing support (`compressed_cursor`).
pub fn convert_from_raw_parallel(
    input_path: &Path,
    output_path: &Path,
    compress: bool,
    compression_type: Option<u8>,
    data_file: Option<String>,
    encryption: Option<EncryptionOptions>,
    num_threads: usize,
) -> Result<()> {
    if num_threads <= 1 {
        return convert_from_raw(input_path, output_path, compress, compression_type, data_file, encryption);
    }

    let input = File::open(input_path).map_err(|e| Error::ConversionFailed {
        message: format!("failed to open raw input: {e}"),
    })?;
    let input_size = input
        .metadata()
        .map_err(|e| Error::ConversionFailed {
            message: format!("failed to read raw file size: {e}"),
        })?
        .len();

    let input_backend = Arc::new(SyncFileBackend::from_file(input));

    let dest = Qcow2Image::create(
        output_path,
        CreateOptions {
            virtual_size: input_size,
            cluster_bits: None,
            extended_l2: false,
            compression_type,
            data_file,
            encryption,
        },
    )?;

    let cluster_size = dest.cluster_size() as usize;
    let dest_async = Arc::new(Qcow2ImageAsync::from_image(dest)?);

    // Split work into chunks aligned to batch boundaries
    let batch_clusters = 64usize; // 4 MB batches
    let batch_size = batch_clusters * cluster_size;
    let total_batches = (input_size as usize + batch_size - 1) / batch_size;
    let batches_per_thread = (total_batches + num_threads - 1) / num_threads;

    let result: Result<()> = std::thread::scope(|s| {
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let start_batch = t * batches_per_thread;
            if start_batch >= total_batches {
                break;
            }
            let end_batch = ((t + 1) * batches_per_thread).min(total_batches);
            let start_offset = start_batch as u64 * batch_size as u64;
            let end_offset = (end_batch as u64 * batch_size as u64).min(input_size);

            let input_be = Arc::clone(&input_backend);
            let dest = Arc::clone(&dest_async);

            handles.push(s.spawn(move || {
                process_raw_range(
                    input_be.as_ref(), &dest, start_offset, end_offset,
                    cluster_size, batch_size, compress,
                )
            }));
        }

        // Collect results
        for handle in handles {
            handle.join().map_err(|_| Error::ConversionFailed {
                message: "worker thread panicked".into(),
            })??;
        }

        Ok(())
    });

    result?;
    dest_async.flush()?;

    // Convert back to sync image for proper Drop/cleanup
    let _image = Arc::try_unwrap(dest_async)
        .map_err(|_| Error::ConversionFailed {
            message: "failed to unwrap Arc".into(),
        })?
        .into_image();

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
    password: Option<&[u8]>,
    encryption: Option<EncryptionOptions>,
) -> Result<()> {
    let mut source = if let Some(pw) = password {
        Qcow2Image::open_with_password(input_path, pw)?
    } else {
        Qcow2Image::open(input_path)?
    };
    let virtual_size = source.virtual_size();

    let mut dest = Qcow2Image::create(
        output_path,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(source.cluster_bits()),
            extended_l2: source.header().has_extended_l2(),
            compression_type: Some(compression_type.unwrap_or(source.header().compression_type)),
            data_file, encryption,
        },
    )?;

    let cluster_size = source.cluster_size() as usize;

    if compress {
        // Compressed path: must write one cluster at a time
        let mut buf = vec![0u8; cluster_size];
        let mut offset = 0u64;
        while offset < virtual_size {
            let read_size = cluster_size.min((virtual_size - offset) as usize);
            buf[..read_size].fill(0);
            source.read_at(&mut buf[..read_size], offset)?;
            if !is_all_zeros(&buf[..read_size]) {
                dest.write_cluster_maybe_compressed(&buf[..read_size], offset)?;
            }
            offset += read_size as u64;
        }
    } else {
        // Uncompressed path: large batches with run coalescing
        let batch_clusters = 64;
        let batch_size = batch_clusters * cluster_size;
        let mut buf = vec![0u8; batch_size];

        let mut offset = 0u64;
        while offset < virtual_size {
            let read_size = batch_size.min((virtual_size - offset) as usize);
            buf[..read_size].fill(0);
            source.read_at(&mut buf[..read_size], offset)?;

            let mut pos = 0usize;
            while pos < read_size {
                let chunk = cluster_size.min(read_size - pos);
                if is_all_zeros(&buf[pos..pos + chunk]) {
                    pos += chunk;
                    continue;
                }
                let run_start = pos;
                pos += chunk;
                while pos < read_size {
                    let next_chunk = cluster_size.min(read_size - pos);
                    if is_all_zeros(&buf[pos..pos + next_chunk]) {
                        break;
                    }
                    pos += next_chunk;
                }
                let run_offset = offset + run_start as u64;
                dest.write_at(&buf[run_start..pos], run_offset)?;
            }
            offset += read_size as u64;
        }
    }

    dest.flush()?;
    Ok(())
}

/// Process a range of batches: read from input, skip zeros, write non-zero data to dest.
///
/// When `compress` is true, writes one cluster at a time via
/// `write_cluster_maybe_compressed` (compression runs in the calling thread,
/// only the small compressed write is serialized by the meta mutex).
/// When `compress` is false, coalesces non-zero runs for larger batch writes.
fn process_raw_range(
    input: &dyn IoBackend,
    dest: &Qcow2ImageAsync,
    start_offset: u64,
    end_offset: u64,
    cluster_size: usize,
    batch_size: usize,
    compress: bool,
) -> Result<()> {
    let mut buf = vec![0u8; batch_size];
    let mut offset = start_offset;

    while offset < end_offset {
        let read_size = batch_size.min((end_offset - offset) as usize);
        buf[..read_size].fill(0);
        input.read_exact_at(&mut buf[..read_size], offset)?;

        let mut pos = 0usize;
        while pos < read_size {
            let chunk = cluster_size.min(read_size - pos);

            if is_all_zeros(&buf[pos..pos + chunk]) {
                pos += chunk;
                continue;
            }

            if compress {
                // Compressed path: one cluster at a time
                dest.write_cluster_maybe_compressed(
                    &buf[pos..pos + chunk],
                    offset + pos as u64,
                )?;
                pos += chunk;
            } else {
                // Uncompressed path: coalesce non-zero runs
                let run_start = pos;
                pos += chunk;
                while pos < read_size {
                    let next_chunk = cluster_size.min(read_size - pos);
                    if is_all_zeros(&buf[pos..pos + next_chunk]) {
                        break;
                    }
                    pos += next_chunk;
                }
                let run_offset = offset + run_start as u64;
                dest.write_at(&buf[run_start..pos], run_offset)?;
            }
        }
        offset += read_size as u64;
    }
    Ok(())
}

/// Check if a byte slice is entirely zeros (word-at-a-time for speed).
fn is_all_zeros(buf: &[u8]) -> bool {
    // Check 8 bytes at a time using u64
    let (prefix, chunks, suffix) = unsafe { buf.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && chunks.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
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
            data_file: None, encryption: None,
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

        convert_to_raw(&qcow2_path, &raw_path, None).unwrap();

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
        convert_from_raw(&raw_path, &qcow2_path, false, None, None, None).unwrap();

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

        convert_qcow2_to_qcow2(&src, &dst, false, None, None, None, None).unwrap();

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
        convert_from_raw(&raw_path, &qcow2_path, false, None, None, None).unwrap();

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

        convert_from_raw(&raw_path, &uncompressed_path, false, None, None, None).unwrap();
        convert_from_raw(&raw_path, &compressed_path, true, None, None, None).unwrap();

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

    #[test]
    fn convert_raw_to_qcow2_parallel_round_trip() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("input.raw");

        let mut raw_data = vec![0u8; 1024 * 1024];
        raw_data[..512].fill(0xBB);
        raw_data[65536..65536 + 1024].fill(0xCC);
        std::fs::write(&raw_path, &raw_data).unwrap();

        let qcow2_path = dir.path().join("parallel.qcow2");
        convert_from_raw_parallel(&raw_path, &qcow2_path, false, None, None, None, 4).unwrap();

        let mut image = Qcow2Image::open(&qcow2_path).unwrap();
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        let mut buf2 = vec![0u8; 1024];
        image.read_at(&mut buf2, 65536).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xCC));

        // Zero area
        let mut buf3 = vec![0u8; 512];
        image.read_at(&mut buf3, 131072).unwrap();
        assert!(buf3.iter().all(|&b| b == 0));
    }

    #[test]
    fn convert_parallel_matches_sequential() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("input.raw");

        // Create raw with scattered non-zero data
        let mut raw_data = vec![0u8; 512 * 1024]; // 512 KB
        for i in 0..8 {
            let start = i * 65536;
            raw_data[start..start + 4096].fill((i + 1) as u8);
        }
        std::fs::write(&raw_path, &raw_data).unwrap();

        let seq_path = dir.path().join("sequential.qcow2");
        let par_path = dir.path().join("parallel.qcow2");

        convert_from_raw(&raw_path, &seq_path, false, None, None, None).unwrap();
        convert_from_raw_parallel(&raw_path, &par_path, false, None, None, None, 4).unwrap();

        // Both should produce identical guest-visible data
        let mut seq_img = Qcow2Image::open(&seq_path).unwrap();
        let mut par_img = Qcow2Image::open(&par_path).unwrap();

        let mut seq_buf = vec![0u8; raw_data.len()];
        let mut par_buf = vec![0u8; raw_data.len()];
        seq_img.read_at(&mut seq_buf, 0).unwrap();
        par_img.read_at(&mut par_buf, 0).unwrap();

        assert_eq!(seq_buf, par_buf, "parallel and sequential conversions differ");
    }

    #[test]
    fn convert_parallel_compressed_round_trip() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("input.raw");

        // Create raw with compressible data in multiple clusters
        let mut raw_data = vec![0u8; 256 * 1024];
        for (i, byte) in raw_data.iter_mut().enumerate() {
            *byte = (i % 4) as u8; // highly compressible
        }
        std::fs::write(&raw_path, &raw_data).unwrap();

        let qcow2_path = dir.path().join("parallel_compressed.qcow2");
        convert_from_raw_parallel(&raw_path, &qcow2_path, true, None, None, None, 4).unwrap();

        // Verify data integrity
        let mut image = Qcow2Image::open(&qcow2_path).unwrap();
        let mut buf = vec![0u8; raw_data.len()];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, raw_data);
    }

    #[test]
    fn convert_parallel_compressed_matches_sequential() {
        let dir = TempDir::new().unwrap();
        let raw_path = dir.path().join("input.raw");

        // Scattered compressible data across multiple clusters
        let mut raw_data = vec![0u8; 512 * 1024];
        for i in 0..8 {
            let start = i * 65536;
            for j in 0..65536 {
                raw_data[start + j] = ((i * 7 + j) % 5) as u8;
            }
        }
        std::fs::write(&raw_path, &raw_data).unwrap();

        let seq_path = dir.path().join("seq_compressed.qcow2");
        let par_path = dir.path().join("par_compressed.qcow2");

        convert_from_raw(&raw_path, &seq_path, true, None, None, None).unwrap();
        convert_from_raw_parallel(&raw_path, &par_path, true, None, None, None, 4).unwrap();

        // Both must produce identical guest-visible data
        let mut seq_img = Qcow2Image::open(&seq_path).unwrap();
        let mut par_img = Qcow2Image::open(&par_path).unwrap();

        let mut seq_buf = vec![0u8; raw_data.len()];
        let mut par_buf = vec![0u8; raw_data.len()];
        seq_img.read_at(&mut seq_buf, 0).unwrap();
        par_img.read_at(&mut par_buf, 0).unwrap();

        assert_eq!(seq_buf, par_buf, "parallel and sequential compressed conversions differ");

        // Both should produce compressed output (smaller than uncompressed)
        let seq_size = std::fs::metadata(&seq_path).unwrap().len();
        let par_size = std::fs::metadata(&par_path).unwrap().len();
        let raw_size = raw_data.len() as u64;
        assert!(seq_size < raw_size, "sequential compressed should be smaller than raw");
        assert!(par_size < raw_size, "parallel compressed should be smaller than raw");
    }
}
