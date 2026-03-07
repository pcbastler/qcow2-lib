//! Compression type detection and decompression probes.

use std::io::{Read, Seek, SeekFrom};

use qcow2::engine::compression::decompress_cluster;
use qcow2_format::constants::*;

use crate::error::Result;

/// Detect compression type from the QCOW2 header.
///
/// Returns 0 (deflate) as default if the header is unreadable.
pub(super) fn detect_compression_type(file: &mut std::fs::File, cluster_size: u64) -> u8 {
    let mut buf = vec![0u8; 4096.min(cluster_size as usize)];
    if file.seek(SeekFrom::Start(0)).is_err() {
        return COMPRESSION_DEFLATE;
    }
    if file.read_exact(&mut buf).is_err() {
        return COMPRESSION_DEFLATE;
    }
    match qcow2_format::Header::read_from(&buf) {
        Ok(h) => h.compression_type,
        Err(_) => COMPRESSION_DEFLATE,
    }
}

/// Try to decompress a compressed cluster.
///
/// For compressed clusters, the host_offset from the L2 entry is the raw
/// byte offset where compressed data starts. We read up to `cluster_size`
/// bytes from that offset (compressed data is always smaller than one cluster).
///
/// Returns `Ok(true)` if decompression succeeded.
pub(super) fn try_decompress_cluster(
    file: &mut std::fs::File,
    host_offset: u64,
    cluster_size: u64,
    _cluster_bits: u32,
    file_size: u64,
    compression_type: u8,
) -> Result<bool> {
    if host_offset >= file_size {
        return Ok(false);
    }

    let read_size = cluster_size.min(file_size - host_offset) as usize;
    let mut buf = vec![0u8; read_size];
    file.seek(SeekFrom::Start(host_offset))?;
    file.read_exact(&mut buf)?;

    match decompress_cluster(&buf, cluster_size as usize, 0, compression_type) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
