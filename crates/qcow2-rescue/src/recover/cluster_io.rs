//! Cluster data reading: decompression and decryption.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use qcow2::engine::compression::decompress_cluster;
use qcow2_core::engine::encryption::CryptContext;
use qcow2_format::constants::*;

use crate::error::Result;

use super::merge::ResolvedMapping;

/// Read a cluster from a source file.
///
/// For compressed clusters: reads compressed data and decompresses.
/// For encrypted clusters: decrypts if CryptContext is provided.
/// For normal clusters: reads raw data.
pub(crate) fn read_cluster_data(
    source: &Path,
    mapping: &ResolvedMapping,
    cluster_size: u64,
    _cluster_bits: u32,
    crypt: Option<&CryptContext>,
) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(source)?;
    let file_size = file.seek(SeekFrom::End(0))?;

    if mapping.compressed {
        // Compressed: host_offset is the raw descriptor offset from L2.
        // Read up to cluster_size bytes from that offset.
        let offset = mapping.host_offset;
        if offset >= file_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("compressed offset {offset:#x} beyond file size {file_size:#x}"),
            ).into());
        }
        let read_size = cluster_size.min(file_size - offset) as usize;
        let mut buf = vec![0u8; read_size];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        // Detect compression type from header
        let compression_type = detect_compression_type(&mut file);

        decompress_cluster(&buf, cluster_size as usize, 0, compression_type)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompression failed at offset {offset:#x}: {e}"),
            ).into())
    } else {
        // Normal cluster: read directly
        let offset = mapping.host_offset;
        if offset + cluster_size > file_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("cluster at {offset:#x} extends beyond file ({file_size:#x})"),
            ).into());
        }
        let mut buf = vec![0u8; cluster_size as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        // Decrypt if this is an encrypted cluster and we have a key
        if mapping.encrypted {
            if let Some(ctx) = crypt {
                ctx.decrypt_cluster(offset, &mut buf)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("decryption failed at offset {offset:#x}: {e}"),
                    ))?;
            }
            // If no crypt context, write raw (still encrypted) — this is intentional
        }

        Ok(buf)
    }
}

/// Detect compression type from a QCOW2 header. Returns COMPRESSION_DEFLATE as default.
fn detect_compression_type(file: &mut std::fs::File) -> u8 {
    let mut buf = [0u8; 108];
    if file.seek(SeekFrom::Start(0)).is_err() || file.read_exact(&mut buf).is_err() {
        return COMPRESSION_DEFLATE;
    }
    match qcow2_format::Header::read_from(&buf) {
        Ok(h) => h.compression_type,
        Err(_) => COMPRESSION_DEFLATE,
    }
}
