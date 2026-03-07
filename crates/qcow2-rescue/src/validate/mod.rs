//! Content validation: decompression and decryption probes.
//!
//! After reconstruction, we validate a sample of mapped clusters by
//! attempting to decompress (for compressed clusters) or decrypt (for
//! encrypted clusters). Successful decompression/decryption is strong
//! evidence that the mapping is correct.

mod compression;
mod structure;

pub use structure::has_structure;

use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::error::Result;
use crate::report::*;

use compression::{detect_compression_type, try_decompress_cluster};
use structure::try_decrypt_cluster;

/// Maximum number of clusters to probe per category.
const MAX_PROBES: usize = 100;

/// Validate content of mapped clusters by attempting decompression and decryption.
///
/// For compressed clusters: reads the compressed data from disk and tries to
/// decompress it. Success means the L2 entry is almost certainly correct.
///
/// For encrypted clusters: requires a `CryptContext` (from password + LUKS header).
/// Without one, encrypted clusters are skipped.
pub fn validate_content(
    path: &Path,
    cluster_size: u64,
    mappings: &[MappingEntry],
    crypt_context: Option<&qcow2_core::engine::encryption::CryptContext>,
) -> Result<ContentValidationReport> {
    let cluster_bits = cluster_size.trailing_zeros();
    let mut file = std::fs::File::open(path)?;
    let file_size = file.seek(SeekFrom::End(0))?;

    let compression_type = detect_compression_type(&mut file, cluster_size);

    let mut compressed_probed = 0u64;
    let mut compressed_ok = 0u64;
    let mut compressed_failed = 0u64;
    let mut encrypted_probed = 0u64;
    let mut encrypted_ok = 0u64;
    let mut encrypted_failed = 0u64;

    for m in mappings {
        if m.compressed && compressed_probed < MAX_PROBES as u64 {
            compressed_probed += 1;
            match try_decompress_cluster(
                &mut file,
                m.host_offset,
                cluster_size,
                cluster_bits,
                file_size,
                compression_type,
            ) {
                Ok(true) => compressed_ok += 1,
                Ok(false) | Err(_) => compressed_failed += 1,
            }
        }

        if m.encrypted && encrypted_probed < MAX_PROBES as u64 {
            if let Some(crypt) = crypt_context {
                encrypted_probed += 1;
                match try_decrypt_cluster(&mut file, m.host_offset, cluster_size, crypt) {
                    Ok(true) => encrypted_ok += 1,
                    Ok(false) | Err(_) => encrypted_failed += 1,
                }
            }
        }
    }

    Ok(ContentValidationReport {
        compressed_probed,
        compressed_ok,
        compressed_failed,
        encrypted_probed,
        encrypted_ok,
        encrypted_failed,
    })
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use byteorder::{BigEndian, ByteOrder};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    use qcow2_format::compressed::CompressedClusterDescriptor;
    use qcow2_format::constants::{QCOW2_MAGIC, VERSION_3, L2_COMPRESSED_FLAG};

    /// Create a QCOW2 image with one compressed cluster (deflate).
    fn create_compressed_image(cluster_bits: u32) -> tempfile::NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20; // 1 MB
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Compress some data
        let original = vec![0xAA; cluster_size as usize];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        // Pad to sector alignment (QCOW2 stores compressed clusters sector-aligned)
        let sector_aligned_size = ((compressed.len() + 511) & !511).max(512);

        // Layout:
        // Cluster 0: header
        // Cluster 1: L1 table
        // Cluster 2: L2 table
        // Cluster 3: compressed data (padded to sector alignment)
        let l1_offset = cluster_size;
        let l2_offset = 2 * cluster_size;
        let compressed_offset = 3 * cluster_size;
        let file_size = 4 * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        BigEndian::write_u32(&mut buf[100..104], 104);

        // L1: entry 0 → L2 at cluster 2
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l2_offset | (1u64 << 63),
        );

        // L2[0]: compressed descriptor using the format layer's encode method
        let desc = CompressedClusterDescriptor {
            host_offset: compressed_offset,
            compressed_size: sector_aligned_size as u64,
        };
        let l2_raw = L2_COMPRESSED_FLAG | desc.encode(cluster_bits);
        BigEndian::write_u64(&mut buf[l2_offset as usize..], l2_raw);

        // Write compressed data (padded with zeros to sector alignment)
        buf[compressed_offset as usize..compressed_offset as usize + compressed.len()]
            .copy_from_slice(&compressed);

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        tmpfile
    }

    #[test]
    fn validate_compressed_cluster_ok() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        let tmpfile = create_compressed_image(cluster_bits);

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = crate::reconstruct::reconstruct(tmpfile.path(), &cluster_map).unwrap();

        // Find compressed mappings
        let compressed_mappings: Vec<_> = report.mappings.iter().filter(|m| m.compressed).collect();
        assert!(!compressed_mappings.is_empty(), "should have at least one compressed mapping");

        // Run content validation
        let validation = validate_content(
            tmpfile.path(),
            cluster_size,
            &report.mappings,
            None, // no encryption
        ).unwrap();

        assert_eq!(validation.compressed_probed, compressed_mappings.len() as u64);
        assert_eq!(validation.compressed_ok, compressed_mappings.len() as u64);
        assert_eq!(validation.compressed_failed, 0);
    }

    #[test]
    fn validate_compressed_cluster_corrupt() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        let tmpfile = create_compressed_image(cluster_bits);

        // Corrupt the compressed data
        {
            let compressed_offset = 3 * cluster_size;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(tmpfile.path())
                .unwrap();
            f.seek(SeekFrom::Start(compressed_offset)).unwrap();
            f.write_all(&[0xFF; 64]).unwrap(); // overwrite with garbage
        }

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = crate::reconstruct::reconstruct(tmpfile.path(), &cluster_map).unwrap();

        let compressed_count = report.mappings.iter().filter(|m| m.compressed).count();
        if compressed_count > 0 {
            let validation = validate_content(
                tmpfile.path(),
                cluster_size,
                &report.mappings,
                None,
            ).unwrap();

            assert!(validation.compressed_failed > 0, "corrupted compressed data should fail validation");
        }
    }

    #[test]
    fn has_structure_zeros() {
        let data = vec![0u8; 1024];
        assert!(has_structure(&data));
    }

    #[test]
    fn has_structure_filesystem_like() {
        // Typical filesystem data: mostly zeros with some structure
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(b"\x53\xef\x01\x00"); // ext4 magic
        data[100] = 0x42;
        assert!(has_structure(&data));
    }

    #[test]
    fn has_structure_random_data() {
        // Pseudo-random data (simulating wrong-key decryption)
        let mut data = vec![0u8; 4096];
        let mut val = 0xDEADBEEFu32;
        for byte in data.iter_mut() {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = ((val >> 16) as u8) | 1; // avoid zeros
        }
        assert!(!has_structure(&data));
    }

    #[test]
    fn has_structure_repeated_bytes() {
        let mut data = vec![0u8; 1024];
        // Random-ish but with a run of 8 identical bytes
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8 | 1;
        }
        data[500..508].fill(0xAA); // 8-byte run
        assert!(has_structure(&data));
    }

    #[test]
    fn has_structure_empty() {
        assert!(!has_structure(&[]));
    }
}
