//! Phase 4: Recovery — extract data from corrupted images into usable output.
//!
//! Two output modes:
//! - **Raw**: Flat disk image. Backing chain is flattened (base → leaf merge).
//! - **QCOW2**: New QCOW2 image(s). Can preserve backing structure or flatten.
//!
//! For each guest cluster, recovery reads the raw data from the source image
//! using the mappings from Phase 2 (reconstruct). Compressed clusters are
//! decompressed, encrypted clusters are decrypted. The result is written to
//! the output file.
//!
//! ## Encryption handling
//!
//! If a LUKS header is found in the image:
//! - **With password**: decrypt clusters by default, probe to verify correctness
//! - **Without password or wrong password**: write raw (still encrypted) data,
//!   preserve LUKS header info in the report so the user can retry later

mod cluster_io;
mod encryption;
mod merge;
mod progress;
mod writer;

use std::path::{Path, PathBuf};

use crate::config::{ConflictStrategy, OutputFormat};
use crate::error::{RescueError, Result};
use crate::report::*;
use crate::scan;
use crate::reconstruct;

use encryption::{setup_encryption, EncryptionSetup};
use merge::infer_virtual_size;
use writer::{write_raw, write_qcow2, write_chain};

/// Options controlling recovery behavior.
pub struct RecoverOptions {
    /// Output format (Raw or Qcow2).
    pub format: OutputFormat,
    /// Skip corrupt clusters instead of failing (zero-fill).
    pub skip_corrupt: bool,
    /// Password for encrypted images.
    pub password: Option<Vec<u8>>,
    /// Override cluster size (when header is corrupt).
    pub cluster_size_override: Option<u64>,
    /// Resume from a previous interrupted run.
    pub resume: bool,
    /// How to resolve mapping conflicts.
    pub on_conflict: ConflictStrategy,
}

/// Recover a single QCOW2 image (no backing chain) to the output path.
pub fn recover_single(
    input: &Path,
    output: &Path,
    options: &RecoverOptions,
) -> Result<RecoveryReport> {
    let cluster_size = match options.cluster_size_override {
        Some(cs) => cs,
        None => scan::detect_cluster_size(input)?,
    };

    let cluster_map = scan::scan_file(input, cluster_size)?;
    let tables = reconstruct::reconstruct_with_strategy(input, &cluster_map, options.on_conflict)?;
    let virtual_size = infer_virtual_size(&tables, cluster_size);

    // Check if image has encrypted clusters
    let has_encrypted = tables.mappings.iter().any(|m| m.encrypted);
    let encryption = if has_encrypted {
        setup_encryption(input, cluster_size, &tables.mappings, options)
    } else {
        EncryptionSetup {
            crypt_context: None,
            luks_found: false,
            luks_offset: None,
            luks_size: None,
            probe_ok: None,
        }
    };

    let crypt_ref = encryption.crypt_context.as_ref();

    match options.format {
        OutputFormat::Raw => write_raw(
            output,
            &[(input.to_path_buf(), tables)],
            virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Qcow2 | OutputFormat::Chain => write_qcow2(
            output,
            &[(input.to_path_buf(), tables)],
            virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
    }
}

/// Recover a backing chain (base → ... → leaf), flattening into one output.
///
/// `chain` must be ordered base-first: `[base, overlay1, ..., leaf]`.
/// Later layers override earlier ones for the same guest offset.
pub fn recover_chain(
    chain: &[PathBuf],
    output: &Path,
    options: &RecoverOptions,
) -> Result<RecoveryReport> {
    if chain.is_empty() {
        return Err(RescueError::NoHeaderFound);
    }

    // Scan and reconstruct each layer
    let mut layers: Vec<(PathBuf, ReconstructedTablesReport)> = Vec::new();
    let mut cluster_size = 0u64;

    for path in chain {
        let cs = match options.cluster_size_override {
            Some(cs) => cs,
            None => scan::detect_cluster_size(path)?,
        };
        if cluster_size == 0 {
            cluster_size = cs;
        }

        let cluster_map = scan::scan_file(path, cs)?;
        let tables = reconstruct::reconstruct_with_strategy(path, &cluster_map, options.on_conflict)?;
        layers.push((path.clone(), tables));
    }

    // Use the largest plausible virtual_size across all layers
    let max_virtual_size = layers.iter()
        .map(|(_, t)| infer_virtual_size(t, cluster_size))
        .max()
        .unwrap_or(0);

    let layer_refs: Vec<(PathBuf, ReconstructedTablesReport)> = layers;

    // Check if any layer has encrypted clusters
    let has_encrypted = layer_refs.iter()
        .any(|(_, t)| t.mappings.iter().any(|m| m.encrypted));

    let encryption = if has_encrypted {
        // Use the first layer with encrypted clusters to find the LUKS header
        let (enc_path, enc_tables) = layer_refs.iter()
            .find(|(_, t)| t.mappings.iter().any(|m| m.encrypted))
            .unwrap();
        setup_encryption(enc_path, cluster_size, &enc_tables.mappings, options)
    } else {
        EncryptionSetup {
            crypt_context: None,
            luks_found: false,
            luks_offset: None,
            luks_size: None,
            probe_ok: None,
        }
    };

    let crypt_ref = encryption.crypt_context.as_ref();

    match options.format {
        OutputFormat::Raw => write_raw(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Qcow2 => write_qcow2(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Chain => write_chain(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
    }
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

    use encryption::find_luks_header;
    use merge::merge_mappings;
    use progress::RecoveryProgress;

    /// Create a minimal QCOW2 image with one data cluster at guest offset 0.
    fn create_data_image(cluster_bits: u32, data: &[u8]) -> tempfile::NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Layout:
        // Cluster 0: header
        // Cluster 1: refcount table
        // Cluster 2: refcount block
        // Cluster 3: L1 table
        // Cluster 4: L2 table
        // Cluster 5: data cluster
        let l1_offset = 3 * cluster_size;
        let l2_offset = 4 * cluster_size;
        let data_offset = 5 * cluster_size;
        let file_size = 6 * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Refcount table (cluster 1): entry 0 → refcount block at cluster 2
        let rct_offset = cluster_size;
        let rcb_offset = 2 * cluster_size;
        BigEndian::write_u64(&mut buf[48..56], rct_offset); // refcount_table_offset
        BigEndian::write_u32(&mut buf[56..60], 1); // refcount_table_clusters
        BigEndian::write_u64(&mut buf[rct_offset as usize..], rcb_offset);

        // Refcount block (cluster 2): set refcount=1 for clusters 0-5
        for i in 0..6u16 {
            BigEndian::write_u16(
                &mut buf[rcb_offset as usize + i as usize * 2..],
                1,
            );
        }

        // L1[0] → L2 at cluster 4
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l2_offset | (1u64 << 63),
        );

        // L2[0] → data at cluster 5
        BigEndian::write_u64(
            &mut buf[l2_offset as usize..],
            data_offset | (1u64 << 63),
        );

        // Data cluster
        let copy_len = data.len().min(cluster_size as usize);
        buf[data_offset as usize..data_offset as usize + copy_len]
            .copy_from_slice(&data[..copy_len]);

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        tmpfile
    }

    /// Create a QCOW2 image with a compressed cluster at guest offset 0.
    fn create_compressed_image(cluster_bits: u32) -> tempfile::NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Compress some data
        let original = vec![0xAA; cluster_size as usize];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        let sector_aligned_size = ((compressed.len() + 511) & !511).max(512);

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

        // L1[0] → L2
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l2_offset | (1u64 << 63),
        );

        // L2[0] → compressed descriptor
        let desc = CompressedClusterDescriptor {
            host_offset: compressed_offset,
            compressed_size: sector_aligned_size as u64,
        };
        let l2_raw = L2_COMPRESSED_FLAG | desc.encode(cluster_bits);
        BigEndian::write_u64(&mut buf[l2_offset as usize..], l2_raw);

        // Write compressed data
        buf[compressed_offset as usize..compressed_offset as usize + compressed.len()]
            .copy_from_slice(&compressed);

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        tmpfile
    }

    #[test]
    fn recover_single_data_cluster_raw() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42u8; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // Verify the data at guest offset 0
        let recovered = std::fs::read(&out_path).unwrap();
        assert_eq!(recovered.len(), 1 << 20); // virtual_size
        assert_eq!(&recovered[..cluster_size as usize], &data[..]);
    }

    #[test]
    fn recover_compressed_cluster_raw() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let src = create_compressed_image(cluster_bits);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // The compressed cluster contained 0xAA bytes
        let recovered = std::fs::read(&out_path).unwrap();
        let expected = vec![0xAA; cluster_size as usize];
        assert_eq!(&recovered[..cluster_size as usize], &expected[..]);
    }

    #[test]
    fn recover_single_data_cluster_qcow2() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42u8; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.qcow2");

        let options = RecoverOptions {
            format: OutputFormat::Qcow2,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);
        assert_eq!(report.output_format, "qcow2");

        // Verify by reading back through the library
        let mut image = qcow2::Qcow2Image::open(&out_path).unwrap();
        let mut buf = vec![0u8; cluster_size as usize];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn recover_chain_merge() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        // Base: guest 0 = 0xAA
        let base_data = vec![0xAA; cluster_size as usize];
        let base = create_data_image(cluster_bits, &base_data);

        // Overlay: guest 0 = 0xBB (overrides base)
        let overlay_data = vec![0xBB; cluster_size as usize];
        let overlay = create_data_image(cluster_bits, &overlay_data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("merged.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let chain = vec![base.path().to_path_buf(), overlay.path().to_path_buf()];
        let report = recover_chain(&chain, &out_path, &options).unwrap();

        assert_eq!(report.source_files.len(), 2);
        assert!(report.clusters_written > 0);

        // Guest offset 0 should have overlay data (0xBB), not base (0xAA)
        let recovered = std::fs::read(&out_path).unwrap();
        assert_eq!(recovered[0], 0xBB);
        assert!(recovered[..cluster_size as usize].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn recover_skip_corrupt() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        // Corrupt the data cluster (cluster 5)
        {
            let data_offset = 5 * cluster_size;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(src.path())
                .unwrap();
            // Truncate file so the data cluster is incomplete
            f.set_len(data_offset + 100).unwrap();
        }

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        // The corrupt cluster should be counted as failed
        assert!(report.clusters_failed > 0 || report.clusters_written == 0);
    }

    #[test]
    fn merge_mappings_later_overrides_earlier() {
        let cluster_size = 65536u64;
        let base_path = PathBuf::from("/fake/base.qcow2");
        let overlay_path = PathBuf::from("/fake/overlay.qcow2");

        let base_tables = ReconstructedTablesReport {
            file_path: base_path.display().to_string(),
            l1_entries: 1,
            l2_tables_verified: 1,
            l2_tables_suspicious: 0,
            mappings_total: 2,
            mappings_from_l2: 2,
            orphan_data_clusters: 0,
            refcount_check: None,
            content_validation: None,
            mapping_conflicts: 0,
            virtual_size: Some(1 << 20),
            mappings: vec![
                MappingEntry {
                    guest_offset: 0,
                    host_offset: 0x10000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
                MappingEntry {
                    guest_offset: 0x10000,
                    host_offset: 0x20000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
            ],
        };

        let overlay_tables = ReconstructedTablesReport {
            file_path: overlay_path.display().to_string(),
            l1_entries: 1,
            l2_tables_verified: 1,
            l2_tables_suspicious: 0,
            mappings_total: 1,
            mappings_from_l2: 1,
            orphan_data_clusters: 0,
            refcount_check: None,
            content_validation: None,
            mapping_conflicts: 0,
            virtual_size: Some(1 << 20),
            mappings: vec![
                MappingEntry {
                    guest_offset: 0, // same as base — overlay wins
                    host_offset: 0x30000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
            ],
        };

        let layers = vec![
            (base_path.clone(), base_tables),
            (overlay_path.clone(), overlay_tables),
        ];

        let (merged, stats) = merge_mappings(&layers, cluster_size);

        // Guest 0 should come from overlay (layer 1)
        assert_eq!(merged[&0].layer_index, 1);
        assert_eq!(merged[&0].host_offset, 0x30000);

        // Guest 0x10000 should come from base (layer 0)
        assert_eq!(merged[&0x10000].layer_index, 0);
        assert_eq!(merged[&0x10000].host_offset, 0x20000);

        // Layer stats
        assert_eq!(stats[0].mappings_found, 2);
        assert_eq!(stats[0].mappings_used, 1); // only 0x10000 survived
        assert_eq!(stats[1].mappings_found, 1);
        assert_eq!(stats[1].mappings_used, 1); // 0 won
    }

    #[test]
    fn recover_encrypted_image_with_password() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let cluster_size = 65536u64;
        let virtual_size = 1u64 << 20;
        let password = b"testpassword";

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        // Create encrypted image and write some data
        {
            let opts = CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: Some(EncryptionOptions {
                    password: password.to_vec(),
                    cipher: CipherMode::AesXtsPlain64,
                    luks_version: 1,
                    iter_time_ms: Some(10), // fast for tests
                }),
            };
            let mut image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
            let data = vec![0x42u8; cluster_size as usize];
            image.write_at(&data, 0).unwrap();
            image.flush().unwrap();
        }

        // Recover with correct password
        let recovered_path = out_dir.path().join("recovered.raw");
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: Some(password.to_vec()),
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(&src_path, &recovered_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // Check encryption info in report
        let enc_info = report.encryption_info.as_ref().expect("should have encryption info");
        assert!(enc_info.luks_header_found);
        assert!(enc_info.decrypted);

        // Verify decrypted data
        let recovered = std::fs::read(&recovered_path).unwrap();
        assert_eq!(recovered[0], 0x42);
        assert!(recovered[..cluster_size as usize].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn recover_encrypted_image_without_password() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let cluster_size = 65536u64;
        let virtual_size = 1u64 << 20;
        let password = b"testpassword";

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        // Create encrypted image and write some data
        {
            let opts = CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: Some(EncryptionOptions {
                    password: password.to_vec(),
                    cipher: CipherMode::AesXtsPlain64,
                    luks_version: 1,
                    iter_time_ms: Some(10),
                }),
            };
            let mut image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
            let data = vec![0x42u8; cluster_size as usize];
            image.write_at(&data, 0).unwrap();
            image.flush().unwrap();
        }

        // Recover WITHOUT password — should still work but data stays encrypted
        let recovered_path = out_dir.path().join("recovered_no_pw.raw");
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(&src_path, &recovered_path, &options).unwrap();
        // Should still recover something
        assert!(report.clusters_written > 0 || report.clusters_zeroed > 0);

        // Encryption info should show no decryption
        let enc_info = report.encryption_info.as_ref().expect("should have encryption info");
        assert!(enc_info.luks_header_found);
        assert!(!enc_info.decrypted);

        // Data should NOT be all 0x42 (it's still encrypted)
        let recovered = std::fs::read(&recovered_path).unwrap();
        let first_cluster = &recovered[..cluster_size as usize];
        let all_0x42 = first_cluster.iter().all(|&b| b == 0x42);
        assert!(!all_0x42,
            "without password, data should still be encrypted");
    }

    #[test]
    fn find_luks_header_in_encrypted_image() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        let opts = CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(16),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: b"test".to_vec(),
                cipher: CipherMode::AesXtsPlain64,
                luks_version: 1,
                iter_time_ms: Some(10),
            }),
        };
        let image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
        drop(image);

        let result = find_luks_header(&src_path, 65536);
        assert!(result.is_some(), "should find LUKS header");
        let (offset, data) = result.unwrap();
        assert_eq!(&data[..6], b"LUKS\xba\xbe");
        assert!(offset > 0, "LUKS header should not be at offset 0");
    }

    #[test]
    fn resume_recovery_skips_already_written() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        let data = vec![0xAA; cluster_size as usize];
        let tmpfile = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        // First run: normal recovery
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report1 = recover_single(tmpfile.path(), &out_path, &options).unwrap();
        let written1 = report1.clusters_written;
        assert!(written1 > 0);

        // Verify no progress file left after success
        assert!(!RecoveryProgress::progress_path(&out_path).exists());

        // Simulate interrupted run by creating a progress file
        let mut fake_progress = RecoveryProgress::default();
        // Record the data cluster's guest offset as already written
        fake_progress.written_offsets.push(0); // guest offset 0
        fake_progress.total_clusters = 1;
        fake_progress.save(&out_path).unwrap();

        // Second run: resume — should skip the cluster we "already wrote"
        let resume_options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: true,
            on_conflict: ConflictStrategy::Ask,
        };

        let report2 = recover_single(tmpfile.path(), &out_path, &resume_options).unwrap();
        // The cluster at guest 0 was in the progress file, so it gets counted
        // in clusters_written via already_done.len(), but not re-written.
        // Total clusters_written should include the already-done count.
        assert!(report2.clusters_written >= written1,
            "resume should count already-written clusters");

        // Progress file should be cleaned up after success
        assert!(!RecoveryProgress::progress_path(&out_path).exists());
    }
}
