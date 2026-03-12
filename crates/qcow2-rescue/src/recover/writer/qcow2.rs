//! QCOW2 output image writer.

use std::path::{Path, PathBuf};

use qcow2_core::engine::encryption::CryptContext;

use crate::error::{RescueError, Result};
use crate::report::*;

use super::super::cluster_io::read_cluster_data;
use super::super::encryption::{build_encryption_info, EncryptionSetup};
use super::super::merge::merge_mappings;
use super::super::progress::RecoveryProgress;
use super::super::RecoverOptions;

/// Write a QCOW2 output image from merged mappings.
#[allow(clippy::too_many_lines)]
pub(crate) fn write_qcow2(
    output: &Path,
    layers: &[(PathBuf, ReconstructedTablesReport)],
    virtual_size: u64,
    cluster_size: u64,
    options: &RecoverOptions,
    crypt: Option<&CryptContext>,
    encryption: &EncryptionSetup,
) -> Result<RecoveryReport> {
    let cluster_bits = cluster_size.trailing_zeros();
    let (merged, mut layer_stats) = merge_mappings(layers, cluster_size);

    // Resume support
    let (already_done, mut progress) = if options.resume {
        let p = RecoveryProgress::load(output);
        if !p.written_offsets.is_empty() {
            eprintln!("  resuming: {} clusters already written", p.written_offsets.len());
        }
        (p.as_set(), p)
    } else {
        (std::collections::HashSet::new(), RecoveryProgress::default())
    };

    // Create or open existing QCOW2 image
    let mut image = if options.resume && output.exists() {
        qcow2::Qcow2Image::open(output)
            .map_err(RescueError::Qcow2)?
    } else {
        let create_options = qcow2::engine::image::CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
            refcount_order: None,
        };
        qcow2::Qcow2Image::create(output, create_options)
            .map_err(RescueError::Qcow2)?
    };

    let mut clusters_written = already_done.len() as u64;
    let mut clusters_failed = 0u64;
    let mut clusters_zeroed = 0u64;
    let mut bytes_written = 0u64;

    let total = merged.len();
    let progress_interval = (total / 20).max(1);
    let save_interval = 100usize;
    let mut since_last_save = 0usize;

    progress.total_clusters = total as u64;

    for (idx, (&guest_offset, rm)) in merged.iter().enumerate() {
        if idx % progress_interval == 0 && total > 0 {
            eprintln!(
                "  writing: {}/{} clusters ({:.0}%)",
                idx, total,
                idx as f64 / total as f64 * 100.0,
            );
        }

        if guest_offset >= virtual_size {
            continue;
        }

        if already_done.contains(&guest_offset) {
            continue;
        }

        match read_cluster_data(&rm.source_file, rm, cluster_size, cluster_bits, crypt) {
            Ok(data) => {
                if data.iter().all(|&b| b == 0) {
                    clusters_zeroed += 1;
                } else {
                    image.write_at(&data, guest_offset)
                        .map_err(RescueError::Qcow2)?;
                    clusters_written += 1;
                    bytes_written += data.len() as u64;
                }
                progress.written_offsets.push(guest_offset);
                since_last_save += 1;
            }
            Err(e) => {
                clusters_failed += 1;
                layer_stats[rm.layer_index].read_failures += 1;
                if !options.skip_corrupt {
                    let _ = progress.save(output);
                    return Err(e);
                }
                eprintln!(
                    "  warning: failed to read cluster at guest {guest_offset:#x} from {}: {e}",
                    rm.source_file.display(),
                );
                clusters_zeroed += 1;
            }
        }

        if since_last_save >= save_interval {
            let _ = progress.save(output);
            since_last_save = 0;
        }
    }

    image.flush().map_err(RescueError::Qcow2)?;

    // Success — remove progress file
    RecoveryProgress::remove(output);

    let total_clusters = virtual_size / cluster_size;
    let mapped_clusters = clusters_written + clusters_zeroed;
    clusters_zeroed += total_clusters.saturating_sub(mapped_clusters);

    Ok(RecoveryReport {
        output_path: output.display().to_string(),
        output_format: "qcow2".to_string(),
        virtual_size,
        cluster_size,
        source_files: layers.iter().map(|(p, _)| p.display().to_string()).collect(),
        clusters_written,
        clusters_failed,
        clusters_zeroed,
        bytes_written,
        layer_stats,
        encryption_info: build_encryption_info(encryption, crypt),
    })
}
