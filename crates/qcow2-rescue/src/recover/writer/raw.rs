//! Raw flat disk image output writer.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use qcow2_core::engine::encryption::CryptContext;

use crate::error::Result;
use crate::report::*;

use super::super::cluster_io::read_cluster_data;
use super::super::encryption::{build_encryption_info, EncryptionSetup};
use super::super::merge::merge_mappings;
use super::super::progress::RecoveryProgress;
use super::super::RecoverOptions;

/// Write a flat raw output image from merged mappings.
pub(crate) fn write_raw(
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

    // Resume support: load progress and open file accordingly
    let (already_done, mut progress) = if options.resume {
        let p = RecoveryProgress::load(output);
        if !p.written_offsets.is_empty() {
            eprintln!("  resuming: {} clusters already written", p.written_offsets.len());
        }
        (p.as_set(), p)
    } else {
        (std::collections::HashSet::new(), RecoveryProgress::default())
    };

    let mut out = if options.resume && output.exists() {
        std::fs::OpenOptions::new().write(true).open(output)?
    } else {
        std::fs::File::create(output)?
    };
    // Set the file size upfront (sparse)
    out.set_len(virtual_size)?;

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

        // Skip already written clusters (resume)
        if already_done.contains(&guest_offset) {
            continue;
        }

        match read_cluster_data(&rm.source_file, rm, cluster_size, cluster_bits, crypt) {
            Ok(data) => {
                // Check if cluster is all zeros — skip writing (sparse file handles it)
                if data.iter().all(|&b| b == 0) {
                    clusters_zeroed += 1;
                } else {
                    out.seek(SeekFrom::Start(guest_offset))?;
                    out.write_all(&data)?;
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
                    // Save progress before returning error
                    let _ = progress.save(output);
                    return Err(e);
                }
                eprintln!(
                    "  warning: failed to read cluster at guest {guest_offset:#x} from {}: {e}",
                    rm.source_file.display(),
                );
                // Zero-filled by sparse file
                clusters_zeroed += 1;
            }
        }

        // Periodically save progress
        if since_last_save >= save_interval {
            let _ = progress.save(output);
            since_last_save = 0;
        }
    }

    out.flush()?;

    // Success — remove progress file
    RecoveryProgress::remove(output);

    // Count unallocated clusters as zeroed
    let total_clusters = virtual_size / cluster_size;
    let mapped_clusters = clusters_written + clusters_zeroed;
    clusters_zeroed += total_clusters.saturating_sub(mapped_clusters);

    Ok(RecoveryReport {
        output_path: output.display().to_string(),
        output_format: "raw".to_string(),
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
