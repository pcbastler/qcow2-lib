//! Chain output writer: each layer as a separate QCOW2 with backing file references.

use std::path::{Path, PathBuf};

use qcow2_core::engine::encryption::CryptContext;

use crate::error::{RescueError, Result};
use crate::report::*;

use super::super::cluster_io::read_cluster_data;
use super::super::encryption::{build_encryption_info, EncryptionSetup};
use super::super::merge::ResolvedMapping;
use super::super::RecoverOptions;

/// Write each layer as a separate QCOW2 with backing file references.
///
/// `output` is treated as a directory. Each layer gets its own file:
/// `layer_0_base.qcow2`, `layer_1.qcow2`, etc.
/// Layer 0 has no backing file. Layer N references layer N-1 as backing.
#[allow(clippy::too_many_lines)]
pub(crate) fn write_chain(
    output: &Path,
    layers: &[(PathBuf, ReconstructedTablesReport)],
    virtual_size: u64,
    cluster_size: u64,
    options: &RecoverOptions,
    crypt: Option<&CryptContext>,
    encryption: &EncryptionSetup,
) -> Result<RecoveryReport> {
    let cluster_bits = cluster_size.trailing_zeros();

    // output is the base path — we derive per-layer filenames
    let output_dir = output.parent().unwrap_or(Path::new("."));
    let stem = output.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("recovered");

    let mut clusters_written = 0u64;
    let mut clusters_failed = 0u64;
    let mut clusters_zeroed = 0u64;
    let mut bytes_written = 0u64;
    let mut layer_stats = Vec::new();
    let mut output_files: Vec<String> = Vec::new();

    for (layer_idx, (source_path, tables)) in layers.iter().enumerate() {
        let layer_name = if layer_idx == 0 {
            format!("{stem}_base.qcow2")
        } else {
            format!("{stem}_layer{layer_idx}.qcow2")
        };
        let layer_path = output_dir.join(&layer_name);

        // Backing file is the previous layer (if any)
        let backing_file = if layer_idx > 0 {
            Some(output_files.get(layer_idx - 1)
                .ok_or_else(|| qcow2_core::Error::IndexOutOfBounds { index: layer_idx - 1, len: output_files.len() })?
                .clone())
        } else {
            None
        };

        let create_options = qcow2::engine::image::CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        };

        let mut image = qcow2::Qcow2Image::create(&layer_path, create_options)
            .map_err(RescueError::Qcow2)?;

        // Set backing file reference if this is an overlay
        if let Some(ref backing) = backing_file {
            image.rebase_unsafe(Some(Path::new(backing)))
                .map_err(RescueError::Qcow2)?;
        }

        let mut layer_written = 0u64;
        let mut layer_failed = 0u64;

        for m in &tables.mappings {
            if m.guest_offset >= virtual_size {
                continue;
            }

            let rm = ResolvedMapping {
                source_file: source_path.clone(),
                host_offset: m.host_offset,
                compressed: m.compressed,
                encrypted: m.encrypted,
                layer_index: layer_idx,
            };

            match read_cluster_data(source_path, &rm, cluster_size, cluster_bits, crypt) {
                Ok(data) => {
                    if data.iter().all(|&b| b == 0) {
                        clusters_zeroed += 1;
                    } else {
                        image.write_at(&data, m.guest_offset)
                            .map_err(RescueError::Qcow2)?;
                        clusters_written += 1;
                        layer_written += 1;
                        bytes_written += data.len() as u64;
                    }
                }
                Err(e) => {
                    clusters_failed += 1;
                    layer_failed += 1;
                    if !options.skip_corrupt {
                        return Err(e);
                    }
                    eprintln!(
                        "  warning: failed to read cluster at guest {:#x} from {}: {e}",
                        m.guest_offset, source_path.display(),
                    );
                    clusters_zeroed += 1;
                }
            }
        }

        image.flush().map_err(RescueError::Qcow2)?;

        eprintln!(
            "  layer {}: {} → {} clusters written",
            layer_idx, source_path.display(), layer_written,
        );

        layer_stats.push(LayerRecoveryStat {
            file_path: source_path.display().to_string(),
            mappings_found: tables.mappings.len() as u64,
            mappings_used: layer_written,
            read_failures: layer_failed,
        });

        output_files.push(layer_path.display().to_string());
    }

    // Primary output path is the leaf (last layer)
    let primary_output = output_files.last()
        .cloned()
        .unwrap_or_else(|| output.display().to_string());

    Ok(RecoveryReport {
        output_path: primary_output,
        output_format: "chain".to_string(),
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
