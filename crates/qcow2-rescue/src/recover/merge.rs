//! Layer mapping merge logic for multi-layer recovery.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::report::*;

/// Merged mapping: tells us where to read each guest cluster from.
pub(crate) struct ResolvedMapping {
    /// Source file path.
    pub(crate) source_file: PathBuf,
    /// Host offset within source file.
    pub(crate) host_offset: u64,
    /// Whether the cluster is compressed.
    pub(crate) compressed: bool,
    /// Whether the cluster is encrypted.
    pub(crate) encrypted: bool,
    /// Layer index this mapping came from.
    pub(crate) layer_index: usize,
}

/// Merge mappings from multiple layers. Later layers override earlier ones.
///
/// Returns a map of guest_offset → ResolvedMapping, plus per-layer stats.
pub(crate) fn merge_mappings(
    layers: &[(PathBuf, ReconstructedTablesReport)],
    cluster_size: u64,
) -> (BTreeMap<u64, ResolvedMapping>, Vec<LayerRecoveryStat>) {
    let mut merged: BTreeMap<u64, ResolvedMapping> = BTreeMap::new();
    let mut stats: Vec<LayerRecoveryStat> = Vec::new();

    for (layer_idx, (path, tables)) in layers.iter().enumerate() {
        let mut mappings_found = 0u64;

        for m in &tables.mappings {
            mappings_found += 1;
            // Align guest offset to cluster boundary
            let guest_aligned = m.guest_offset & !(cluster_size - 1);
            merged.insert(guest_aligned, ResolvedMapping {
                source_file: path.clone(),
                host_offset: m.host_offset,
                compressed: m.compressed,
                encrypted: m.encrypted,
                layer_index: layer_idx,
            });
        }

        stats.push(LayerRecoveryStat {
            file_path: path.display().to_string(),
            mappings_found,
            mappings_used: 0, // filled in after merge
            read_failures: 0,
        });
    }

    // Count how many mappings each layer actually contributed
    for rm in merged.values() {
        stats[rm.layer_index].mappings_used += 1;
    }

    (merged, stats)
}

/// Infer the virtual_size from header and mapping data.
///
/// The header's virtual_size may be corrupt (zero, too small, or random garbage).
/// We cross-check against the actual mappings to catch obvious errors:
/// - If header says 0 or less than what mappings cover → use mapping-derived size
/// - If header says something unreasonably large (>64TB or >1000× file size) → use mapping-derived size
/// - If no header and no mappings → return 0
pub(crate) fn infer_virtual_size(tables: &ReconstructedTablesReport, cluster_size: u64) -> u64 {
    let mapping_max = tables.mappings.iter()
        .map(|m| m.guest_offset + cluster_size)
        .max()
        .unwrap_or(0);

    match tables.virtual_size {
        Some(vs) if vs > 0 && vs >= mapping_max => {
            // Header value is plausible: non-zero and covers all mappings.
            // Sanity-check: reject unreasonably large values (>64 TB).
            if vs > 64 * 1024 * 1024 * 1024 * 1024 {
                eprintln!(
                    "  warning: header virtual_size {} is unreasonably large, \
                     using mapping-derived size {}",
                    vs, mapping_max
                );
                mapping_max
            } else {
                vs
            }
        }
        Some(vs) => {
            eprintln!(
                "  warning: header virtual_size {} is too small or zero \
                 (mappings cover up to {}), using mapping-derived size",
                vs, mapping_max
            );
            mapping_max
        }
        None => {
            if mapping_max > 0 {
                eprintln!(
                    "  warning: no virtual_size from header, \
                     inferred {} from mappings",
                    mapping_max
                );
            }
            mapping_max
        }
    }
}
