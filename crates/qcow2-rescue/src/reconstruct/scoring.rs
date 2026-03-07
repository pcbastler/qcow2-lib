//! Plausibility scoring for reconstructed mappings.

use std::collections::{BTreeMap, HashSet};

use crate::report::*;

/// Score a set of mappings for plausibility.
///
/// Returns (primary_score, header_match) where:
/// - primary_score counts plausible mappings minus penalties
/// - header_match is used as a tiebreaker only
///
/// Checks:
/// - Host offsets within file size and cluster-aligned (+2 per valid, -3 per out-of-bounds)
/// - No duplicate host offsets (-5 per duplicate)
/// - Guest offsets within virtual_size (+1 per valid, -2 per out-of-bounds)
/// - Subcluster fragmentation: >4 allocated ranges gets -1 per excess range (soft signal)
pub(super) fn score_plausibility(
    mappings: &BTreeMap<u64, MappingEntry>,
    file_size: u64,
    virtual_size: Option<u64>,
    cluster_size: u64,
    valid_data_offsets: &HashSet<u64>,
    matches_header: bool,
) -> (i64, bool) {
    if mappings.is_empty() {
        return (0, matches_header);
    }

    let mut score: i64 = 0;
    let mut seen_hosts: HashSet<u64> = HashSet::new();

    for m in mappings.values() {
        // Host offset within file and cluster-aligned?
        if m.host_offset < file_size && m.host_offset % cluster_size == 0 {
            score += 2;
        } else {
            score -= 3;
        }

        // Points to a cluster the scanner classified as Data/Compressed?
        if !valid_data_offsets.is_empty() {
            let containing = m.host_offset & !(cluster_size - 1);
            if valid_data_offsets.contains(&containing) {
                score += 3;
            } else {
                score -= 4;
            }
        }

        // Duplicate host offset? Two guest addresses → same host cluster is wrong.
        if !seen_hosts.insert(m.host_offset) {
            score -= 5;
        }

        // Guest offset within virtual_size?
        if let Some(vs) = virtual_size {
            if m.guest_offset < vs {
                score += 1;
            } else {
                score -= 2;
            }
        }

        // Subcluster fragmentation: many non-contiguous allocated ranges
        // are unusual for real workloads (soft penalty).
        if let Some(ref sc) = m.subclusters {
            let ranges = sc.allocated_ranges.len();
            if ranges > 4 {
                score -= (ranges - 4) as i64;
            }
        }
    }

    (score, matches_header)
}

/// Extract the virtual_size from the first header found in the cluster map.
pub(super) fn find_virtual_size(cluster_map: &ClusterMapReport) -> Option<u64> {
    cluster_map.clusters.iter().find_map(|c| {
        if let ClusterTypeReport::Header { virtual_size, .. } = c.cluster_type {
            Some(virtual_size)
        } else {
            None
        }
    })
}
