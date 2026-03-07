//! Post-scan L2 table refinement.
//!
//! Reclassifies false-positive L2 tables as Data by scoring each candidate's
//! entries against the set of known data cluster offsets.

use std::io::{Read, Seek, SeekFrom};

use crate::report::{ClusterInfo, ClusterSummary, ClusterTypeReport};

/// Post-scan refinement: reclassify false-positive L2 tables as Data.
///
/// In a healthy QCOW2, each L2 table maps up to cluster_size/8 data clusters,
/// so the number of L2 tables should be much smaller than the number of
/// data+compressed clusters. When L2 tables outnumber data clusters, most are
/// false positives (structured data that passes the L2 heuristic).
///
/// We score each candidate L2 table by how many of its entries point to
/// known Data/Compressed cluster offsets. Real L2 tables reference data
/// clusters; false positives (misclassified data) have entries pointing
/// to random offsets. Keep the highest-scoring candidates.
pub(crate) fn refine_l2_classification(
    clusters: &mut [ClusterInfo],
    summary: &mut ClusterSummary,
    cluster_size: u64,
    file: &mut std::fs::File,
) {
    let l2_count = clusters
        .iter()
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::L2Table { .. }))
        .count();

    if l2_count <= 1 {
        return; // Nothing to refine
    }

    let data_count = clusters
        .iter()
        .filter(|c| {
            matches!(
                c.cluster_type,
                ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. }
            )
        })
        .count();

    // In a normal image, 1 L2 table maps cluster_size/8 data clusters.
    // Some data clusters may be misclassified as L2, so use the total
    // pool (data + L2) as the upper bound for data cluster count.
    let entries_per_l2 = (cluster_size / 8) as usize;
    let total_possible_data = data_count + l2_count;
    let expected_l2 = if total_possible_data > 0 {
        (total_possible_data + entries_per_l2 - 1) / entries_per_l2
    } else {
        1
    };

    let keep = expected_l2.max(1).min(l2_count);
    if l2_count <= keep {
        return;
    }

    // Build a set of known data/compressed cluster offsets for cross-referencing.
    let data_offsets: std::collections::HashSet<u64> = clusters
        .iter()
        .filter(|c| {
            matches!(
                c.cluster_type,
                ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. }
            )
        })
        .map(|c| c.offset)
        .collect();

    // Score each L2 candidate by reading its data from the file and checking
    // how many entries point to known data cluster offsets.
    let mut buf = vec![0u8; cluster_size as usize];
    let mut l2_scored: Vec<(usize, u32)> = Vec::new();

    for (idx, c) in clusters.iter().enumerate() {
        if !matches!(c.cluster_type, ClusterTypeReport::L2Table { .. }) {
            continue;
        }
        let score = if file.seek(SeekFrom::Start(c.offset)).is_ok()
            && file.read_exact(&mut buf).is_ok()
        {
            score_l2_against_data(&buf, cluster_size, &data_offsets)
        } else {
            0
        };
        l2_scored.push((idx, score));
    }

    // Sort by score descending — keep the best L2 candidates
    l2_scored.sort_by(|a, b| b.1.cmp(&a.1));

    let mut reclassified = 0u32;
    for &(idx, _) in &l2_scored[keep..] {
        clusters[idx].cluster_type = ClusterTypeReport::Data;
        reclassified += 1;
    }

    if reclassified > 0 {
        summary.l2_tables -= reclassified as u64;
        summary.data += reclassified as u64;
        eprintln!(
            "  info: reclassified {} false-positive L2 tables as Data \
             (found {} L2 but expected ~{} for {} data clusters, keeping {})",
            reclassified, l2_count, expected_l2, data_count, keep
        );
    }
}

/// Score an L2 table candidate by how many entries point to known data clusters.
fn score_l2_against_data(
    raw_data: &[u8],
    _cluster_size: u64,
    data_offsets: &std::collections::HashSet<u64>,
) -> u32 {
    use byteorder::{BigEndian, ByteOrder};
    use qcow2_format::constants::*;

    let entry_count = raw_data.len() / L2_ENTRY_SIZE;
    let mut hits = 0u32;

    for i in 0..entry_count {
        let raw = BigEndian::read_u64(&raw_data[i * 8..(i + 1) * 8]);
        if raw == 0 {
            continue;
        }
        let offset = raw & L2_STANDARD_OFFSET_MASK;
        if offset > 0 && data_offsets.contains(&offset) {
            hits += 1;
        }
    }

    hits
}
