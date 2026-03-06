//! Phase 1: Cluster scanning and classification.
//!
//! Reads every cluster in an image file and classifies it by content:
//! Header, L1 table, L2 table, refcount block, compressed data,
//! uncompressed data, empty, or unknown.

mod classifier;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{RescueError, Result};
use crate::report::{ClusterInfo, ClusterMapReport, ClusterSummary};

/// Detect the cluster size by reading the QCOW2 header at offset 0.
///
/// Falls back to scanning for QCOW2 magic at power-of-2 boundaries,
/// then to heuristic L2-table analysis.
pub fn detect_cluster_size(path: &Path) -> Result<u64> {
    let mut file = std::fs::File::open(path)?;
    let mut header_buf = vec![0u8; 4096]; // read enough for any header
    let bytes_read = file.read(&mut header_buf)?;
    if bytes_read < 72 {
        return Err(RescueError::NoHeaderFound);
    }

    // Try parsing the header normally
    match qcow2_format::Header::read_from(&header_buf) {
        Ok(header) => {
            let cs = 1u64 << header.cluster_bits;
            println!("  header intact: cluster_bits={}, cluster_size={}", header.cluster_bits, cs);
            return Ok(cs);
        }
        Err(e) => {
            println!("  header parse failed: {e}");
        }
    }

    // Fallback: check if at least the magic is correct and cluster_bits field is readable
    let magic = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
    if magic == qcow2_format::constants::QCOW2_MAGIC {
        let cluster_bits = u32::from_be_bytes([
            header_buf[20], header_buf[21], header_buf[22], header_buf[23],
        ]);
        if cluster_bits >= qcow2_format::constants::MIN_CLUSTER_BITS
            && cluster_bits <= qcow2_format::constants::MAX_CLUSTER_BITS
        {
            let cs = 1u64 << cluster_bits;
            println!(
                "  header partially corrupt but cluster_bits={} readable, cluster_size={}",
                cluster_bits, cs
            );
            return Ok(cs);
        }
    }

    // Heuristic: try common cluster sizes and score by L2-table candidate count
    println!("  trying heuristic cluster size detection...");
    let file_size = std::fs::metadata(path)?.len();
    let candidates = [65536u64, 4096, 1048576, 131072, 32768, 16384, 8192, 2097152];
    let mut best_size = 65536u64; // default
    let mut best_score = 0u64;

    for &cs in &candidates {
        if cs > file_size {
            continue;
        }
        let score = score_cluster_size(path, cs, file_size)?;
        if score > best_score {
            best_score = score;
            best_size = cs;
        }
    }

    if best_score > 0 {
        println!(
            "  heuristic: cluster_size={} (score={} L2-like clusters)",
            best_size, best_score
        );
        Ok(best_size)
    } else {
        println!("  heuristic failed, defaulting to 65536");
        Ok(65536)
    }
}

/// Score a candidate cluster size by counting how many clusters look like L2 tables.
fn score_cluster_size(path: &Path, cluster_size: u64, file_size: u64) -> Result<u64> {
    let mut file = std::fs::File::open(path)?;
    let total_clusters = file_size / cluster_size;
    // Sample up to 256 clusters spread across the file
    let step = (total_clusters / 256).max(1);
    let mut score = 0u64;
    let mut buf = vec![0u8; cluster_size as usize];

    for i in (0..total_clusters).step_by(step as usize) {
        let offset = i * cluster_size;
        file.seek(SeekFrom::Start(offset))?;
        let n = file.read(&mut buf)?;
        if n < cluster_size as usize {
            break;
        }
        if classifier::looks_like_l2_table(&buf, cluster_size) {
            score += 1;
        }
    }

    Ok(score)
}

/// Scan every cluster in a file and classify it.
pub fn scan_file(path: &Path, cluster_size: u64) -> Result<ClusterMapReport> {
    let mut file = std::fs::File::open(path)?;
    let file_size = std::fs::metadata(path)?.len();
    let total_clusters = file_size / cluster_size;
    let trailing_bytes = file_size % cluster_size;

    let mut clusters = Vec::with_capacity(total_clusters as usize);
    let mut summary = ClusterSummary::default();
    let mut buf = vec![0u8; cluster_size as usize];

    for i in 0..total_clusters {
        let offset = i * cluster_size;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        let cluster_type = classifier::classify_cluster(&buf, cluster_size, offset);
        update_summary(&mut summary, &cluster_type);

        clusters.push(ClusterInfo {
            index: i,
            offset,
            cluster_type,
        });

        // Progress every 10%
        if total_clusters >= 10 && i % (total_clusters / 10) == 0 {
            let pct = (i * 100) / total_clusters;
            eprint!("\r  scanning: {}%", pct);
        }
    }
    if total_clusters >= 10 {
        eprintln!("\r  scanning: 100%");
    }

    // Post-scan validation: reclassify L2 tables whose entries don't point to
    // known Data/Compressed clusters. This catches false positives where PRNG or
    // other structured data passes the L2 heuristic.
    refine_l2_classification(&mut clusters, &mut summary, cluster_size, &mut file);

    let cluster_size_source = "auto-detected".to_string();

    Ok(ClusterMapReport {
        file_path: path.display().to_string(),
        file_size: file_size - trailing_bytes, // only scanned portion
        cluster_size,
        cluster_size_source,
        total_clusters,
        summary,
        clusters,
    })
}

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
fn refine_l2_classification(
    clusters: &mut [ClusterInfo],
    summary: &mut ClusterSummary,
    cluster_size: u64,
    file: &mut std::fs::File,
) {
    use crate::report::ClusterTypeReport;

    let l2_count = clusters
        .iter()
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::L2Table { .. }))
        .count();

    if l2_count <= 1 {
        return; // Nothing to refine
    }

    let data_count = clusters
        .iter()
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. }))
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
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. }))
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
    cluster_size: u64,
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

fn update_summary(summary: &mut ClusterSummary, ct: &crate::report::ClusterTypeReport) {
    use crate::report::ClusterTypeReport;
    match ct {
        ClusterTypeReport::Header { .. } => summary.headers += 1,
        ClusterTypeReport::L1Table { .. } => summary.l1_tables += 1,
        ClusterTypeReport::L2Table { .. } => summary.l2_tables += 1,
        ClusterTypeReport::RefcountBlock { .. } => summary.refcount_blocks += 1,
        ClusterTypeReport::Compressed { .. } => summary.compressed += 1,
        ClusterTypeReport::Data => summary.data += 1,
        ClusterTypeReport::Empty => summary.empty += 1,
        ClusterTypeReport::Unknown => summary.unknown += 1,
    }
}
