//! Phase 1: Cluster scanning and classification.
//!
//! Reads every cluster in an image file and classifies it by content:
//! Header, L1 table, L2 table, refcount block, compressed data,
//! uncompressed data, empty, or unknown.

mod classifier;
mod detection;
mod refinement;

pub use detection::detect_cluster_size;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::Result;
use crate::report::{ClusterInfo, ClusterMapReport, ClusterSummary, ClusterTypeReport};

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
    refinement::refine_l2_classification(&mut clusters, &mut summary, cluster_size, &mut file);

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

fn update_summary(summary: &mut ClusterSummary, ct: &ClusterTypeReport) {
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
