//! Cluster size detection from header or heuristic analysis.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{RescueError, Result};

use super::classifier;

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
            println!(
                "  header intact: cluster_bits={}, cluster_size={}",
                header.cluster_bits, cs
            );
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
            header_buf[20],
            header_buf[21],
            header_buf[22],
            header_buf[23],
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
    let candidates = [
        65536u64, 4096, 1048576, 131072, 32768, 16384, 8192, 2097152,
    ];
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
