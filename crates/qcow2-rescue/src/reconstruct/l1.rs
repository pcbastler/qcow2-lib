//! L1 table reading from header or scan-detected clusters.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;

use crate::report::*;

/// Try to read the L1 table by parsing the header at offset 0.
///
/// Returns the raw L1 table bytes, or None if the header is unreadable.
pub(super) fn try_read_l1_from_header(file: &mut std::fs::File, cluster_size: u64) -> Option<Vec<u8>> {
    // Read enough for the header
    let mut header_buf = vec![0u8; 4096.min(cluster_size as usize)];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut header_buf).ok()?;

    let header = qcow2_format::Header::read_from(&header_buf).ok()?;

    let l1_offset = header.l1_table_offset.0;
    let l1_entries = header.l1_table_entries;
    if l1_offset == 0 || l1_entries == 0 {
        return None;
    }

    // Plausibility: L1 table must be cluster-aligned
    let cluster_size_val = 1u64 << header.cluster_bits;
    if l1_offset % cluster_size_val != 0 {
        return None;
    }

    // Plausibility: L1 table must fit within the file
    let l1_size = l1_entries as usize * L1_ENTRY_SIZE;
    let file_size = file.seek(SeekFrom::End(0)).ok()?;
    if l1_offset + l1_size as u64 > file_size {
        return None;
    }

    let mut l1_buf = vec![0u8; l1_size];
    file.seek(SeekFrom::Start(l1_offset)).ok()?;
    file.read_exact(&mut l1_buf).ok()?;

    Some(l1_buf)
}

/// Try to read the L1 table from a scan-detected L1 cluster.
///
/// When the header is corrupt but the scanner found L1-like clusters,
/// read the first one directly from disk. This provides L2 offsets
/// even when the header's l1_table_offset field is unreadable.
pub(super) fn try_read_l1_from_scan(
    file: &mut std::fs::File,
    cluster_map: &ClusterMapReport,
    cluster_size: u64,
) -> Option<Vec<u8>> {
    // Find the first scan-detected L1 cluster
    let l1_cluster = cluster_map.clusters.iter().find(|c| {
        matches!(c.cluster_type, ClusterTypeReport::L1Table { .. })
    })?;

    let l1_offset = l1_cluster.offset;
    let mut l1_buf = vec![0u8; cluster_size as usize];
    file.seek(SeekFrom::Start(l1_offset)).ok()?;
    file.read_exact(&mut l1_buf).ok()?;

    // Validate: at least one non-zero entry that points to a scan-detected L2 table
    let l2_offsets: HashSet<u64> = cluster_map.clusters.iter()
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::L2Table { .. }))
        .map(|c| c.offset)
        .collect();

    let has_valid_ref = l1_buf.chunks_exact(L1_ENTRY_SIZE).any(|chunk| {
        let raw = BigEndian::read_u64(chunk);
        let offset = raw & L1_OFFSET_MASK;
        offset > 0 && l2_offsets.contains(&offset)
    });

    if has_valid_ref {
        Some(l1_buf)
    } else {
        None
    }
}
