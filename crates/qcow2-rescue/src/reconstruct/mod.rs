//! Phase 2: Metadata reconstruction from classified clusters.
//!
//! Takes the cluster map from Phase 1 and reconstructs guest-to-host
//! mappings by parsing L1/L2 tables found during the scan.
//!
//! Strategy:
//! 1. Try reading the header to get L1 table offset and virtual_size.
//! 2. If header is intact, follow L1 → L2 chains (the "clean" path).
//! 3. Also parse L2 clusters found by the classifier, even if not referenced
//!    by L1, to recover mappings from orphan L2 tables.
//! 4. Track which host data/compressed clusters are referenced by L2 entries
//!    and which are orphaned.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;
use qcow2_format::l2::L2Entry;
use qcow2_format::refcount::{read_refcount_table, RefcountBlock};
use qcow2_format::types::ClusterGeometry;

use crate::error::Result;
use crate::report::*;

/// Reconstruct guest-to-host mappings from a scanned image.
///
/// Reads the file directly (not from memory) using offsets from the cluster map.
pub fn reconstruct(path: &Path, cluster_map: &ClusterMapReport) -> Result<ReconstructedTablesReport> {
    let cluster_size = cluster_map.cluster_size;
    let cluster_bits = cluster_size.trailing_zeros();

    let mut file = std::fs::File::open(path)?;

    // Determine virtual_size from header scan results
    let virtual_size = find_virtual_size(cluster_map);

    // Try to read L1 table from the header
    let l1_result = try_read_l1_from_header(&mut file, cluster_size);

    // Collect L2 table cluster offsets from the scan
    let scan_l2_offsets: Vec<u64> = cluster_map
        .clusters
        .iter()
        .filter(|c| matches!(c.cluster_type, ClusterTypeReport::L2Table { .. }))
        .map(|c| c.offset)
        .collect();

    // Detect extended_l2 from header (may be corrupt).
    let header_extended_l2 = detect_extended_l2(&mut file, cluster_size);

    // Detect encryption from header.
    let is_encrypted = detect_encryption(&mut file, cluster_size);

    // Build set of offsets that are valid mapping targets (Data or Compressed clusters).
    // An L2 entry pointing to a Header, L1, L2, Refcount, or Empty cluster is implausible.
    let valid_data_offsets: HashSet<u64> = cluster_map
        .clusters
        .iter()
        .filter(|c| {
            matches!(
                c.cluster_type,
                ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. }
            )
        })
        .map(|c| c.offset)
        .collect();

    // Always try both modes and pick the most plausible result.
    // Even if the header is readable, the incompatible_features field could be corrupt.
    // The header's choice gets a small bonus in scoring to break ties.
    let file_size = cluster_map.file_size;

    let mut best_result: Option<(
        BTreeMap<u64, MappingEntry>,
        u32, // l2_tables_verified
        u32, // l2_tables_suspicious
        u32, // l1_entries_found
        ClusterGeometry,
        (i64, bool), // plausibility (score, header_match)
    )> = None;

    for try_extended in [false, true] {
        let geo = ClusterGeometry {
            cluster_bits,
            extended_l2: try_extended,
        };

        let (mappings, verified, suspicious, l1_entries) = reconstruct_with_geometry(
            &mut file,
            &l1_result,
            &scan_l2_offsets,
            &valid_data_offsets,
            cluster_size,
            cluster_bits,
            geo,
            is_encrypted,
        );

        let score = score_plausibility(
            &mappings,
            file_size,
            virtual_size,
            cluster_size,
            &valid_data_offsets,
            header_extended_l2 == Some(try_extended),
        );

        let is_better = match &best_result {
            None => true,
            Some((.., prev_score)) => score > *prev_score,
        };

        if is_better {
            best_result = Some((mappings, verified, suspicious, l1_entries, geo, score));
        }
    }

    let (mappings, l2_tables_verified, l2_tables_suspicious, l1_entries_found, _geo, _score) =
        best_result.unwrap_or_else(|| {
            let geo = ClusterGeometry { cluster_bits, extended_l2: false };
            (BTreeMap::new(), 0, 0, 0, geo, (0, false))
        });

    // Phase 2c: Find orphan data clusters (not referenced by any L2 entry)
    let referenced_hosts: HashSet<u64> = mappings
        .values()
        .map(|m| m.host_offset)
        .collect();

    let orphan_data_clusters = cluster_map
        .clusters
        .iter()
        .filter(|c| {
            matches!(c.cluster_type, ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. })
                && !referenced_hosts.contains(&c.offset)
        })
        .count() as u64;

    let mappings_from_l2 = mappings
        .values()
        .filter(|m| matches!(m.source, MappingSource::L2Table))
        .count() as u64;

    let mappings_vec: Vec<MappingEntry> = mappings.into_values().collect();

    // Phase 2d: Refcount cross-check
    let refcount_check = cross_check_refcounts(&mut file, cluster_size, &mappings_vec);

    Ok(ReconstructedTablesReport {
        file_path: cluster_map.file_path.clone(),
        l1_entries: l1_entries_found,
        l2_tables_verified,
        l2_tables_suspicious,
        mappings_total: mappings_vec.len() as u64,
        mappings_from_l2,
        orphan_data_clusters,
        refcount_check,
        content_validation: None, // Filled in later by content validation pass
        mappings: mappings_vec,
        virtual_size,
    })
}

/// Run L1→L2 chain reconstruction with a specific geometry.
///
/// Returns (mappings, l2_verified, l2_suspicious, l1_entries).
fn reconstruct_with_geometry(
    file: &mut std::fs::File,
    l1_result: &Option<Vec<u8>>,
    scan_l2_offsets: &[u64],
    valid_data_offsets: &HashSet<u64>,
    cluster_size: u64,
    cluster_bits: u32,
    geo: ClusterGeometry,
    is_encrypted: bool,
) -> (BTreeMap<u64, MappingEntry>, u32, u32, u32) {
    let file_size = file.seek(SeekFrom::End(0)).unwrap_or(0);
    let mut mappings: BTreeMap<u64, MappingEntry> = BTreeMap::new();
    let mut l2_tables_verified = 0u32;
    let mut l2_tables_suspicious = 0u32;
    let mut l1_entries_found = 0u32;
    let mut l1_referenced_l2: HashSet<u64> = HashSet::new();

    if let Some(ref l1_data) = l1_result {
        l1_entries_found = (l1_data.len() / L1_ENTRY_SIZE) as u32;
        let l2_entries_per_table = geo.l2_entries_per_table();

        for (l1_idx, chunk) in l1_data.chunks_exact(L1_ENTRY_SIZE).enumerate() {
            let raw = BigEndian::read_u64(chunk);
            let l2_offset = raw & L1_OFFSET_MASK;
            if l2_offset == 0 {
                continue;
            }

            // Plausibility: L2 offset must be cluster-aligned and within file
            if l2_offset % cluster_size != 0 || l2_offset + cluster_size > file_size {
                l2_tables_suspicious += 1;
                continue;
            }

            let verified = scan_l2_offsets.contains(&l2_offset);
            l1_referenced_l2.insert(l2_offset);

            match read_l2_table(file, l2_offset, cluster_size, geo) {
                Ok(entries) => {
                    if verified {
                        l2_tables_verified += 1;
                    } else {
                        l2_tables_suspicious += 1;
                    }

                    add_l2_mappings(
                        &entries,
                        l1_idx as u64,
                        l2_entries_per_table,
                        cluster_size,
                        cluster_bits,
                        MappingSource::L2Table,
                        geo.extended_l2,
                        file_size,
                        valid_data_offsets,
                        is_encrypted,
                        &mut mappings,
                    );
                }
                Err(_) => {
                    l2_tables_suspicious += 1;
                }
            }
        }
    }

    // Orphan L2 tables from the scanner
    let l2_entries_per_table = geo.l2_entries_per_table();

    for &l2_offset in scan_l2_offsets {
        if l1_referenced_l2.contains(&l2_offset) {
            continue;
        }

        let inferred_l1_idx = infer_l1_index_for_orphan_l2(
            l2_offset,
            l1_result,
            cluster_size,
        );

        match read_l2_table(file, l2_offset, cluster_size, geo) {
            Ok(entries) => {
                l2_tables_verified += 1;

                if let Some(l1_idx) = inferred_l1_idx {
                    add_l2_mappings(
                        &entries,
                        l1_idx,
                        l2_entries_per_table,
                        cluster_size,
                        cluster_bits,
                        MappingSource::Heuristic,
                        geo.extended_l2,
                        file_size,
                        valid_data_offsets,
                        is_encrypted,
                        &mut mappings,
                    );
                }
            }
            Err(_) => {
                l2_tables_suspicious += 1;
            }
        }
    }

    (mappings, l2_tables_verified, l2_tables_suspicious, l1_entries_found)
}

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
fn score_plausibility(
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

/// Detect whether the image uses extended L2 entries by reading the header.
///
/// Returns `Some(true)` for extended, `Some(false)` for standard,
/// or `None` if the header is unreadable (caller should try both).
fn detect_extended_l2(file: &mut std::fs::File, cluster_size: u64) -> Option<bool> {
    let mut header_buf = vec![0u8; 4096.min(cluster_size as usize)];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut header_buf).ok()?;
    let header = qcow2_format::Header::read_from(&header_buf).ok()?;
    Some(header.has_extended_l2())
}

/// Detect whether the image uses LUKS encryption from the header.
fn detect_encryption(file: &mut std::fs::File, cluster_size: u64) -> bool {
    let mut header_buf = vec![0u8; 4096.min(cluster_size as usize)];
    if file.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    if file.read_exact(&mut header_buf).is_err() {
        return false;
    }
    match qcow2_format::Header::read_from(&header_buf) {
        Ok(header) => header.crypt_method == CRYPT_LUKS,
        Err(_) => false,
    }
}

/// Extract the virtual_size from the first header found in the cluster map.
fn find_virtual_size(cluster_map: &ClusterMapReport) -> Option<u64> {
    cluster_map.clusters.iter().find_map(|c| {
        if let ClusterTypeReport::Header { virtual_size, .. } = c.cluster_type {
            Some(virtual_size)
        } else {
            None
        }
    })
}

/// Try to read the L1 table by parsing the header at offset 0.
///
/// Returns the raw L1 table bytes, or None if the header is unreadable.
fn try_read_l1_from_header(file: &mut std::fs::File, cluster_size: u64) -> Option<Vec<u8>> {
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

/// Read and parse an L2 table from the file.
fn read_l2_table(
    file: &mut std::fs::File,
    offset: u64,
    cluster_size: u64,
    geo: ClusterGeometry,
) -> Result<Vec<(u32, L2Entry)>> {
    let mut buf = vec![0u8; cluster_size as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;

    let entry_size = geo.l2_entry_size();
    let entry_count = cluster_size as usize / entry_size;
    let mut entries = Vec::new();

    for i in 0..entry_count {
        let base = i * entry_size;
        let raw = BigEndian::read_u64(&buf[base..]);
        if raw == 0 && (!geo.extended_l2 || BigEndian::read_u64(&buf[base + 8..]) == 0) {
            continue; // Skip unallocated entries
        }

        let entry = if geo.extended_l2 {
            let bitmap_raw = BigEndian::read_u64(&buf[base + 8..]);
            L2Entry::decode_extended(raw, bitmap_raw, geo.cluster_bits, true)
        } else {
            L2Entry::decode(raw, geo.cluster_bits)
        };

        if !matches!(entry, L2Entry::Unallocated) {
            entries.push((i as u32, entry));
        }
    }

    Ok(entries)
}

/// Add mappings from parsed L2 entries to the mapping table.
///
/// Each entry is validated for plausibility:
/// - Host offset must be cluster-aligned and within the file
/// - Host offset must point to a cluster classified as Data or Compressed
///   (not Header, L1, L2, Refcount, or Empty)
fn add_l2_mappings(
    entries: &[(u32, L2Entry)],
    l1_idx: u64,
    l2_entries_per_table: u64,
    cluster_size: u64,
    cluster_bits: u32,
    source: MappingSource,
    extended_l2: bool,
    file_size: u64,
    valid_data_offsets: &HashSet<u64>,
    is_encrypted: bool,
    mappings: &mut BTreeMap<u64, MappingEntry>,
) {
    for &(l2_idx, ref entry) in entries {
        let guest_offset =
            (l1_idx * l2_entries_per_table + l2_idx as u64) * cluster_size;

        // Only report subcluster info for actual extended L2 entries.
        // Standard entries synthesize all_allocated() which is not real metadata.
        let subclusters = if extended_l2 {
            let sc_bitmap = entry.subclusters().0;
            if sc_bitmap != 0 {
                Some(SubclusterInfo::from_bitmap(sc_bitmap, cluster_size))
            } else {
                None
            }
        } else {
            None
        };

        match entry {
            L2Entry::Standard { host_offset, .. } => {
                // Plausibility: must be cluster-aligned, non-zero, within file,
                // and point to a cluster classified as Data or Compressed.
                let in_file = host_offset.0 > 0
                    && host_offset.is_cluster_aligned(cluster_bits)
                    && host_offset.0 < file_size;
                // If we have scan data, cross-check against classified cluster types.
                // An empty valid_data_offsets means no scan data (shouldn't happen).
                let target_ok = valid_data_offsets.is_empty()
                    || valid_data_offsets.contains(&host_offset.0);
                if in_file && target_ok {
                    mappings.entry(guest_offset).or_insert(MappingEntry {
                        guest_offset,
                        host_offset: host_offset.0,
                        source,
                        compressed: false,
                        encrypted: is_encrypted,
                        subclusters,
                    });
                }
            }
            L2Entry::Compressed(desc) => {
                // Plausibility: host offset must be within the file and
                // the containing cluster must be classified as Data or Compressed.
                let containing_cluster = desc.host_offset & !(cluster_size - 1);
                let target_ok = valid_data_offsets.is_empty()
                    || valid_data_offsets.contains(&containing_cluster);
                if desc.host_offset < file_size && target_ok {
                    mappings.entry(guest_offset).or_insert(MappingEntry {
                        guest_offset,
                        host_offset: desc.host_offset,
                        source,
                        compressed: true,
                        encrypted: is_encrypted,
                        subclusters: None,
                    });
                }
            }
            L2Entry::Zero { .. } | L2Entry::Unallocated => {
                // No host mapping for zero/unallocated entries
            }
        }
    }
}

/// Try to infer which L1 index an orphan L2 table belongs to.
///
/// If we have a valid L1 table, scan it for an entry that matches.
/// Otherwise, return None (we can't determine the guest range).
fn infer_l1_index_for_orphan_l2(
    l2_offset: u64,
    l1_data: &Option<Vec<u8>>,
    _cluster_size: u64,
) -> Option<u64> {
    // If we have L1 data, scan for a matching entry
    if let Some(l1_buf) = l1_data {
        for (idx, chunk) in l1_buf.chunks_exact(L1_ENTRY_SIZE).enumerate() {
            let raw = BigEndian::read_u64(chunk);
            let offset = raw & L1_OFFSET_MASK;
            if offset == l2_offset {
                return Some(idx as u64);
            }
        }
    }

    // Without L1 data, we cannot determine the guest address range.
    // Future enhancement: use data pattern matching or known file signatures.
    None
}

/// Cross-check refcounts for all mapped host clusters.
///
/// Reads the refcount table and blocks from the image (via header), then
/// looks up the refcount for each host offset in the reconstructed mappings.
/// Normal allocated clusters should have refcount == 1.
///
/// Returns `None` if the header or refcount table is unreadable.
fn cross_check_refcounts(
    file: &mut std::fs::File,
    cluster_size: u64,
    mappings: &[MappingEntry],
) -> Option<RefcountCheckReport> {
    if mappings.is_empty() {
        return None;
    }

    // Read header for refcount table location and order
    let mut header_buf = vec![0u8; 4096.min(cluster_size as usize)];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut header_buf).ok()?;
    let header = qcow2_format::Header::read_from(&header_buf).ok()?;

    let rt_offset = header.refcount_table_offset.0;
    let rt_clusters = header.refcount_table_clusters;
    let refcount_order = header.refcount_order;

    if rt_offset == 0 || rt_clusters == 0 {
        return None;
    }

    // Read refcount table
    let rt_entry_count = (rt_clusters as u64 * cluster_size / REFCOUNT_TABLE_ENTRY_SIZE as u64) as u32;
    let rt_byte_size = rt_entry_count as usize * REFCOUNT_TABLE_ENTRY_SIZE;
    let mut rt_buf = vec![0u8; rt_byte_size];
    file.seek(SeekFrom::Start(rt_offset)).ok()?;
    file.read_exact(&mut rt_buf).ok()?;

    let rt_entries = read_refcount_table(&rt_buf, rt_entry_count).ok()?;

    // Number of clusters covered by one refcount block
    let refcount_bits = 1u32 << refcount_order;
    let entries_per_block = (cluster_size as u32 * 8) / refcount_bits;

    let mut correct = 0u64;
    let mut leaked = 0u64;
    let mut shared = 0u64;
    let mut unreadable = 0u64;
    let mut mismatches = Vec::new();
    let max_mismatches = 1000;

    // Cache for refcount blocks (block_offset → parsed block)
    let mut block_cache: std::collections::HashMap<u64, Option<RefcountBlock>> =
        std::collections::HashMap::new();

    for m in mappings {
        // Which cluster index is this host offset?
        let cluster_idx = m.host_offset / cluster_size;

        // Which refcount table entry covers this cluster?
        let rt_idx = (cluster_idx / entries_per_block as u64) as usize;
        if rt_idx >= rt_entries.len() {
            unreadable += 1;
            continue;
        }

        let block_offset = match rt_entries[rt_idx].block_offset() {
            Some(off) => off.0,
            None => {
                // Refcount table entry is zero → cluster has refcount 0
                leaked += 1;
                if mismatches.len() < max_mismatches {
                    mismatches.push(RefcountMismatch {
                        host_offset: m.host_offset,
                        guest_offset: m.guest_offset,
                        expected: 1,
                        actual: 0,
                    });
                }
                continue;
            }
        };

        // Read or get cached refcount block
        let block = block_cache.entry(block_offset).or_insert_with(|| {
            let mut buf = vec![0u8; cluster_size as usize];
            if file.seek(SeekFrom::Start(block_offset)).is_err() {
                return None;
            }
            if file.read_exact(&mut buf).is_err() {
                return None;
            }
            RefcountBlock::read_from(&buf, refcount_order).ok()
        });

        let refcount = match block {
            Some(b) => {
                let idx_in_block = (cluster_idx % entries_per_block as u64) as u32;
                match b.get(idx_in_block) {
                    Ok(rc) => rc,
                    Err(_) => {
                        unreadable += 1;
                        continue;
                    }
                }
            }
            None => {
                unreadable += 1;
                continue;
            }
        };

        if refcount == 1 {
            correct += 1;
        } else if refcount == 0 {
            leaked += 1;
            if mismatches.len() < max_mismatches {
                mismatches.push(RefcountMismatch {
                    host_offset: m.host_offset,
                    guest_offset: m.guest_offset,
                    expected: 1,
                    actual: 0,
                });
            }
        } else {
            shared += 1;
            if mismatches.len() < max_mismatches {
                mismatches.push(RefcountMismatch {
                    host_offset: m.host_offset,
                    guest_offset: m.guest_offset,
                    expected: 1,
                    actual: refcount,
                });
            }
        }
    }

    Some(RefcountCheckReport {
        refcount_order,
        clusters_checked: correct + leaked + shared + unreadable,
        correct,
        leaked,
        shared,
        unreadable,
        mismatches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create a minimal valid QCOW2 image in a temp file.
    fn create_test_image(
        cluster_bits: u32,
        virtual_size: u64,
        l2_mappings: &[(u32, u64)], // (l2_index, host_offset)
    ) -> (tempfile::NamedTempFile, u64) {
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Layout:
        // Cluster 0: header
        // Cluster 1: L1 table
        // Cluster 2: L2 table (for L1[0])
        // Cluster 3+: data clusters

        let l1_offset = cluster_size;
        let l2_offset = 2 * cluster_size;
        let data_start = 3 * cluster_size;

        // Total file size: header + L1 + L2 + data clusters
        let num_data_clusters = l2_mappings.len() as u64;
        let file_size = data_start + num_data_clusters * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Write QCOW2 header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        // refcount_table_offset (dummy, not used in this test)
        BigEndian::write_u64(&mut buf[48..56], 0);
        // v3 header_length
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Write L1 table: entry 0 points to L2 at cluster 2
        let l1_raw = l2_offset | (1u64 << 63); // COPIED flag
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l1_raw,
        );

        // Write L2 table entries
        for (i, &(l2_idx, host_off)) in l2_mappings.iter().enumerate() {
            let actual_host = if host_off == 0 {
                data_start + i as u64 * cluster_size
            } else {
                host_off
            };
            let l2_raw = actual_host | (1u64 << 63); // COPIED flag
            let entry_offset = l2_offset as usize + l2_idx as usize * 8;
            BigEndian::write_u64(&mut buf[entry_offset..], l2_raw);
        }

        // Write some data in data clusters
        for i in 0..num_data_clusters {
            let off = (data_start + i * cluster_size) as usize;
            for j in 0..cluster_size as usize {
                buf[off + j] = ((i as u8).wrapping_mul(7).wrapping_add(j as u8)) | 1;
            }
        }

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        (tmpfile, cluster_size)
    }

    #[test]
    fn reconstruct_simple_image() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20; // 1 MB

        // Create image with 3 data clusters mapped at L2 indices 0, 1, 2
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0), (2, 0)],
        );

        // Run Phase 1 scan
        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();

        // Verify scan found the expected cluster types
        assert!(cluster_map.summary.headers >= 1);
        assert!(cluster_map.summary.data >= 3);
        // Note: sparse L2 tables with few entries may not be classified as L2
        // by the scanner, but reconstruction still works via L1 → L2 chains.

        // Run Phase 2 reconstruct
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert!(report.l1_entries > 0);
        assert!(report.l2_tables_verified + report.l2_tables_suspicious >= 1);
        assert_eq!(report.mappings_total, 3);
        assert_eq!(report.mappings_from_l2, 3);

        // Verify mappings are in correct guest offset order
        for (i, m) in report.mappings.iter().enumerate() {
            assert_eq!(m.guest_offset, i as u64 * cluster_size);
            assert!(!m.compressed);
            assert!(matches!(m.source, MappingSource::L2Table));
        }
    }

    #[test]
    fn reconstruct_with_gaps() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 24; // 16 MB

        // Sparse: only L2 indices 0, 10, 100 are mapped
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (10, 0), (100, 0)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 3);

        // Guest offsets should match L2 indices
        assert_eq!(report.mappings[0].guest_offset, 0);
        assert_eq!(report.mappings[1].guest_offset, 10 * cluster_size);
        assert_eq!(report.mappings[2].guest_offset, 100 * cluster_size);
    }

    #[test]
    fn orphan_data_clusters_detected() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // Create image with 1 mapped cluster
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 1);
        // The data cluster at index 3 is referenced by L2[0],
        // so orphan count should be 0 for this test
        assert_eq!(report.orphan_data_clusters, 0);
    }

    #[test]
    fn virtual_size_from_header() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 30; // 1 GB

        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.virtual_size, Some(virtual_size));
    }

    /// Helper: create a minimal extended L2 QCOW2 image in a temp file.
    fn create_extended_l2_test_image(
        cluster_bits: u32,
        virtual_size: u64,
        l2_mappings: &[(u32, u64)], // (l2_index, host_offset)
    ) -> (tempfile::NamedTempFile, u64) {
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 16; // 16-byte entries for extended L2
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        let l1_offset = cluster_size;
        let l2_offset = 2 * cluster_size;
        let data_start = 3 * cluster_size;

        let num_data_clusters = l2_mappings.len() as u64;
        let file_size = data_start + num_data_clusters * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Write QCOW2 header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        BigEndian::write_u64(&mut buf[48..56], 0);
        // incompatible_features: EXTENDED_L2 = bit 4 = 16
        BigEndian::write_u64(&mut buf[72..80], 16);
        // v3 header_length
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Write L1 table
        let l1_raw = l2_offset | (1u64 << 63);
        BigEndian::write_u64(&mut buf[l1_offset as usize..], l1_raw);

        // Write extended L2 table entries (16 bytes each)
        for (i, &(l2_idx, host_off)) in l2_mappings.iter().enumerate() {
            let actual_host = if host_off == 0 {
                data_start + i as u64 * cluster_size
            } else {
                host_off
            };
            let l2_raw = actual_host | (1u64 << 63); // COPIED flag
            let entry_offset = l2_offset as usize + l2_idx as usize * 16;
            // Word 1: L2 entry
            BigEndian::write_u64(&mut buf[entry_offset..], l2_raw);
            // Word 2: SubclusterBitmap — all subclusters allocated
            BigEndian::write_u64(&mut buf[entry_offset + 8..], 0x0000_0000_FFFF_FFFF);
        }

        // Write data
        for i in 0..num_data_clusters {
            let off = (data_start + i * cluster_size) as usize;
            for j in 0..cluster_size as usize {
                buf[off + j] = ((i as u8).wrapping_mul(7).wrapping_add(j as u8)) | 1;
            }
        }

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        (tmpfile, cluster_size)
    }

    #[test]
    fn reconstruct_extended_l2_image() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        let (tmpfile, _cs) = create_extended_l2_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0), (2, 0)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert!(report.l1_entries > 0);
        assert_eq!(report.mappings_total, 3);

        // Verify subcluster info is present and shows all-allocated
        for m in &report.mappings {
            let sc = m.subclusters.as_ref().expect(
                &format!("expected subcluster info for guest_offset {}", m.guest_offset),
            );
            assert_eq!(sc.raw_bitmap, 0x0000_0000_FFFF_FFFF);
            assert_eq!(sc.allocated_count, 32);
            assert_eq!(sc.zero_count, 0);
            assert_eq!(sc.unallocated_count, 0);
            assert_eq!(sc.state_map, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            assert_eq!(sc.allocated_ranges.len(), 1);
            assert_eq!(sc.allocated_ranges[0], (0, cluster_size));
        }
    }

    #[test]
    fn reconstruct_extended_l2_with_gaps() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 24;

        let (tmpfile, _cs) = create_extended_l2_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (10, 0)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 2);
        assert_eq!(report.mappings[0].guest_offset, 0);
        assert_eq!(report.mappings[1].guest_offset, 10 * cluster_size);
    }

    #[test]
    fn reconstruct_extended_l2_partial_subclusters() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        let (tmpfile, _cs) = create_extended_l2_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0)],
        );

        // Patch the bitmap of L2[0] to have partial allocation:
        // subclusters 0-7 allocated, 8-15 zero, 16-31 unallocated
        {
            use std::io::{Seek, Write};
            let l2_offset = 2 * cluster_size;
            let bitmap_offset = l2_offset + 8; // word 2 of first entry
            let alloc: u32 = 0x0000_00FF;
            let zero: u32 = 0x0000_FF00;
            let bitmap = (zero as u64) << 32 | alloc as u64;

            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(tmpfile.path())
                .unwrap();
            f.seek(SeekFrom::Start(bitmap_offset)).unwrap();
            let mut buf = [0u8; 8];
            BigEndian::write_u64(&mut buf, bitmap);
            f.write_all(&buf).unwrap();
        }

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 1);
        let sc = report.mappings[0].subclusters.as_ref().expect("expected subcluster info");
        assert_eq!(sc.allocated_count, 8);
        assert_eq!(sc.zero_count, 8);
        assert_eq!(sc.unallocated_count, 16);
        assert_eq!(sc.state_map, "AAAAAAAAZZZZZZZZUUUUUUUUUUUUUUUU");
        // One contiguous allocated range: subclusters 0-7
        assert_eq!(sc.allocated_ranges.len(), 1);
        let sc_size = cluster_size / 32;
        assert_eq!(sc.allocated_ranges[0], (0, 8 * sc_size));
    }

    #[test]
    fn out_of_bounds_host_offsets_filtered() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // Create image with one valid and one out-of-bounds host offset.
        // The OOB entry points way beyond the file size.
        let oob_offset = 100 * cluster_size; // file is only ~4-5 clusters
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, oob_offset)],
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        // Only the valid mapping should survive plausibility filtering
        assert_eq!(report.mappings_total, 1);
        assert_eq!(report.mappings[0].guest_offset, 0);
    }

    #[test]
    fn l2_entry_pointing_to_metadata_filtered() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // L2 index 0: host_offset = 0 (points to header cluster!)
        // L2 index 1: host_offset = cluster_size (points to L1 table!)
        // L2 index 2: valid data cluster
        // The first two should be filtered because the scanner classified
        // those clusters as Header and L1Table, not Data.
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, cluster_size), (2, 0)],
        );

        // Manually fix: entry at L2[0] points to offset 0 (header),
        // entry at L2[1] points to cluster 1 (L1 table).
        // create_test_image auto-assigned host offsets starting at data_start,
        // so we need to patch the L2 entries directly.
        {
            use std::io::{Seek, Write};
            let l2_offset = 2 * cluster_size;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(tmpfile.path())
                .unwrap();

            // L2[0] → offset 0 (header cluster)
            f.seek(SeekFrom::Start(l2_offset)).unwrap();
            let mut entry = [0u8; 8];
            BigEndian::write_u64(&mut entry, 0); // offset 0 with no COPIED bit → unallocated
            // Actually we need a non-zero standard entry pointing to offset 0.
            // But offset 0 is rejected by the > 0 check already. Use the refcount table
            // area or header cluster at a plausible-looking offset instead.
            // Let's make L2[0] point to the L2 table itself (cluster 2 = metadata)
            let l2_self = 2 * cluster_size | (1u64 << 63);
            BigEndian::write_u64(&mut entry, l2_self);
            f.write_all(&entry).unwrap();

            // L2[1] → L1 table (cluster 1 = metadata)
            let l1_target = cluster_size | (1u64 << 63);
            BigEndian::write_u64(&mut entry, l1_target);
            f.write_all(&entry).unwrap();
        }

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        // Only L2[2] (pointing to actual data) should survive
        assert_eq!(report.mappings_total, 1);
        assert_eq!(report.mappings[0].guest_offset, 2 * cluster_size);
    }

    #[test]
    fn plausibility_overrides_corrupt_header() {
        // Create a standard (non-extended) image but set the EXTENDED_L2 flag
        // in the header to simulate a corrupt incompatible_features field.
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // Use the standard image helper (8-byte L2 entries)
        let (tmpfile, _cs) = create_test_image(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0), (2, 0)],
        );

        // Corrupt: set EXTENDED_L2 bit in header
        {
            use std::io::{Seek, Write};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(tmpfile.path())
                .unwrap();
            f.seek(SeekFrom::Start(72)).unwrap();
            let mut incompat = [0u8; 8];
            BigEndian::write_u64(&mut incompat, 16); // EXTENDED_L2 = bit 4
            f.write_all(&incompat).unwrap();
        }

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        // Despite the header claiming extended L2, plausibility scoring should
        // pick standard mode because the L2 data is actually 8-byte entries.
        assert_eq!(report.mappings_total, 3);
        for m in &report.mappings {
            assert!(m.subclusters.is_none(), "should be standard L2 (no subcluster info)");
        }
    }

    /// Helper: create a QCOW2 image with proper refcount table and block.
    ///
    /// Layout:
    /// Cluster 0: header
    /// Cluster 1: refcount table (1 cluster)
    /// Cluster 2: refcount block (covers all clusters)
    /// Cluster 3: L1 table
    /// Cluster 4: L2 table (for L1[0])
    /// Cluster 5+: data clusters
    fn create_image_with_refcounts(
        cluster_bits: u32,
        virtual_size: u64,
        l2_mappings: &[(u32, u64)], // (l2_index, host_offset)
        refcount_overrides: &[(u64, u16)], // (cluster_index, refcount_value)
    ) -> (tempfile::NamedTempFile, u64) {
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        let rt_offset = cluster_size;       // cluster 1
        let rb_offset = 2 * cluster_size;   // cluster 2
        let l1_offset = 3 * cluster_size;   // cluster 3
        let l2_offset = 4 * cluster_size;   // cluster 4
        let data_start = 5 * cluster_size;  // cluster 5+

        let num_data_clusters = l2_mappings.len() as u64;
        let total_clusters = 5 + num_data_clusters;
        let file_size = total_clusters * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Write QCOW2 header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        // refcount_table_offset
        BigEndian::write_u64(&mut buf[48..56], rt_offset);
        // refcount_table_clusters = 1
        BigEndian::write_u32(&mut buf[56..60], 1);
        // refcount_order = 4 (16-bit)
        BigEndian::write_u32(&mut buf[96..100], 4);
        // v3 header_length
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Write refcount table: entry 0 points to refcount block at rb_offset
        BigEndian::write_u64(&mut buf[rt_offset as usize..], rb_offset);

        // Write refcount block: set refcount=1 for all used clusters
        // Clusters 0-4 are metadata, 5+ are data
        let rb_base = rb_offset as usize;
        for i in 0..total_clusters {
            BigEndian::write_u16(&mut buf[rb_base + i as usize * 2..], 1);
        }

        // Apply refcount overrides
        for &(cluster_idx, refcount) in refcount_overrides {
            BigEndian::write_u16(
                &mut buf[rb_base + cluster_idx as usize * 2..],
                refcount,
            );
        }

        // Write L1 table
        let l1_raw = l2_offset | (1u64 << 63);
        BigEndian::write_u64(&mut buf[l1_offset as usize..], l1_raw);

        // Write L2 table entries
        for (i, &(l2_idx, host_off)) in l2_mappings.iter().enumerate() {
            let actual_host = if host_off == 0 {
                data_start + i as u64 * cluster_size
            } else {
                host_off
            };
            let l2_raw = actual_host | (1u64 << 63);
            let entry_offset = l2_offset as usize + l2_idx as usize * 8;
            BigEndian::write_u64(&mut buf[entry_offset..], l2_raw);
        }

        // Write data in data clusters
        for i in 0..num_data_clusters {
            let off = (data_start + i * cluster_size) as usize;
            for j in 0..cluster_size as usize {
                buf[off + j] = ((i as u8).wrapping_mul(7).wrapping_add(j as u8)) | 1;
            }
        }

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        (tmpfile, cluster_size)
    }

    #[test]
    fn refcount_check_all_correct() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        let (tmpfile, _cs) = create_image_with_refcounts(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0), (2, 0)],
            &[], // no overrides, all refcounts = 1
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 3);
        let rc = report.refcount_check.expect("should have refcount check");
        assert_eq!(rc.refcount_order, 4);
        assert_eq!(rc.correct, 3);
        assert_eq!(rc.leaked, 0);
        assert_eq!(rc.shared, 0);
        assert!(rc.mismatches.is_empty());
    }

    #[test]
    fn refcount_check_leaked_cluster() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // Data cluster at index 5 will have refcount=0 (leaked)
        let (tmpfile, _cs) = create_image_with_refcounts(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0)],
            &[(5, 0)], // cluster 5 (first data cluster) has refcount 0
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 2);
        let rc = report.refcount_check.expect("should have refcount check");
        assert_eq!(rc.leaked, 1);
        assert_eq!(rc.correct, 1);
        assert_eq!(rc.mismatches.len(), 1);
        assert_eq!(rc.mismatches[0].actual, 0);
        assert_eq!(rc.mismatches[0].expected, 1);
    }

    #[test]
    fn refcount_check_shared_cluster() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;

        // Data cluster at index 6 will have refcount=3 (shared, e.g. snapshot)
        let (tmpfile, _cs) = create_image_with_refcounts(
            cluster_bits,
            virtual_size,
            &[(0, 0), (1, 0)],
            &[(6, 3)], // cluster 6 (second data cluster) has refcount 3
        );

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        assert_eq!(report.mappings_total, 2);
        let rc = report.refcount_check.expect("should have refcount check");
        assert_eq!(rc.shared, 1);
        assert_eq!(rc.correct, 1);
        assert_eq!(rc.mismatches.len(), 1);
        assert_eq!(rc.mismatches[0].actual, 3);
    }
}
