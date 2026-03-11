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

mod l1;
mod l2;
mod orphan;
mod refcount;
mod scoring;

use std::collections::{BTreeMap, HashSet};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;
use qcow2_format::l2::L2Entry;
use qcow2_format::types::ClusterGeometry;

use crate::config::ConflictStrategy;
use crate::error::Result;
use crate::report::*;

use l1::{try_read_l1_from_header, try_read_l1_from_scan};
use l2::{detect_extended_l2, detect_encryption, read_l2_table, add_l2_mappings};
use orphan::{MissingL2Info, detect_partition_gap, infer_l1_index_for_orphan_l2};
use refcount::cross_check_refcounts;
use scoring::{score_plausibility, find_virtual_size};

/// Reconstruct guest-to-host mappings from a scanned image.
///
/// Reads the file directly (not from memory) using offsets from the cluster map.
pub fn reconstruct(path: &Path, cluster_map: &ClusterMapReport) -> Result<ReconstructedTablesReport> {
    reconstruct_with_strategy(path, cluster_map, ConflictStrategy::Ask)
}

/// Reconstruct with a specific conflict resolution strategy.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub fn reconstruct_with_strategy(
    path: &Path,
    cluster_map: &ClusterMapReport,
    conflict_strategy: ConflictStrategy,
) -> Result<ReconstructedTablesReport> {
    let cluster_size = cluster_map.cluster_size;
    let cluster_bits = cluster_size.trailing_zeros();

    let mut file = std::fs::File::open(path)?;

    // Determine virtual_size from header scan results
    let virtual_size = find_virtual_size(cluster_map);

    // Try to read L1 table from the header, falling back to scan-detected L1 clusters
    let l1_result = try_read_l1_from_header(&mut file, cluster_size)
        .or_else(|| try_read_l1_from_scan(&mut file, cluster_map, cluster_size));

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

    #[allow(clippy::type_complexity)]
    let mut best_result: Option<(
        BTreeMap<u64, MappingEntry>,
        u32, // l2_tables_verified
        u32, // l2_tables_suspicious
        u32, // l1_entries_found
        u64, // conflicts
        ClusterGeometry,
        (i64, bool), // plausibility (score, header_match)
    )> = None;

    // Collect missing L2 info from the validated pass (best L2 reconstruction data).
    // This is separate from scoring: even if validate=false wins for mappings,
    // we still want the L1-guided info about which L2 tables are missing.
    let mut best_missing_l2: Vec<MissingL2Info> = Vec::new();

    for try_extended in [false, true] {
      for validate_l1_against_scan in [false, true] {
        let geo = ClusterGeometry {
            cluster_bits,
            extended_l2: try_extended,
        };

        let (mappings, verified, suspicious, l1_entries, conflicts, missing_l2) = reconstruct_with_geometry(
            &mut file,
            &l1_result,
            &scan_l2_offsets,
            &valid_data_offsets,
            cluster_size,
            cluster_bits,
            geo,
            is_encrypted,
            conflict_strategy,
            validate_l1_against_scan,
        );

        let mut score = score_plausibility(
            &mappings,
            file_size,
            virtual_size,
            cluster_size,
            &valid_data_offsets,
            header_extended_l2 == Some(try_extended),
        );
        // Penalize configurations with many suspicious (unconfirmed) L2 tables —
        // a sign that L1 entries are garbage pointing to random data
        score.0 -= suspicious as i64 * 10;

        // Bonus for recoverable orphan data clusters: each orphan that could
        // be assigned via heuristic is valuable. This makes the validated
        // variant win when garbage L1 entries create false mappings that
        // block orphan recovery.
        //
        // Exclude corrupted L2 offsets from orphan counting — those clusters
        // contain metadata garbage, not user data, and shouldn't inflate the score.
        let referenced: HashSet<u64> = mappings.values().map(|m| m.host_offset).collect();
        let corrupt_l2_hosts: HashSet<u64> = missing_l2.iter().map(|m| m.host_offset).collect();
        let potential_orphans = cluster_map.clusters.iter()
            .filter(|c| matches!(c.cluster_type, ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. })
                && !referenced.contains(&c.offset)
                && !corrupt_l2_hosts.contains(&c.offset))
            .count();
        score.0 += potential_orphans as i64 * 2;

        eprintln!("  [scoring] ext={} val={}: mappings={} orphans={} missing_l2={} suspicious={} score={:?}",
            try_extended, validate_l1_against_scan,
            mappings.len(), potential_orphans, missing_l2.len(), suspicious, score);

        // Keep the best missing_l2 info from any validated pass
        if validate_l1_against_scan && missing_l2.len() > best_missing_l2.len() {
            best_missing_l2 = missing_l2;
        }

        let is_better = match &best_result {
            None => true,
            Some((.., prev_score)) => score > *prev_score,
        };

        if is_better {
            best_result = Some((mappings, verified, suspicious, l1_entries, conflicts, geo, score));
        }
      }
    }

    let (mut mappings, l2_tables_verified, l2_tables_suspicious, l1_entries_found, total_conflicts, _geo, _score) =
        best_result.unwrap_or_else(|| {
            let geo = ClusterGeometry { cluster_bits, extended_l2: false };
            (BTreeMap::new(), 0, 0, 0, 0, geo, (0, false))
        });

    let missing_l2_info = best_missing_l2;

    // Phase 2c: Find orphan data clusters (not referenced by any L2 entry).
    //
    // IMPORTANT: Exclude host offsets of corrupted L2 tables. When L1 points to
    // an L2 offset that the scanner didn't confirm as L2 (corrupted), that cluster
    // contains metadata garbage, not user data. Including it in the orphan pool
    // would inject garbage into the recovered image and shift all subsequent data.
    let referenced_hosts: HashSet<u64> = mappings
        .values()
        .map(|m| m.host_offset)
        .collect();

    let corrupted_l2_offsets: HashSet<u64> = missing_l2_info
        .iter()
        .map(|m| m.host_offset)
        .collect();

    let mut orphan_data_offsets: Vec<u64> = cluster_map
        .clusters
        .iter()
        .filter(|c| {
            matches!(c.cluster_type, ClusterTypeReport::Data | ClusterTypeReport::Compressed { .. })
                && !referenced_hosts.contains(&c.offset)
                && !corrupted_l2_offsets.contains(&c.offset)
        })
        .map(|c| c.offset)
        .collect();
    orphan_data_offsets.sort();

    let orphan_data_clusters = orphan_data_offsets.len() as u64;

    // Phase 2c2: L1-guided orphan placement.
    //
    // When L1 is intact and tells us which L2 tables are missing, we know
    // exactly which virtual address ranges need data. Assign orphan clusters
    // to those specific ranges instead of blindly filling from offset 0.
    //
    // Strategy:
    // 1. If we have missing L2 info (L1 intact, specific L2s corrupted):
    //    a. Detect partition layout from first orphan (MBR/GPT) to find
    //       the gap between partition table and first partition data.
    //    b. Place orphan[0] at slot 0 (partition table), skip the gap,
    //       then assign remaining orphans from the partition start slot.
    // 2. Fallback: fill remaining orphans into any unmapped guest offsets.
    if !orphan_data_offsets.is_empty() {
        let l2_entries_per_table = cluster_size / 8; // standard L2
        let occupied_guests: HashSet<u64> = mappings.keys().copied().collect();

        // Try to detect partition layout from the first orphan cluster.
        // If the first orphan is an MBR/GPT, we know there's a gap between
        // the partition table (slot 0) and the first partition's data.
        let partition_start_slot = detect_partition_gap(
            &mut file, &orphan_data_offsets, cluster_size,
        );

        let mut orphan_iter = orphan_data_offsets.iter().peekable();

        if !missing_l2_info.is_empty() {
            // Sort missing L2 ranges by L1 index for deterministic assignment
            let mut missing_sorted: Vec<&MissingL2Info> = missing_l2_info.iter().collect();
            missing_sorted.sort_by_key(|m| m.l1_idx);

            for missing in &missing_sorted {
                let base_guest = missing.l1_idx * l2_entries_per_table * cluster_size;

                // Build a list of target slots, respecting partition gap
                let target_slots: Vec<u64> = if let Some(part_start) = partition_start_slot {
                    // First orphan goes at slot 0 (MBR/GPT), then skip to
                    // partition start for the rest. After partition start, fill
                    // sequentially.
                    let mut slots = Vec::new();
                    // Slot 0 for the partition table cluster
                    if !occupied_guests.contains(&base_guest) {
                        slots.push(0);
                    }
                    // Remaining slots from partition start onwards
                    for s in part_start..l2_entries_per_table {
                        let guest = base_guest + s * cluster_size;
                        if !occupied_guests.contains(&guest) {
                            slots.push(s);
                        }
                    }
                    slots
                } else {
                    // No partition table detected — fill sequentially
                    (0..l2_entries_per_table)
                        .filter(|&s| !occupied_guests.contains(&(base_guest + s * cluster_size)))
                        .collect()
                };

                for l2_slot in target_slots {
                    let guest_offset = base_guest + l2_slot * cluster_size;
                    if let Some(&host_offset) = orphan_iter.next() {
                        mappings.entry(guest_offset).or_insert(MappingEntry {
                            guest_offset,
                            host_offset,
                            compressed: false,
                            encrypted: false,
                            source: MappingSource::Heuristic,
                            subclusters: None,
                        });
                    } else {
                        break;
                    }
                }
            }

            let assigned_targeted = orphan_data_offsets.len() - orphan_iter.clone().count();
            if assigned_targeted > 0 {
                let gap_info = if let Some(ps) = partition_start_slot {
                    format!(" (partition gap detected: data starts at slot {})", ps)
                } else {
                    String::new()
                };
                eprintln!(
                    "  L2 reconstruction: assigned {} orphan data clusters to {} missing L2 range(s) \
                     (L1 indices: {}){}",
                    assigned_targeted,
                    missing_sorted.len(),
                    missing_sorted.iter().map(|m| m.l1_idx.to_string()).collect::<Vec<_>>().join(", "),
                    gap_info,
                );
            }
        }

        // Fallback: assign any remaining orphans to unmapped guest offsets
        let remaining: Vec<u64> = orphan_iter.copied().collect();
        if !remaining.is_empty() {
            let occupied_guests: HashSet<u64> = mappings.keys().copied().collect();
            let mut next_guest = 0u64;
            for host_offset in &remaining {
                while occupied_guests.contains(&(next_guest * cluster_size)) {
                    next_guest += 1;
                }
                let guest_offset = next_guest * cluster_size;
                mappings.entry(guest_offset).or_insert(MappingEntry {
                    guest_offset,
                    host_offset: *host_offset,
                    compressed: false,
                    encrypted: false,
                    source: MappingSource::Heuristic,
                    subclusters: None,
                });
                next_guest += 1;
            }
            eprintln!(
                "  WARNING: {} remaining orphan data clusters assigned by disk position (heuristic)",
                remaining.len()
            );
        }
    }

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
        mapping_conflicts: total_conflicts,
        mappings: mappings_vec,
        virtual_size,
    })
}

/// Run L1→L2 chain reconstruction with a specific geometry.
///
/// Returns (mappings, l2_verified, l2_suspicious, l1_entries, conflicts,
///          corrupted_l2_offsets, missing_l2_ranges).
#[allow(clippy::too_many_arguments, clippy::too_many_lines, clippy::cognitive_complexity)]
fn reconstruct_with_geometry(
    file: &mut std::fs::File,
    l1_result: &Option<Vec<u8>>,
    scan_l2_offsets: &[u64],
    valid_data_offsets: &HashSet<u64>,
    cluster_size: u64,
    cluster_bits: u32,
    geo: ClusterGeometry,
    is_encrypted: bool,
    conflict_strategy: ConflictStrategy,
    validate_l1_against_scan: bool,
) -> (BTreeMap<u64, MappingEntry>, u32, u32, u32, u64, Vec<MissingL2Info>) {
    let file_size = file.seek(SeekFrom::End(0)).unwrap_or(0);
    let mut mappings: BTreeMap<u64, MappingEntry> = BTreeMap::new();
    let mut l2_tables_verified = 0u32;
    let mut l2_tables_suspicious = 0u32;
    let mut l1_entries_found = 0u32;
    let mut conflicts = 0u64;
    let mut l1_referenced_l2: HashSet<u64> = HashSet::new();
    let mut missing_l2s: Vec<MissingL2Info> = Vec::new();

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
                missing_l2s.push(MissingL2Info {
                    l1_idx: l1_idx as u64,
                    host_offset: l2_offset,
                });
                continue;
            }

            let verified = scan_l2_offsets.contains(&l2_offset);

            // When validation is enabled and the scanner found L2 clusters,
            // only follow L1 entries that point to scanner-confirmed L2 offsets.
            // This prevents garbage L1 entries from reading random data as L2
            // tables and creating false mappings.
            if !verified && validate_l1_against_scan && !scan_l2_offsets.is_empty() {
                l2_tables_suspicious += 1;
                missing_l2s.push(MissingL2Info {
                    l1_idx: l1_idx as u64,
                    host_offset: l2_offset,
                });
                continue;
            }

            l1_referenced_l2.insert(l2_offset);

            match read_l2_table(file, l2_offset, cluster_size, geo) {
                Ok(entries) => {
                    let nonzero_entries = entries.len();

                    // Try adding mappings from this L2 table
                    let mappings_before = mappings.len();
                    conflicts += add_l2_mappings(
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
                        conflict_strategy,
                        &mut mappings,
                    );
                    let mappings_added = mappings.len() - mappings_before;

                    // Detect garbage L2: if we read many non-zero entries but
                    // very few produced valid mappings, this L2 is likely corrupted.
                    // A real L2 table should have most entries map to valid data clusters.
                    let is_garbage = nonzero_entries >= 4
                        && mappings_added * 4 < nonzero_entries; // <25% valid

                    if is_garbage {
                        // Undo the false mappings we just added
                        let l2_base_guest = l1_idx as u64 * l2_entries_per_table * cluster_size;
                        let l2_end_guest = l2_base_guest + l2_entries_per_table * cluster_size;
                        mappings.retain(|guest, m| {
                            !(*guest >= l2_base_guest && *guest < l2_end_guest
                                && matches!(m.source, MappingSource::L2Table))
                        });

                        l2_tables_suspicious += 1;
                        missing_l2s.push(MissingL2Info {
                            l1_idx: l1_idx as u64,
                            host_offset: l2_offset,
                        });
                        eprintln!(
                            "  L2 at offset {:#x} (L1[{}]) detected as garbage: \
                             {}/{} entries produced valid mappings — treating as corrupted",
                            l2_offset, l1_idx, mappings_added, nonzero_entries
                        );
                    } else if verified {
                        l2_tables_verified += 1;
                    } else {
                        l2_tables_suspicious += 1;
                    }
                }
                Err(_) => {
                    l2_tables_suspicious += 1;
                    missing_l2s.push(MissingL2Info {
                        l1_idx: l1_idx as u64,
                        host_offset: l2_offset,
                    });
                }
            }
        }
    }

    // Orphan L2 tables from the scanner.
    // Two-pass approach: first validate which orphan L2s are real (entries point
    // to known data clusters), then infer L1 indices from the validated set only.
    let l2_entries_per_table = geo.l2_entries_per_table();

    // Pass 1: Read and validate orphan L2 tables
    let mut validated_orphan_l2: Vec<(u64, Vec<(u32, L2Entry)>)> = Vec::new();

    for &l2_offset in scan_l2_offsets {
        if l1_referenced_l2.contains(&l2_offset) {
            continue;
        }

        match read_l2_table(file, l2_offset, cluster_size, geo) {
            Ok(entries) => {
                // Validate orphan L2: check that entries produce sensible offsets.
                // A real L2 table should have entries that are:
                //  - cluster-aligned (for standard entries)
                //  - within the file bounds
                //  - pointing to known Data/Compressed clusters (if scanner data available)
                let mut hits = 0usize;
                let mut plausible = 0usize;
                let mut nonzero = 0usize;
                for (_, entry) in &entries {
                    let host = match entry {
                        L2Entry::Standard { host_offset, .. } if host_offset.0 > 0 => {
                            Some(host_offset.0)
                        }
                        L2Entry::Compressed(desc) if desc.host_offset > 0 => {
                            Some(desc.host_offset & !(cluster_size - 1))
                        }
                        _ => None,
                    };
                    if let Some(h) = host {
                        nonzero += 1;
                        // Basic plausibility: cluster-aligned and within file
                        let aligned = h % cluster_size == 0;
                        let in_file = h < file_size;
                        if aligned && in_file {
                            plausible += 1;
                            // Stronger check: points to scanner-confirmed data cluster
                            if !valid_data_offsets.is_empty() && valid_data_offsets.contains(&h) {
                                hits += 1;
                            }
                        }
                    }
                }
                // Reject if most nonzero entries aren't even plausible offsets
                if nonzero > 0 && plausible * 2 < nonzero {
                    l2_tables_suspicious += 1;
                    continue;
                }
                // Reject if scanner data available but <25% of entries point to known data
                if nonzero > 0 && !valid_data_offsets.is_empty() && hits * 4 < nonzero {
                    l2_tables_suspicious += 1;
                    continue;
                }

                validated_orphan_l2.push((l2_offset, entries));
            }
            Err(_) => {
                l2_tables_suspicious += 1;
            }
        }
    }

    // Pass 2: Infer L1 indices from validated orphan L2 offsets only
    let validated_offsets: Vec<u64> = validated_orphan_l2.iter().map(|(off, _)| *off).collect();

    for (l2_offset, entries) in validated_orphan_l2 {
        l2_tables_verified += 1;

        let inferred_l1_idx = infer_l1_index_for_orphan_l2(
            l2_offset,
            l1_result,
            &validated_offsets,
            cluster_size,
        );

        if let Some(l1_idx) = inferred_l1_idx {
            conflicts += add_l2_mappings(
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
                conflict_strategy,
                &mut mappings,
            );
        }
    }

    (mappings, l2_tables_verified, l2_tables_suspicious, l1_entries_found, conflicts, missing_l2s)
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
            let sc = m.subclusters.as_ref().unwrap_or_else(||
                panic!("expected subcluster info for guest_offset {}", m.guest_offset),
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

        // Only the valid mapping should survive L2 plausibility filtering
        assert_eq!(report.mappings_from_l2, 1);
        // First mapping (from L2) should be at guest offset 0
        assert!(report.mappings.iter().any(|m|
            m.guest_offset == 0 && matches!(m.source, MappingSource::L2Table)));
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
            let l2_self = (2 * cluster_size) | (1u64 << 63);
            BigEndian::write_u64(&mut entry, l2_self);
            f.write_all(&entry).unwrap();

            // L2[1] → L1 table (cluster 1 = metadata)
            let l1_target = cluster_size | (1u64 << 63);
            BigEndian::write_u64(&mut entry, l1_target);
            f.write_all(&entry).unwrap();
        }

        let cluster_map = crate::scan::scan_file(tmpfile.path(), cluster_size).unwrap();
        let report = reconstruct(tmpfile.path(), &cluster_map).unwrap();

        // Only L2[2] (pointing to actual data) should survive from L2
        assert_eq!(report.mappings_from_l2, 1);
        assert!(report.mappings.iter().any(|m|
            m.guest_offset == 2 * cluster_size && matches!(m.source, MappingSource::L2Table)));
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
