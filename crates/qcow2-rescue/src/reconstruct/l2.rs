//! L2 table reading, parsing, and mapping extraction.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;
use qcow2_format::l2::L2Entry;
use qcow2_format::types::ClusterGeometry;

use crate::config::ConflictStrategy;
use crate::error::Result;
use crate::report::*;

/// Detect whether the image uses extended L2 entries by reading the header.
///
/// Returns `Some(true)` for extended, `Some(false)` for standard,
/// or `None` if the header is unreadable (caller should try both).
pub(super) fn detect_extended_l2(file: &mut std::fs::File, cluster_size: u64) -> Option<bool> {
    let mut header_buf = vec![0u8; 4096.min(cluster_size as usize)];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut header_buf).ok()?;
    let header = qcow2_format::Header::read_from(&header_buf).ok()?;
    Some(header.has_extended_l2())
}

/// Detect whether the image uses LUKS encryption from the header.
pub(super) fn detect_encryption(file: &mut std::fs::File, cluster_size: u64) -> bool {
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

/// Read and parse an L2 table from the file.
pub(super) fn read_l2_table(
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
///
/// Returns the number of conflicts encountered.
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
pub(super) fn add_l2_mappings(
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
    conflict_strategy: ConflictStrategy,
    mappings: &mut BTreeMap<u64, MappingEntry>,
) -> u64 {
    let mut conflicts = 0u64;

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

        let new_entry = match entry {
            L2Entry::Standard { host_offset, .. } => {
                let in_file = host_offset.0 > 0
                    && host_offset.is_cluster_aligned(cluster_bits)
                    && host_offset.0 < file_size;
                let target_ok = valid_data_offsets.is_empty()
                    || valid_data_offsets.contains(&host_offset.0);
                if in_file && target_ok {
                    Some(MappingEntry {
                        guest_offset,
                        host_offset: host_offset.0,
                        source,
                        compressed: false,
                        encrypted: is_encrypted,
                        subclusters,
                    })
                } else {
                    None
                }
            }
            L2Entry::Compressed(desc) => {
                let containing_cluster = desc.host_offset & !(cluster_size - 1);
                let target_ok = valid_data_offsets.is_empty()
                    || valid_data_offsets.contains(&containing_cluster);
                if desc.host_offset < file_size && target_ok {
                    Some(MappingEntry {
                        guest_offset,
                        host_offset: desc.host_offset,
                        source,
                        compressed: true,
                        encrypted: is_encrypted,
                        subclusters: None,
                    })
                } else {
                    None
                }
            }
            L2Entry::Zero { .. } | L2Entry::Unallocated => None,
        };

        if let Some(new) = new_entry {
            match mappings.entry(guest_offset) {
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(new);
                }
                std::collections::btree_map::Entry::Occupied(mut e) => {
                    let existing = e.get();
                    // Only a conflict if the host offsets differ
                    if existing.host_offset != new.host_offset {
                        conflicts += 1;
                        let replace = match conflict_strategy {
                            // Ask/Both: keep the first (L2Table source preferred)
                            ConflictStrategy::Ask | ConflictStrategy::Both => false,
                            // Newer: higher host_offset wins (written later on disk)
                            ConflictStrategy::Newer => new.host_offset > existing.host_offset,
                            // Safer: L2Table > Heuristic (more reliable source)
                            ConflictStrategy::Safer => matches!(
                                (&new.source, &existing.source),
                                (MappingSource::L2Table, MappingSource::Heuristic)
                            ),
                        };
                        if replace {
                            e.insert(new);
                        }
                    }
                }
            }
        }
    }

    conflicts
}
