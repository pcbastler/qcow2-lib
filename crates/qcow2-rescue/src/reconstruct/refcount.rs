//! Refcount cross-checking for reconstructed mappings.

use std::io::{Read, Seek, SeekFrom};

use qcow2_format::constants::*;
use qcow2_format::refcount::{read_refcount_table, RefcountBlock};

use crate::report::*;

/// Cross-check refcounts for all mapped host clusters.
///
/// Reads the refcount table and blocks from the image (via header), then
/// looks up the refcount for each host offset in the reconstructed mappings.
/// Normal allocated clusters should have refcount == 1.
///
/// Returns `None` if the header or refcount table is unreadable.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub(super) fn cross_check_refcounts(
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
