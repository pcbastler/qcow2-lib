//! Orphan L2 handling and partition layout detection.

use std::io::{Read, Seek, SeekFrom};

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;

/// Info about L1 entries whose L2 table is corrupted/missing.
pub(super) struct MissingL2Info {
    /// L1 index of the missing L2 table.
    pub(super) l1_idx: u64,
    /// Host offset where the (corrupted) L2 was/is.
    pub(super) host_offset: u64,
}

/// Try to infer which L1 index an orphan L2 table belongs to.
///
/// Strategy:
/// Detect partition layout from the first orphan cluster's data.
///
/// If the first orphan (by host offset, i.e. the first allocated cluster)
/// contains an MBR or protective MBR (GPT), parse the partition table to
/// find where the first partition starts. Returns the L2 slot index of the
/// first partition, or None if no partition table is detected.
///
/// This is critical for L2 reconstruction: qemu-img allocates data clusters
/// in guest-offset order, so orphan[0] is the lowest-offset non-zero guest
/// cluster (typically MBR at slot 0). The gap between MBR and the first
/// partition (usually 1MB = 16 slots for 64K clusters) must be preserved.
pub(super) fn detect_partition_gap<R: Read + Seek>(
    file: &mut R,
    orphan_offsets: &[u64],
    cluster_size: u64,
) -> Option<u64> {
    if orphan_offsets.is_empty() {
        return None;
    }

    // Read the first orphan cluster (lowest host offset = first allocated data)
    let first_host = orphan_offsets[0];
    let mut buf = vec![0u8; cluster_size.min(512) as usize];
    file.seek(SeekFrom::Start(first_host)).ok()?;
    file.read_exact(&mut buf).ok()?;

    // Check MBR signature: 0x55AA at bytes 510-511
    if buf.len() < 512 || buf[510] != 0x55 || buf[511] != 0xAA {
        return None;
    }

    // Parse first partition entry (MBR offset 446, 16 bytes per entry)
    // Bytes 8-11 of the entry = start LBA (little-endian u32)
    let entry_offset = 446;
    let start_lba = u32::from_le_bytes([
        buf[entry_offset + 8],
        buf[entry_offset + 9],
        buf[entry_offset + 10],
        buf[entry_offset + 11],
    ]);

    if start_lba == 0 {
        return None;
    }

    let start_byte = start_lba as u64 * 512;
    let start_slot = start_byte / cluster_size;

    // Sanity: partition start should be within reasonable range
    if start_slot > 0 && start_slot < 2048 {
        eprintln!(
            "  partition table detected: first partition at LBA {} (slot {} for {}K clusters)",
            start_lba, start_slot, cluster_size / 1024,
        );
        Some(start_slot)
    } else {
        None
    }
}

/// 1. If we have a valid L1 table, scan it for a matching entry.
/// 2. Otherwise, use the position among all known L2 tables to infer index.
///    L2 tables are typically allocated in L1-index order, so sorting
///    by disk offset gives a good approximation.
pub(super) fn infer_l1_index_for_orphan_l2(
    l2_offset: u64,
    l1_data: &Option<Vec<u8>>,
    all_l2_offsets: &[u64],
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

    // Without L1 data: infer index from position among all L2 tables.
    // L2 tables are typically allocated sequentially, so the Nth L2 table
    // (sorted by disk offset) corresponds to L1 index N.
    let mut sorted = all_l2_offsets.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.iter().position(|&off| off == l2_offset).map(|i| i as u64)
}
