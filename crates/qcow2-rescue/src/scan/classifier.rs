//! Cluster content classification heuristics.
//!
//! Each function examines the raw bytes of a cluster and determines
//! what kind of QCOW2 structure it most likely contains.

use byteorder::{BigEndian, ByteOrder};

use qcow2_format::constants::*;
use qcow2_format::l2::SubclusterBitmap;

use crate::report::ClusterTypeReport;

/// Classify a single cluster by examining its content.
///
/// The classifier tries each type in order of specificity:
/// header → L2 table → L1 table → refcount block → compressed → data → empty.
pub fn classify_cluster(buf: &[u8], cluster_size: u64, _offset: u64) -> ClusterTypeReport {
    // Empty check first (very common, fast path)
    if is_all_zeros(buf) {
        return ClusterTypeReport::Empty;
    }

    // Header: QCOW2 magic at offset 0
    if let Some(report) = try_classify_header(buf) {
        return report;
    }

    // Compressed data: deflate or zstd magic at start (very specific signature)
    if let Some(report) = try_classify_compressed(buf) {
        return report;
    }

    // Refcount block: array of small uniform u16 values (check before L2 —
    // refcount entries with value 1 look like valid L2 zero-flag entries)
    if let Some(report) = try_classify_refcount(buf) {
        return report;
    }

    // L2 table: try extended (16-byte) first (more specific), then standard (8-byte)
    if let Some(report) = try_classify_l2_extended(buf, cluster_size) {
        return report;
    }
    if let Some(report) = try_classify_l2(buf, cluster_size) {
        return report;
    }

    // L1 table: array of 8-byte entries pointing to plausible L2 offsets
    if let Some(report) = try_classify_l1(buf, cluster_size) {
        return report;
    }

    // Non-zero data that didn't match anything else
    ClusterTypeReport::Data
}

/// Check if all bytes in the buffer are zero.
fn is_all_zeros(buf: &[u8]) -> bool {
    // Check 8 bytes at a time for speed
    let (prefix, chunks, suffix) = unsafe { buf.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && chunks.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
}

/// Try to classify as a QCOW2 header.
fn try_classify_header(buf: &[u8]) -> Option<ClusterTypeReport> {
    if buf.len() < HEADER_V2_LENGTH {
        return None;
    }

    let magic = BigEndian::read_u32(&buf[0..4]);
    if magic != QCOW2_MAGIC {
        return None;
    }

    let version = BigEndian::read_u32(&buf[4..8]);
    if version != VERSION_2 && version != VERSION_3 {
        return None;
    }

    let cluster_bits = BigEndian::read_u32(&buf[20..24]);
    let virtual_size = BigEndian::read_u64(&buf[24..32]);

    Some(ClusterTypeReport::Header {
        version,
        cluster_bits,
        virtual_size,
    })
}

/// Try to classify as an L2 table.
///
/// An L2 table is an array of 8-byte entries where most entries are either:
/// - All zeros (unallocated)
/// - A cluster-aligned offset with valid flags
/// - A compressed descriptor (bit 62 set)
/// - A zero flag (bit 0 set, bits 1-8 zero)
fn try_classify_l2(buf: &[u8], cluster_size: u64) -> Option<ClusterTypeReport> {
    let entry_count = buf.len() / L2_ENTRY_SIZE;
    if entry_count < 8 {
        return None;
    }

    let mut valid = 0u32;
    let total = entry_count as u32;
    let mut nonzero = 0u32;

    for i in 0..entry_count {
        let raw = BigEndian::read_u64(&buf[i * 8..(i + 1) * 8]);
        if raw == 0 {
            valid += 1; // Unallocated
            continue;
        }
        nonzero += 1;

        if is_valid_l2_entry(raw, cluster_size) {
            valid += 1;
        }
    }

    // At least 90% valid and a meaningful fraction of nonzero entries.
    // Require at least 1% nonzero to distinguish from mostly-empty buffers
    // that happen to have a few stray bytes (e.g. refcount blocks, compressed data).
    let min_nonzero = (total / 100).max(4);
    if nonzero >= min_nonzero && valid * 100 / total >= 90 {
        Some(ClusterTypeReport::L2Table {
            valid_entries: valid,
            total_entries: total,
            extended: false,
        })
    } else {
        None
    }
}

/// Check if a single 64-bit value looks like a valid L2 entry.
fn is_valid_l2_entry(raw: u64, cluster_size: u64) -> bool {
    // Compressed: bit 62 set
    if raw & L2_COMPRESSED_FLAG != 0 {
        return true;
    }

    // Zero flag: bit 0 set, standard offset mask zero or cluster-aligned
    if raw & L2_ZERO_FLAG != 0 {
        let offset = raw & L2_STANDARD_OFFSET_MASK;
        return offset == 0 || offset % cluster_size == 0;
    }

    // Standard: offset must be cluster-aligned and non-zero
    let offset = raw & L2_STANDARD_OFFSET_MASK;
    if offset == 0 {
        return false;
    }
    offset % cluster_size == 0
}

/// Try to classify as an extended L2 table (16-byte entries).
///
/// Each entry is a pair: 8-byte L2 descriptor + 8-byte SubclusterBitmap.
/// The bitmap must satisfy alloc_bits & zero_bits == 0.
fn try_classify_l2_extended(buf: &[u8], cluster_size: u64) -> Option<ClusterTypeReport> {
    let entry_count = buf.len() / L2_ENTRY_SIZE_EXTENDED;
    if entry_count < 8 {
        return None;
    }

    let mut valid = 0u32;
    let total = entry_count as u32;
    let mut nonzero = 0u32;

    for i in 0..entry_count {
        let base = i * L2_ENTRY_SIZE_EXTENDED;
        let raw = BigEndian::read_u64(&buf[base..base + 8]);
        let bitmap_raw = BigEndian::read_u64(&buf[base + 8..base + 16]);

        if raw == 0 && bitmap_raw == 0 {
            valid += 1; // Unallocated
            continue;
        }
        nonzero += 1;

        // Both the L2 entry and the bitmap must be valid
        if is_valid_l2_entry(raw, cluster_size) && SubclusterBitmap(bitmap_raw).validate() {
            valid += 1;
        }
    }

    let min_nonzero = (total / 100).max(4);
    if nonzero >= min_nonzero && valid * 100 / total >= 90 {
        Some(ClusterTypeReport::L2Table {
            valid_entries: valid,
            total_entries: total,
            extended: true,
        })
    } else {
        None
    }
}

/// Quick heuristic check for cluster-size scoring: does this buffer look like an L2 table?
pub fn looks_like_l2_table(buf: &[u8], cluster_size: u64) -> bool {
    try_classify_l2(buf, cluster_size).is_some()
        || try_classify_l2_extended(buf, cluster_size).is_some()
}

/// Try to classify as an L1 table.
///
/// An L1 table is an array of 8-byte entries where each non-zero entry
/// is a cluster-aligned offset (masked with L1_OFFSET_MASK) within
/// a plausible file size range.
fn try_classify_l1(buf: &[u8], cluster_size: u64) -> Option<ClusterTypeReport> {
    let entry_count = buf.len() / L1_ENTRY_SIZE;
    if entry_count < 1 {
        return None;
    }

    let mut valid = 0u32;
    let mut nonzero = 0u32;

    for i in 0..entry_count {
        let raw = BigEndian::read_u64(&buf[i * 8..(i + 1) * 8]);
        if raw == 0 {
            valid += 1;
            continue;
        }
        nonzero += 1;

        let offset = raw & L1_OFFSET_MASK;
        if offset > 0 && offset % cluster_size == 0 {
            valid += 1;
        }
    }

    // Need at least some non-zero entries and high validity
    // L1 tables are usually smaller and have fewer entries than L2 tables
    if nonzero >= 1 && valid * 100 / entry_count as u32 >= 90 {
        Some(ClusterTypeReport::L1Table {
            entry_count: entry_count as u32,
            valid_entries: valid,
        })
    } else {
        None
    }
}

/// Try to classify as a refcount block.
///
/// A refcount block (assuming 16-bit refcounts, the most common) is an array
/// of u16 values where most are small (0–10) and the distribution is narrow.
fn try_classify_refcount(buf: &[u8]) -> Option<ClusterTypeReport> {
    let entry_count = buf.len() / 2;
    if entry_count < 16 {
        return None;
    }

    let mut nonzero = 0u32;
    let mut small_count = 0u32; // values 0-10

    for i in 0..entry_count {
        let val = BigEndian::read_u16(&buf[i * 2..(i + 1) * 2]);
        if val > 0 {
            nonzero += 1;
        }
        if val <= 10 {
            small_count += 1;
        }
    }

    // Almost all values should be small, and there should be some nonzero entries.
    // The block should also NOT look like an L2 table (which we already checked).
    if nonzero >= 2 && small_count * 100 / entry_count as u32 >= 95 {
        Some(ClusterTypeReport::RefcountBlock {
            nonzero_entries: nonzero,
        })
    } else {
        None
    }
}

/// Try to classify as compressed data.
///
/// Checks for deflate (zlib) or zstd magic bytes at the start.
fn try_classify_compressed(buf: &[u8]) -> Option<ClusterTypeReport> {
    if buf.len() < 4 {
        return None;
    }

    // Zlib/deflate: CMF byte 0x78 followed by valid FLG byte
    // CMF = 0x78 means deflate with 32K window
    // FLG: (CMF * 256 + FLG) must be divisible by 31
    if buf[0] == 0x78 {
        let flg = buf[1];
        let check = (0x78u16 * 256 + flg as u16) % 31;
        if check == 0 {
            return Some(ClusterTypeReport::Compressed {
                algorithm: "deflate".to_string(),
            });
        }
    }

    // Zstd magic: 0x28B52FFD
    if buf[0] == 0x28 && buf[1] == 0xB5 && buf[2] == 0x2F && buf[3] == 0xFD {
        return Some(ClusterTypeReport::Compressed {
            algorithm: "zstd".to_string(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cluster() {
        let buf = vec![0u8; 65536];
        let result = classify_cluster(&buf, 65536, 0);
        assert!(matches!(result, ClusterTypeReport::Empty));
    }

    #[test]
    fn header_cluster() {
        let mut buf = vec![0u8; 65536];
        // QCOW2 magic
        buf[0] = 0x51; buf[1] = 0x46; buf[2] = 0x49; buf[3] = 0xfb;
        // Version 3
        BigEndian::write_u32(&mut buf[4..8], 3);
        // cluster_bits = 16
        BigEndian::write_u32(&mut buf[20..24], 16);
        // virtual_size = 1 GB
        BigEndian::write_u64(&mut buf[24..32], 1 << 30);

        let result = classify_cluster(&buf, 65536, 0);
        match result {
            ClusterTypeReport::Header { version: 3, cluster_bits: 16, virtual_size } => {
                assert_eq!(virtual_size, 1 << 30);
            }
            other => panic!("expected Header, got {other:?}"),
        }
    }

    #[test]
    fn l2_table_cluster() {
        let cluster_size = 65536u64;
        let mut buf = vec![0u8; cluster_size as usize];
        let entry_count = cluster_size as usize / 8;
        // Fill ~50% of entries with cluster-aligned offsets (realistic L2 table)
        for i in 0..entry_count / 2 {
            let offset = (i as u64 + 4) * cluster_size;
            let copied_bit = 1u64 << 63;
            BigEndian::write_u64(&mut buf[i * 8..], offset | copied_bit);
        }
        // Rest is zeros (unallocated)

        let result = classify_cluster(&buf, cluster_size, 0);
        assert!(matches!(result, ClusterTypeReport::L2Table { .. }));
    }

    #[test]
    fn refcount_block_cluster() {
        let mut buf = vec![0u8; 65536];
        let entry_count = 65536 / 2;
        // Fill ~60% of entries with typical refcount values (mostly 1, some 2)
        for i in 0..entry_count * 6 / 10 {
            BigEndian::write_u16(&mut buf[i * 2..], 1);
        }
        // A few entries with value 2
        BigEndian::write_u16(&mut buf[(entry_count * 6 / 10) * 2..], 2);
        BigEndian::write_u16(&mut buf[(entry_count * 6 / 10 + 1) * 2..], 2);

        let result = classify_cluster(&buf, 65536, 0);
        assert!(matches!(result, ClusterTypeReport::RefcountBlock { .. }));
    }

    #[test]
    fn data_cluster() {
        let mut buf = vec![0u8; 65536];
        // Random-looking data that doesn't match any pattern
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }

        let result = classify_cluster(&buf, 65536, 0);
        assert!(matches!(result, ClusterTypeReport::Data));
    }

    #[test]
    fn compressed_deflate_cluster() {
        let mut buf = vec![0u8; 65536];
        // zlib header: CMF=0x78, FLG=0x9C (default compression)
        buf[0] = 0x78;
        buf[1] = 0x9C;
        // Fill with pseudo-compressed data (realistic: most of the cluster is used)
        for i in 2..32768 {
            buf[i] = ((i * 7 + 3) % 256) as u8;
        }

        let result = classify_cluster(&buf, 65536, 0);
        match result {
            ClusterTypeReport::Compressed { ref algorithm } if algorithm == "deflate" => {}
            other => panic!("expected Compressed(deflate), got {other:?}"),
        }
    }

    #[test]
    fn compressed_zstd_cluster() {
        let mut buf = vec![0u8; 65536];
        // Zstd magic
        buf[0] = 0x28; buf[1] = 0xB5; buf[2] = 0x2F; buf[3] = 0xFD;
        // Fill with pseudo-compressed data
        for i in 4..32768 {
            buf[i] = ((i * 11 + 5) % 256) as u8;
        }

        let result = classify_cluster(&buf, 65536, 0);
        match result {
            ClusterTypeReport::Compressed { ref algorithm } if algorithm == "zstd" => {}
            other => panic!("expected Compressed(zstd), got {other:?}"),
        }
    }

    #[test]
    fn l2_extended_table_cluster() {
        let cluster_size = 65536u64;
        let mut buf = vec![0u8; cluster_size as usize];
        let entry_count = cluster_size as usize / 16; // 16-byte extended entries
        // Fill ~50% of entries with valid extended L2 entries
        for i in 0..entry_count / 2 {
            let offset = (i as u64 + 4) * cluster_size;
            let copied_bit = 1u64 << 63;
            let base = i * 16;
            // Word 1: standard L2 entry with cluster-aligned offset
            BigEndian::write_u64(&mut buf[base..], offset | copied_bit);
            // Word 2: SubclusterBitmap — all allocated (bits 0-31 set, bits 32-63 zero)
            BigEndian::write_u64(&mut buf[base + 8..], 0x0000_0000_FFFF_FFFF);
        }

        let result = classify_cluster(&buf, cluster_size, 0);
        match result {
            ClusterTypeReport::L2Table { extended: true, .. } => {}
            other => panic!("expected extended L2Table, got {other:?}"),
        }
    }

    #[test]
    fn l2_extended_with_zero_subclusters() {
        let cluster_size = 65536u64;
        let mut buf = vec![0u8; cluster_size as usize];
        let entry_count = cluster_size as usize / 16;
        // Fill entries with zero-flag entries + all-zero bitmap
        for i in 0..entry_count / 2 {
            let base = i * 16;
            // Word 1: zero flag set (bit 0), no host offset
            BigEndian::write_u64(&mut buf[base..], L2_ZERO_FLAG as u64);
            // Word 2: SubclusterBitmap — all zero (bits 32-63 set)
            BigEndian::write_u64(&mut buf[base + 8..], 0xFFFF_FFFF_0000_0000);
        }

        let result = classify_cluster(&buf, cluster_size, 0);
        match result {
            ClusterTypeReport::L2Table { extended: true, .. } => {}
            other => panic!("expected extended L2Table, got {other:?}"),
        }
    }

    #[test]
    fn l2_extended_invalid_bitmap_rejected() {
        let cluster_size = 65536u64;
        let mut buf = vec![0u8; cluster_size as usize];
        let entry_count = cluster_size as usize / 16;
        // Fill entries with invalid bitmaps (alloc & zero both set)
        for i in 0..entry_count / 2 {
            let offset = (i as u64 + 4) * cluster_size;
            let base = i * 16;
            BigEndian::write_u64(&mut buf[base..], offset | (1u64 << 63));
            // Invalid: both alloc and zero bits set for same subclusters
            BigEndian::write_u64(&mut buf[base + 8..], 0xFFFF_FFFF_FFFF_FFFF);
        }

        let result = classify_cluster(&buf, cluster_size, 0);
        // Should NOT classify as extended L2 due to invalid bitmaps
        assert!(!matches!(
            result,
            ClusterTypeReport::L2Table { extended: true, .. }
        ));
    }

    #[test]
    fn is_valid_l2_entry_standard() {
        assert!(is_valid_l2_entry(0x0001_0000 | (1u64 << 63), 65536));
    }

    #[test]
    fn is_valid_l2_entry_compressed() {
        assert!(is_valid_l2_entry(1u64 << 62 | 0x1234, 65536));
    }

    #[test]
    fn is_valid_l2_entry_zero() {
        assert!(is_valid_l2_entry(L2_ZERO_FLAG, 65536));
    }

    #[test]
    fn is_valid_l2_entry_unaligned_rejected() {
        assert!(!is_valid_l2_entry(0x0000_0000_0001_0400, 65536)); // offset 0x10400, not cluster-aligned
    }
}
