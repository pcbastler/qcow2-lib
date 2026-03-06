//! Serde-serializable report structures for all rescue phases.
//!
//! Every phase writes a JSON file with complete transparency about what
//! was found, what was damaged, and what decisions were made.

use serde::{Deserialize, Serialize};

/// Result of classifying a single cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInfo {
    /// Cluster index (0-based).
    pub index: u64,
    /// Byte offset in the image file.
    pub offset: u64,
    /// Classified type.
    pub cluster_type: ClusterTypeReport,
}

/// Cluster classification for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClusterTypeReport {
    /// Valid QCOW2 header.
    Header {
        version: u32,
        cluster_bits: u32,
        virtual_size: u64,
    },
    /// Looks like an L1 table.
    L1Table {
        entry_count: u32,
        valid_entries: u32,
    },
    /// Looks like an L2 table.
    L2Table {
        valid_entries: u32,
        total_entries: u32,
        extended: bool,
    },
    /// Looks like a refcount block.
    RefcountBlock { nonzero_entries: u32 },
    /// Compressed data cluster.
    Compressed { algorithm: String },
    /// Uncompressed data cluster (non-zero content).
    Data,
    /// All-zero cluster.
    Empty,
    /// Could not be classified.
    Unknown,
}

/// Phase 1 output: cluster map for a single file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterMapReport {
    /// Path to the scanned file.
    pub file_path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Cluster size used for scanning.
    pub cluster_size: u64,
    /// Whether cluster size was auto-detected or user-specified.
    pub cluster_size_source: String,
    /// Total number of clusters.
    pub total_clusters: u64,
    /// Summary counts by type.
    pub summary: ClusterSummary,
    /// Per-cluster classification.
    pub clusters: Vec<ClusterInfo>,
}

/// Summary counts from a cluster scan.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub headers: u64,
    pub l1_tables: u64,
    pub l2_tables: u64,
    pub refcount_blocks: u64,
    pub compressed: u64,
    pub data: u64,
    pub empty: u64,
    pub unknown: u64,
}

/// A reconstructed guest-to-host mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    /// Guest byte offset.
    pub guest_offset: u64,
    /// Host byte offset in the image file.
    pub host_offset: u64,
    /// How this mapping was determined.
    pub source: MappingSource,
    /// Whether the cluster is compressed.
    pub compressed: bool,
    /// Whether the cluster is encrypted.
    pub encrypted: bool,
    /// Subcluster allocation info (extended L2 only).
    /// None for standard (non-extended) L2 entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subclusters: Option<SubclusterInfo>,
}

/// Per-subcluster allocation state for a single cluster (extended L2 only).
///
/// A cluster is divided into 32 subclusters. Each subcluster can be:
/// - `A` = Allocated (has data at the host offset)
/// - `Z` = Zero (reads as zeros, no host data needed)
/// - `U` = Unallocated (falls through to backing file)
/// - `!` = Invalid (both alloc and zero set — corrupt bitmap)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubclusterInfo {
    /// Raw bitmap value (bits 0-31 = allocation, bits 32-63 = zero).
    pub raw_bitmap: u64,
    /// Subcluster size in bytes (cluster_size / 32).
    pub subcluster_size: u64,
    /// Number of allocated subclusters.
    pub allocated_count: u32,
    /// Number of zero subclusters.
    pub zero_count: u32,
    /// Number of unallocated subclusters (falls through to backing).
    pub unallocated_count: u32,
    /// Contiguous allocated byte ranges within this cluster,
    /// as `(offset_within_cluster, length)` pairs.
    pub allocated_ranges: Vec<(u64, u64)>,
    /// Per-subcluster state string: "AAAZZUUU..." (32 chars, one per subcluster).
    /// A=Allocated, Z=Zero, U=Unallocated, !=Invalid.
    pub state_map: String,
}

impl SubclusterInfo {
    /// Build from a raw bitmap and cluster size.
    pub fn from_bitmap(raw_bitmap: u64, cluster_size: u64) -> Self {
        let subcluster_size = cluster_size / 32;
        let alloc_mask = raw_bitmap as u32;
        let zero_mask = (raw_bitmap >> 32) as u32;

        let mut allocated_count = 0u32;
        let mut zero_count = 0u32;
        let mut unallocated_count = 0u32;
        let mut state_map = String::with_capacity(32);

        for i in 0..32u32 {
            let alloc = (alloc_mask >> i) & 1 != 0;
            let zero = (zero_mask >> i) & 1 != 0;
            match (alloc, zero) {
                (true, false) => {
                    allocated_count += 1;
                    state_map.push('A');
                }
                (false, true) => {
                    zero_count += 1;
                    state_map.push('Z');
                }
                (false, false) => {
                    unallocated_count += 1;
                    state_map.push('U');
                }
                (true, true) => {
                    // Invalid — both bits set
                    state_map.push('!');
                }
            }
        }

        // Build contiguous allocated ranges
        let mut allocated_ranges = Vec::new();
        let mut range_start: Option<u32> = None;
        for i in 0..32u32 {
            let is_alloc = (alloc_mask >> i) & 1 != 0 && (zero_mask >> i) & 1 == 0;
            match (range_start, is_alloc) {
                (None, true) => range_start = Some(i),
                (Some(start), false) => {
                    allocated_ranges.push((
                        start as u64 * subcluster_size,
                        (i - start) as u64 * subcluster_size,
                    ));
                    range_start = None;
                }
                _ => {}
            }
        }
        if let Some(start) = range_start {
            allocated_ranges.push((
                start as u64 * subcluster_size,
                (32 - start) as u64 * subcluster_size,
            ));
        }

        Self {
            raw_bitmap,
            subcluster_size,
            allocated_count,
            zero_count,
            unallocated_count,
            allocated_ranges,
            state_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcluster_info_all_allocated() {
        let info = SubclusterInfo::from_bitmap(0x0000_0000_FFFF_FFFF, 65536);
        assert_eq!(info.subcluster_size, 2048);
        assert_eq!(info.allocated_count, 32);
        assert_eq!(info.zero_count, 0);
        assert_eq!(info.unallocated_count, 0);
        assert_eq!(info.state_map, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(info.allocated_ranges, vec![(0, 65536)]);
    }

    #[test]
    fn subcluster_info_all_zero() {
        let info = SubclusterInfo::from_bitmap(0xFFFF_FFFF_0000_0000, 65536);
        assert_eq!(info.allocated_count, 0);
        assert_eq!(info.zero_count, 32);
        assert_eq!(info.unallocated_count, 0);
        assert_eq!(info.state_map, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(info.allocated_ranges.is_empty());
    }

    #[test]
    fn subcluster_info_partial() {
        // Subclusters 0-7 allocated, 8-15 zero, 16-31 unallocated
        let alloc: u32 = 0x0000_00FF; // bits 0-7
        let zero: u32 = 0x0000_FF00;  // bits 8-15
        let bitmap = (zero as u64) << 32 | alloc as u64;
        let info = SubclusterInfo::from_bitmap(bitmap, 65536);

        assert_eq!(info.allocated_count, 8);
        assert_eq!(info.zero_count, 8);
        assert_eq!(info.unallocated_count, 16);
        assert_eq!(info.state_map, "AAAAAAAAZZZZZZZZUUUUUUUUUUUUUUUU");
        assert_eq!(info.allocated_ranges, vec![(0, 8 * 2048)]);
    }

    #[test]
    fn subcluster_info_fragmented() {
        // Subclusters 0-3 allocated, 4-7 zero, 8-11 allocated, rest unallocated
        let alloc: u32 = 0x0000_0F0F; // bits 0-3, 8-11
        let zero: u32 = 0x0000_00F0;  // bits 4-7
        let bitmap = (zero as u64) << 32 | alloc as u64;
        let info = SubclusterInfo::from_bitmap(bitmap, 65536);

        assert_eq!(info.allocated_count, 8);
        assert_eq!(info.zero_count, 4);
        assert_eq!(info.unallocated_count, 20);
        assert_eq!(&info.state_map[..12], "AAAAZZZZAAAA");
        // Two separate allocated ranges
        assert_eq!(info.allocated_ranges.len(), 2);
        assert_eq!(info.allocated_ranges[0], (0, 4 * 2048));
        assert_eq!(info.allocated_ranges[1], (8 * 2048, 4 * 2048));
    }

    #[test]
    fn subcluster_info_invalid_bits() {
        // Subcluster 0: both alloc and zero set (invalid)
        let bitmap: u64 = 0x0000_0001_0000_0001;
        let info = SubclusterInfo::from_bitmap(bitmap, 65536);

        assert_eq!(info.state_map.chars().next(), Some('!'));
        assert_eq!(info.allocated_count, 0);
        assert_eq!(info.zero_count, 0);
        assert_eq!(info.unallocated_count, 31);
    }
}

/// How a guest-to-host mapping was determined.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MappingSource {
    /// From a verified L2 table entry.
    L2Table,
    /// From heuristic matching (orphan data cluster).
    Heuristic,
    /// Fallback from a backing file.
    BackingFallback,
}

/// Phase 2 output: reconstructed metadata for a single file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReconstructedTablesReport {
    /// Path to the file.
    pub file_path: String,
    /// Number of L1 entries found.
    pub l1_entries: u32,
    /// Number of L2 tables found and verified.
    pub l2_tables_verified: u32,
    /// Number of L2 tables found but suspicious.
    pub l2_tables_suspicious: u32,
    /// Total guest-to-host mappings reconstructed.
    pub mappings_total: u64,
    /// Mappings from verified L2 tables.
    pub mappings_from_l2: u64,
    /// Orphan data clusters (not referenced by any L2).
    pub orphan_data_clusters: u64,
    /// Refcount mismatches found.
    pub refcount_mismatches: u64,
    /// All mappings.
    pub mappings: Vec<MappingEntry>,
    /// Virtual size from header (if readable).
    pub virtual_size: Option<u64>,
}

/// A node in the backing file tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    /// File name (relative).
    pub file_name: String,
    /// Full path.
    pub path: String,
    /// Backing file reference from header (if readable).
    pub backing_file: Option<String>,
    /// Virtual size (if header readable).
    pub virtual_size: Option<u64>,
    /// Cluster size (if header readable).
    pub cluster_size: Option<u64>,
    /// Whether the header is intact.
    pub header_intact: bool,
    /// Number of allocated clusters.
    pub allocated_clusters: u64,
    /// Children (overlays that reference this file as backing).
    pub children: Vec<TreeNode>,
}

/// Phase 3 output: backing file tree.
#[derive(Debug, Serialize, Deserialize)]
pub struct TreeReport {
    /// Root nodes (base images with no backing file).
    pub roots: Vec<TreeNode>,
    /// All recoverable paths (leaf → root chains).
    pub paths: Vec<Vec<String>>,
}
