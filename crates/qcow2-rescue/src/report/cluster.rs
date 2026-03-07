//! Cluster classification report structures (Phase 1).

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
