//! Backing file tree report structures (Phase 3).

use serde::{Deserialize, Serialize};

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
