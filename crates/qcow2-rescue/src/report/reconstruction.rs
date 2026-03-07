//! Metadata reconstruction report structures (Phase 2).

use serde::{Deserialize, Serialize};

use super::mapping::MappingEntry;

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
    /// Refcount cross-check results (None if refcount table unreadable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refcount_check: Option<RefcountCheckReport>,
    /// Content validation results (decompression/decryption probes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_validation: Option<ContentValidationReport>,
    /// Number of guest offsets where multiple L2 tables disagree.
    pub mapping_conflicts: u64,
    /// All mappings.
    pub mappings: Vec<MappingEntry>,
    /// Virtual size from header (if readable).
    pub virtual_size: Option<u64>,
}

/// Refcount cross-check results.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefcountCheckReport {
    /// Refcount order used (from header).
    pub refcount_order: u32,
    /// Total clusters checked.
    pub clusters_checked: u64,
    /// Clusters with correct refcount (== 1).
    pub correct: u64,
    /// Clusters with refcount == 0 (leaked — referenced by L2 but refcount says free).
    pub leaked: u64,
    /// Clusters with refcount > 1 (shared — possible snapshot or corruption).
    pub shared: u64,
    /// Clusters whose refcount block was unreadable.
    pub unreadable: u64,
    /// Per-mismatch details (capped to avoid giant reports).
    pub mismatches: Vec<RefcountMismatch>,
}

/// A single refcount mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefcountMismatch {
    /// Host cluster offset.
    pub host_offset: u64,
    /// Guest offset that references this cluster.
    pub guest_offset: u64,
    /// Expected refcount (1 for normal mapping).
    pub expected: u64,
    /// Actual refcount found on disk.
    pub actual: u64,
}

/// Content validation results from decompression/decryption probes.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentValidationReport {
    /// Compressed clusters probed.
    pub compressed_probed: u64,
    /// Compressed clusters that decompressed successfully.
    pub compressed_ok: u64,
    /// Compressed clusters that failed to decompress.
    pub compressed_failed: u64,
    /// Encrypted clusters probed.
    pub encrypted_probed: u64,
    /// Encrypted clusters that decrypted successfully.
    pub encrypted_ok: u64,
    /// Encrypted clusters that failed to decrypt.
    pub encrypted_failed: u64,
}
