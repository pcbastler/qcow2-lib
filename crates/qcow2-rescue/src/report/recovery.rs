//! Data recovery report structures (Phase 4).

use serde::{Deserialize, Serialize};

/// Phase 4 output: recovery result for a single layer or flattened chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Output file path.
    pub output_path: String,
    /// Output format used.
    pub output_format: String,
    /// Virtual size of the output image.
    pub virtual_size: u64,
    /// Cluster size used.
    pub cluster_size: u64,
    /// Source files involved (base → leaf order).
    pub source_files: Vec<String>,
    /// Total guest clusters written (non-zero).
    pub clusters_written: u64,
    /// Clusters skipped due to read errors.
    pub clusters_failed: u64,
    /// Clusters that were zero-filled (unallocated or read error with skip_corrupt).
    pub clusters_zeroed: u64,
    /// Bytes written to output.
    pub bytes_written: u64,
    /// Per-layer statistics.
    pub layer_stats: Vec<LayerRecoveryStat>,
    /// Encryption recovery info (if the source had encrypted clusters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_info: Option<EncryptionRecoveryInfo>,
}

/// Encryption recovery information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionRecoveryInfo {
    /// Whether a LUKS header was found.
    pub luks_header_found: bool,
    /// Offset of the LUKS header in the source image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub luks_header_offset: Option<u64>,
    /// Whether clusters were decrypted (password worked).
    pub decrypted: bool,
    /// Whether the decryption probe showed valid data structure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_ok: Option<bool>,
}

/// Per-layer recovery statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerRecoveryStat {
    /// Source file path.
    pub file_path: String,
    /// Mappings found in this layer.
    pub mappings_found: u64,
    /// Mappings contributed to final output (not overridden by higher layer).
    pub mappings_used: u64,
    /// Clusters that failed to read from this layer.
    pub read_failures: u64,
}
