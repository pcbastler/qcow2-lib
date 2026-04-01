//! Configuration types for rescue operations.

use std::path::PathBuf;

/// How to resolve ambiguities (e.g. two L2 candidates for the same L1 index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ConflictStrategy {
    /// Pause and ask the user (default).
    #[default]
    Ask,
    /// Always pick the newer version (by timestamp heuristic).
    Newer,
    /// Always pick the version with fewer errors.
    Safer,
    /// Save both versions as separate outputs.
    Both,
}

/// Output format for the recovered image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Flat raw disk image.
    Raw,
    /// Single flat QCOW2 (no backing file).
    Qcow2,
    /// Reconstructed chain of QCOW2 files with backing references.
    Chain,
}

/// Configuration for a rescue operation.
#[derive(Debug)]
pub struct RescueConfig {
    /// Path to the input file or directory.
    pub input: PathBuf,
    /// Output directory for results.
    pub output: PathBuf,
    /// Output format (only for `recover`).
    pub format: Option<OutputFormat>,
    /// Which snapshot/path in the backing tree to recover.
    pub path: Option<String>,
    /// Password for encrypted images.
    pub password: Option<Vec<u8>>,
    /// Conflict resolution strategy.
    pub on_conflict: ConflictStrategy,
    /// Override cluster size (when header is corrupt).
    pub cluster_size_override: Option<u64>,
    /// Resume from a previous interrupted run.
    pub resume: bool,
}
