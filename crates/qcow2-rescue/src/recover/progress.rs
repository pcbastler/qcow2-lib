//! Resume/progress tracking for recovery operations.

use std::path::{Path, PathBuf};

use serde::{Serialize, Deserialize};

use crate::error::Result;

/// Progress tracker for resumable recovery.
///
/// Stores the set of guest offsets that have been successfully written.
/// Saved as JSON to `<output>.progress.json` and updated periodically.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct RecoveryProgress {
    /// Guest offsets that have been written successfully.
    pub(crate) written_offsets: Vec<u64>,
    /// Total clusters to process.
    pub(crate) total_clusters: u64,
}

impl RecoveryProgress {
    /// Load progress from a file, or return empty if not found.
    pub(crate) fn load(path: &Path) -> Self {
        let progress_path = Self::progress_path(path);
        match std::fs::read_to_string(&progress_path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save progress to file.
    pub(crate) fn save(&self, output: &Path) -> Result<()> {
        let progress_path = Self::progress_path(output);
        let json = serde_json::to_string(self)?;
        std::fs::write(&progress_path, json)?;
        Ok(())
    }

    /// Remove the progress file (called on successful completion).
    pub(crate) fn remove(output: &Path) {
        let progress_path = Self::progress_path(output);
        let _ = std::fs::remove_file(progress_path);
    }

    /// Build a HashSet for fast lookup.
    pub(crate) fn as_set(&self) -> std::collections::HashSet<u64> {
        self.written_offsets.iter().copied().collect()
    }

    pub(crate) fn progress_path(output: &Path) -> PathBuf {
        let mut p = output.as_os_str().to_owned();
        p.push(".progress.json");
        PathBuf::from(p)
    }
}
