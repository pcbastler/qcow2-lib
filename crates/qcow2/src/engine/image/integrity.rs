//! Integrity check and repair API on `Qcow2Image`.

use crate::error::{Error, Result};
use crate::format::bitmap::BitmapDirectoryEntry;
use crate::format::header_extension::HeaderExtension;
use crate::io::IoBackend;

use super::Qcow2Image;

impl Qcow2Image {
    /// Check image integrity by verifying all refcounts against the actual
    /// cluster references.
    ///
    /// This walks all L1/L2 tables (active **and** snapshots) to build an
    /// expected reference count map, then compares with stored refcounts.
    pub fn check_integrity(
        &mut self,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        // Flush dirty metadata so the check sees current on-disk state
        if self.meta.writable {
            self.flush_dirty_metadata()?;
        }
        crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &self.meta.header,
        )
    }

    /// Check integrity and optionally repair mismatches.
    ///
    /// Returns the integrity report from *before* repair. If `mode` is `Some`,
    /// any issues found are repaired in-place and the backend is flushed.
    pub fn check_and_repair(
        &mut self,
        mode: Option<crate::engine::integrity::RepairMode>,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        // Flush dirty metadata so the check sees current on-disk state
        self.flush_dirty_metadata()?;
        let report = crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &self.meta.header,
        )?;

        if let Some(repair_mode) = mode {
            if !report.is_clean() {
                let refcount_manager = self
                    .meta.refcount_manager
                    .as_mut()
                    .ok_or(Error::ReadOnly)?;
                crate::engine::integrity::repair_refcounts(
                    self.backend.as_ref(),
                    &self.meta.header,
                    refcount_manager,
                    &mut self.meta.cache,
                    repair_mode,
                )?;
                self.backend.flush()?;
            }
        }

        Ok(report)
    }

    /// Detect whether any bitmap has the AUTO flag set.
    pub(crate) fn detect_auto_bitmaps(
        backend: &dyn IoBackend,
        extensions: &[HeaderExtension],
    ) -> bool {
        let ext = match extensions.iter().find_map(|e| match e {
            HeaderExtension::Bitmaps(b) => Some(b),
            _ => None,
        }) {
            Some(ext) if ext.nb_bitmaps > 0 => ext,
            _ => return false,
        };

        // Guard against malicious bitmap_directory_size exceeding the file.
        let file_size = match backend.file_size() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if ext.bitmap_directory_size > file_size {
            return false;
        }

        let mut buf = vec![0u8; ext.bitmap_directory_size as usize];
        if backend
            .read_exact_at(&mut buf, ext.bitmap_directory_offset)
            .is_err()
        {
            return false;
        }

        match BitmapDirectoryEntry::read_directory(&buf, ext.nb_bitmaps) {
            Ok(entries) => entries.iter().any(|e| e.is_auto()),
            Err(_) => false,
        }
    }
}
