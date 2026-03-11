//! Integrity check and repair API on `Qcow2ImageAsync`.

use crate::error::{Error, Result};

use super::{poisoned_err, Qcow2ImageAsync};

impl Qcow2ImageAsync {
    /// Check image integrity by verifying all refcounts.
    pub fn check_integrity(&self) -> Result<crate::engine::integrity::IntegrityReport> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if meta.writable {
            let cluster_bits = meta.header.cluster_bits;
            qcow2_core::engine::metadata_io::flush_dirty_metadata(
                self.backend.as_ref(),
                &mut meta.cache,
                cluster_bits,
            )?;
        }
        crate::engine::integrity::check_integrity(self.backend.as_ref(), &meta.header)
    }

    /// Check integrity and optionally repair mismatches.
    pub fn check_and_repair(
        &self,
        mode: Option<crate::engine::integrity::RepairMode>,
    ) -> Result<crate::engine::integrity::IntegrityReport> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let cluster_bits = meta_ref.header.cluster_bits;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            cluster_bits,
        )?;

        let report = crate::engine::integrity::check_integrity(
            self.backend.as_ref(),
            &meta_ref.header,
        )?;

        if let Some(repair_mode) = mode {
            if !report.is_clean() {
                let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;
                crate::engine::integrity::repair_refcounts(
                    self.backend.as_ref(),
                    &meta_ref.header,
                    refcount_manager,
                    &mut meta_ref.cache,
                    repair_mode,
                )?;
                self.backend.flush()?;
            }
        }

        Ok(report)
    }
}
