//! Snapshot API on `Qcow2ImageAsync`.

use crate::engine::snapshot_manager::{SnapshotInfo, SnapshotManager};
use crate::error::{Error, Result};

use super::{poisoned_err, Qcow2ImageAsync};

impl Qcow2ImageAsync {
    /// List all snapshots in the image.
    pub fn snapshot_list(&self) -> Result<Vec<SnapshotInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;

        if meta.header.snapshot_count == 0 {
            return Ok(Vec::new());
        }

        let cluster_size = 1u64 << meta.header.cluster_bits;
        let max_bytes = ((meta.header.snapshot_count as u64) * 1024).min(16 * cluster_size);
        let file_size = self.backend.file_size()?;
        let available = file_size.saturating_sub(meta.header.snapshots_offset.0);
        let read_size = (max_bytes as usize).min(available as usize);

        let mut buf = vec![0u8; read_size];
        self.backend.read_exact_at(&mut buf, meta.header.snapshots_offset.0)?;

        let snapshots = crate::format::snapshot::SnapshotHeader::read_table(
            &buf,
            meta.header.snapshot_count,
            meta.header.snapshots_offset.0,
        )?;

        Ok(snapshots
            .into_iter()
            .map(|s| SnapshotInfo {
                id: s.unique_id,
                name: s.name,
                virtual_size: s.virtual_disk_size,
                timestamp_seconds: s.timestamp_seconds,
                l1_table_entries: s.l1_table_entries,
            })
            .collect())
    }

    /// Create a named snapshot of the current image state.
    pub fn snapshot_create(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        // Flush dirty metadata so snapshot sees current on-disk state
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        mgr.create_snapshot(name, timestamp)
    }

    /// Delete a snapshot by name or ID.
    pub fn snapshot_delete(&self, name_or_id: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        mgr.delete_snapshot(name_or_id)
    }

    /// Revert to a snapshot's state.
    pub fn snapshot_apply(&self, name_or_id: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;

        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            meta_ref.header.cluster_bits,
        )?;

        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;
        let cluster_bits = meta_ref.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.mapper,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
        );
        mgr.apply_snapshot(name_or_id)?;

        meta_ref.has_hashes = crate::engine::hash_manager::detect_hashes(&meta_ref.extensions);
        Ok(())
    }
}
