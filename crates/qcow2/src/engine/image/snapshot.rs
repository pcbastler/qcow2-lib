//! Snapshot API delegation on `Qcow2Image`.

use crate::engine::hash_manager;
use crate::engine::snapshot_manager::{SnapshotInfo, SnapshotManager};
use crate::error::{Error, Result};

use super::Qcow2Image;

impl Qcow2Image {
    /// List all snapshots in the image.
    pub fn snapshot_list(&self) -> Result<Vec<SnapshotInfo>> {
        if self.header.snapshot_count == 0 {
            return Ok(Vec::new());
        }

        let cluster_size = 1u64 << self.header.cluster_bits;
        let max_bytes =
            ((self.header.snapshot_count as u64) * 1024).min(16 * cluster_size);
        let file_size = self.backend.file_size()?;
        let available = file_size.saturating_sub(self.header.snapshots_offset.0);
        let read_size = (max_bytes as usize).min(available as usize);

        let mut buf = vec![0u8; read_size];
        self.backend
            .read_exact_at(&mut buf, self.header.snapshots_offset.0)?;

        let snapshots = crate::format::snapshot::SnapshotHeader::read_table(
            &buf,
            self.header.snapshot_count,
            self.header.snapshots_offset.0,
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
    ///
    /// Copies the active L1 table, increments refcounts for all referenced
    /// clusters, clears COPIED flags, and writes the snapshot table.
    pub fn snapshot_create(&mut self, name: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        // Flush dirty metadata so snapshot sees current on-disk state
        self.flush_dirty_metadata()?;

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            &mut self.extensions,
            cluster_bits,
        );
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        mgr.create_snapshot(name, timestamp)
    }

    /// Delete a snapshot by name or ID.
    pub fn snapshot_delete(&mut self, name_or_id: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        // Flush dirty metadata so snapshot sees current on-disk state
        self.flush_dirty_metadata()?;

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            &mut self.extensions,
            cluster_bits,
        );
        mgr.delete_snapshot(name_or_id)
    }

    /// Revert to a snapshot's state.
    ///
    /// Decrements refcounts for the current active state, loads the snapshot's
    /// L1 table as the new active table, and increments refcounts accordingly.
    pub fn snapshot_apply(&mut self, name_or_id: &str) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        // Flush dirty metadata so snapshot sees current on-disk state
        self.flush_dirty_metadata()?;

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let cluster_bits = self.header.cluster_bits;
        let mut mgr = SnapshotManager::new(
            self.backend.as_ref(),
            &mut self.cache,
            refcount_manager,
            &mut self.mapper,
            &mut self.header,
            &mut self.extensions,
            cluster_bits,
        );
        mgr.apply_snapshot(name_or_id)?;

        // Re-detect hash state after apply (snapshot may have/not have hashes)
        self.has_hashes = hash_manager::detect_hashes(&self.extensions);

        // apply_snapshot calls cache.clear() which drops dirty entries created
        // during refcount adjustments — no further flush needed since clear()
        // already happened. But we DO need to flush after create/delete.
        Ok(())
    }
}
