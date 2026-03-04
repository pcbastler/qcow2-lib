//! Snapshot lifecycle management: create, list, delete, and apply.
//!
//! The [`SnapshotManager`] is a transient helper that borrows components from
//! [`Qcow2Image`](super::image::Qcow2Image) for the duration of a snapshot
//! operation. This follows the same borrow-based pattern as
//! [`Qcow2Writer`](super::writer::Qcow2Writer).

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, Result};
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::constants::HASH_TABLE_ENTRY_SIZE;
use crate::format::hash::{Blake3Extension, HashTable};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::l2::{L2Entry, L2Table};
use crate::format::snapshot::SnapshotHeader;
use crate::format::types::ClusterOffset;
use crate::io::IoBackend;

/// Byte offset of the `snapshot_count` field in the QCOW2 header.
const OFF_SNAPSHOT_COUNT: u64 = 60;

/// Information about a snapshot, suitable for display.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Unique numeric ID.
    pub id: String,
    /// Human-readable snapshot name.
    pub name: String,
    /// Virtual disk size at snapshot time, if recorded.
    pub virtual_size: Option<u64>,
    /// Unix timestamp (seconds since epoch).
    pub timestamp_seconds: u32,
    /// Number of L1 table entries in this snapshot.
    pub l1_table_entries: u32,
}

/// Transient helper for snapshot operations.
///
/// Borrows the mutable state needed from `Qcow2Image` for the duration
/// of a single snapshot operation (create, delete, apply, or list).
#[allow(clippy::too_many_arguments)]
pub struct SnapshotManager<'a> {
    backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    mapper: &'a mut ClusterMapper,
    header: &'a mut Header,
    extensions: &'a mut Vec<HeaderExtension>,
    cluster_bits: u32,
}

impl<'a> SnapshotManager<'a> {
    /// Create a new snapshot manager borrowing the image's state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        mapper: &'a mut ClusterMapper,
        header: &'a mut Header,
        extensions: &'a mut Vec<HeaderExtension>,
        cluster_bits: u32,
    ) -> Self {
        Self {
            backend,
            cache,
            refcount_manager,
            mapper,
            header,
            extensions,
            cluster_bits,
        }
    }

    // ---- Snapshot table I/O ----

    /// Load and parse the snapshot table from disk.
    fn load_snapshot_table(&self) -> Result<Vec<SnapshotHeader>> {
        if self.header.snapshot_count == 0 {
            return Ok(Vec::new());
        }

        // Read enough bytes for the snapshot table. Each entry is at least
        // 40 bytes (fixed header) plus variable-length strings, padded to 8.
        // Generously over-read: the table is compact and always < a few clusters.
        let cluster_size = 1u64 << self.cluster_bits;
        let max_bytes = ((self.header.snapshot_count as u64) * 1024).min(16 * cluster_size);
        let file_size = self.backend.file_size()?;
        let available = file_size.saturating_sub(self.header.snapshots_offset.0);
        let read_size = (max_bytes as usize).min(available as usize);

        let mut buf = vec![0u8; read_size];
        self.backend
            .read_exact_at(&mut buf, self.header.snapshots_offset.0)?;

        SnapshotHeader::read_table(
            &buf,
            self.header.snapshot_count,
            self.header.snapshots_offset.0,
        )
    }

    /// Serialize and write the snapshot table to newly allocated clusters.
    /// Returns the offset where the table was written.
    fn write_snapshot_table(
        &mut self,
        snapshots: &[SnapshotHeader],
    ) -> Result<ClusterOffset> {
        // Serialize all snapshots into a byte vector
        let mut table_bytes = Vec::new();
        for snap in snapshots {
            snap.write_to(&mut table_bytes);
        }

        let cluster_size = 1usize << self.cluster_bits;
        let clusters_needed = (table_bytes.len() + cluster_size - 1) / cluster_size;

        // Allocate contiguous clusters (AppendAllocator guarantees contiguity)
        let first_offset = self
            .refcount_manager
            .allocate_cluster(self.backend, self.cache)?;
        for _ in 1..clusters_needed {
            self.refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
        }

        // Pad to full cluster boundary
        table_bytes.resize(clusters_needed * cluster_size, 0);
        self.backend.write_all_at(&table_bytes, first_offset.0)?;

        // Update file size in mapper
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        Ok(first_offset)
    }

    /// Write snapshot_count and snapshots_offset to the QCOW2 header on disk.
    fn update_header_snapshot_fields(
        &mut self,
        count: u32,
        offset: ClusterOffset,
    ) -> Result<()> {
        let mut buf = [0u8; 12];
        BigEndian::write_u32(&mut buf[0..4], count);
        BigEndian::write_u64(&mut buf[4..12], offset.0);
        self.backend.write_all_at(&buf, OFF_SNAPSHOT_COUNT)?;

        self.header.snapshot_count = count;
        self.header.snapshots_offset = offset;
        Ok(())
    }

    /// Find a snapshot by name (preferred) or by ID.
    fn find_snapshot(
        snapshots: &[SnapshotHeader],
        name_or_id: &str,
    ) -> Result<usize> {
        // Search by name first
        if let Some(pos) = snapshots.iter().position(|s| s.name == name_or_id) {
            return Ok(pos);
        }
        // Fall back to ID
        if let Some(pos) = snapshots.iter().position(|s| s.unique_id == name_or_id) {
            return Ok(pos);
        }
        Err(Error::SnapshotNotFound {
            identifier: name_or_id.to_string(),
        })
    }

    // ---- Public operations ----

    /// List all snapshots in the image.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let snapshots = self.load_snapshot_table()?;
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
    /// This copies the active L1 table, increments refcounts for all referenced
    /// clusters, clears COPIED flags on the active tables, and writes the
    /// snapshot table to disk.
    pub fn create_snapshot(&mut self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::SnapshotNameEmpty);
        }

        let existing = self.load_snapshot_table()?;
        if existing.iter().any(|s| s.name == name) {
            return Err(Error::SnapshotNameDuplicate {
                name: name.to_string(),
            });
        }

        let next_id = self.next_snapshot_id(&existing);
        let cluster_size = 1usize << self.cluster_bits;
        let l1_entry_count = self.header.l1_table_entries;
        let l1_entry_size = 8usize;
        let l1_byte_size = l1_entry_count as usize * l1_entry_size;

        // Phase A: Clear COPIED flags on active L1/L2 entries.
        self.clear_copied_flags_on_active(cluster_size)?;

        // Phase B: Copy the active L1 table to a new cluster.
        let snapshot_l1_offset = self.copy_active_l1_table(l1_byte_size, cluster_size)?;

        // Phase C: Increment refcounts for all referenced clusters.
        self.increment_refcounts_for_l1(cluster_size)?;

        // Phase D: Write snapshot table.
        let old_table_offset = if self.header.snapshot_count > 0 {
            Some(self.header.snapshots_offset)
        } else {
            None
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // Phase B2: Copy hash table reference (if hashes are active).
        let (snap_ht_offset, snap_ht_entries, snap_ht_size, snap_ht_chunk_bits, extra_data_size) =
            self.snapshot_hash_table(cluster_size)?;

        let new_snap = SnapshotHeader {
            l1_table_offset: snapshot_l1_offset,
            l1_table_entries: l1_entry_count,
            unique_id: next_id.to_string(),
            name: name.to_string(),
            timestamp_seconds: timestamp.as_secs() as u32,
            timestamp_nanoseconds: timestamp.subsec_nanos(),
            vm_clock_nanoseconds: 0,
            vm_state_size: 0,
            virtual_disk_size: Some(self.header.virtual_size),
            hash_table_offset: snap_ht_offset,
            hash_table_entries: snap_ht_entries,
            hash_size: snap_ht_size,
            hash_chunk_bits: snap_ht_chunk_bits,
            extra_data_size,
        };

        let mut all_snaps = existing;
        all_snaps.push(new_snap);

        let new_table_offset = self.write_snapshot_table(&all_snaps)?;

        // Phase E: Update header.
        self.update_header_snapshot_fields(
            all_snaps.len() as u32,
            new_table_offset,
        )?;

        // Free old snapshot table cluster(s) if any.
        if let Some(old_offset) = old_table_offset {
            self.free_snapshot_table_clusters(old_offset, &all_snaps[..all_snaps.len() - 1])?;
        }

        self.backend.flush()?;
        Ok(())
    }

    /// Delete a snapshot by name or ID.
    pub fn delete_snapshot(&mut self, name_or_id: &str) -> Result<()> {
        let mut snapshots = self.load_snapshot_table()?;
        let idx = Self::find_snapshot(&snapshots, name_or_id)?;
        let target = snapshots.remove(idx);
        let cluster_size = 1usize << self.cluster_bits;

        // Phase A: Decrement refcounts for the snapshot's L1/L2/data clusters.
        let snap_l1 = self.read_l1_table(
            target.l1_table_offset,
            target.l1_table_entries,
        )?;
        self.decrement_refcounts_for_l1(&snap_l1, cluster_size)?;

        // Phase A2: Free hash clusters from the snapshot.
        self.free_snapshot_hash_clusters(&target, cluster_size)?;

        // Phase B: Free the snapshot's L1 table cluster(s).
        let l1_byte_size = target.l1_table_entries as usize * 8;
        let l1_clusters = (l1_byte_size + cluster_size - 1) / cluster_size;
        for i in 0..l1_clusters {
            let offset = target.l1_table_offset.0 + (i as u64 * cluster_size as u64);
            self.refcount_manager
                .decrement_refcount(offset, self.backend, self.cache)?;
        }

        // Phase C: Restore COPIED flags on active L1/L2 entries where refcount is now 1.
        self.restore_copied_flags_on_active(cluster_size)?;

        // Phase D: Write new snapshot table.
        let old_table_offset = self.header.snapshots_offset;

        if snapshots.is_empty() {
            self.update_header_snapshot_fields(0, ClusterOffset(0))?;
        } else {
            let new_table_offset = self.write_snapshot_table(&snapshots)?;
            self.update_header_snapshot_fields(
                snapshots.len() as u32,
                new_table_offset,
            )?;
        }

        // Free old snapshot table cluster(s).
        let mut old_snaps_for_size = snapshots.clone();
        old_snaps_for_size.push(target);
        self.free_snapshot_table_clusters(old_table_offset, &old_snaps_for_size)?;

        self.backend.flush()?;
        Ok(())
    }

    /// Revert to a snapshot's state.
    ///
    /// Decrements refcounts for the current active state, loads the snapshot's
    /// L1 table as the new active table, and increments refcounts accordingly.
    pub fn apply_snapshot(&mut self, name_or_id: &str) -> Result<()> {
        let snapshots = self.load_snapshot_table()?;
        let idx = Self::find_snapshot(&snapshots, name_or_id)?;
        let target = &snapshots[idx];
        let cluster_size = 1usize << self.cluster_bits;

        if target.l1_table_entries != self.header.l1_table_entries {
            return Err(Error::WriteFailed {
                guest_offset: 0,
                message: format!(
                    "snapshot L1 size {} does not match active L1 size {}",
                    target.l1_table_entries, self.header.l1_table_entries,
                ),
            });
        }

        // Phase A: Decrement refcounts for the current active state.
        self.decrement_refcounts_for_active(cluster_size)?;

        // Phase B: Load snapshot's L1 table and write it to the active L1 location.
        let snap_l1 = self.read_l1_table(
            target.l1_table_offset,
            target.l1_table_entries,
        )?;
        let l1_byte_size = target.l1_table_entries as usize * 8;
        let mut l1_buf = vec![0u8; l1_byte_size];
        snap_l1.write_to(&mut l1_buf)?;
        self.backend
            .write_all_at(&l1_buf, self.header.l1_table_offset.0)?;

        // Phase C: Clear COPIED flags on the new active L1 entries.
        // They are shared with the snapshot copy, so COPIED must be false.
        for i in 0..snap_l1.entry_count() {
            let entry = snap_l1.get(crate::format::types::L1Index(i as u32))?;
            if let Some(offset) = entry.l2_table_offset() {
                let cleared = L1Entry::with_l2_offset(offset, false);
                self.mapper
                    .set_l1_entry(crate::format::types::L1Index(i as u32), cleared)?;
                // Write to disk
                let disk_offset =
                    self.header.l1_table_offset.0 + (i as u64 * 8);
                let mut entry_buf = [0u8; 8];
                BigEndian::write_u64(&mut entry_buf, cleared.raw());
                self.backend.write_all_at(&entry_buf, disk_offset)?;
            } else {
                self.mapper.set_l1_entry(
                    crate::format::types::L1Index(i as u32),
                    entry,
                )?;
            }
        }

        // Phase D: Increment refcounts for the snapshot's clusters.
        // The active table now shares them with the snapshot.
        self.increment_refcounts_for_l1(cluster_size)?;

        // Phase D2: Restore hash table from snapshot.
        self.apply_snapshot_hash_table(target, cluster_size)?;

        // Evict all cached L2 tables (active state changed entirely)
        self.cache.clear();

        self.backend.flush()?;
        Ok(())
    }

    // ---- Internal helpers ----

    /// Generate the next snapshot ID (max existing + 1).
    fn next_snapshot_id(&self, existing: &[SnapshotHeader]) -> u64 {
        existing
            .iter()
            .filter_map(|s| s.unique_id.parse::<u64>().ok())
            .max()
            .map(|m| m + 1)
            .unwrap_or(1)
    }

    /// Clear COPIED flags on all active L1 and L2 entries (in-place on disk).
    fn clear_copied_flags_on_active(&mut self, cluster_size: usize) -> Result<()> {
        let l1_count = self.mapper.l1_table().entry_count();

        for i in 0..l1_count {
            let l1_idx = crate::format::types::L1Index(i as u32);
            let l1_entry = self.mapper.l1_entry(l1_idx)?;

            if let Some(l2_offset) = l1_entry.l2_table_offset() {
                // Load L2 table and clear COPIED flags on its entries
                let mut l2_buf = vec![0u8; cluster_size];
                self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
                let l2_table = L2Table::read_from(&l2_buf, self.header.geometry())?;

                let mut modified = false;
                for j in 0..l2_table.len() {
                    let l2_entry = l2_table.get(crate::format::types::L2Index(j))?;
                    if let L2Entry::Standard {
                        host_offset,
                        copied: true,
                        subclusters,
                    } = l2_entry
                    {
                        let cleared = L2Entry::Standard {
                            host_offset,
                            copied: false,
                            subclusters,
                        };
                        let l2_entry_size = self.header.l2_entry_size();
                        let entry_offset = l2_offset.0 + (j as u64 * l2_entry_size as u64);
                        let mut entry_buf = [0u8; 8];
                        BigEndian::write_u64(
                            &mut entry_buf,
                            cleared.encode(self.header.geometry()),
                        );
                        self.backend.write_all_at(&entry_buf, entry_offset)?;
                        modified = true;
                    }
                }

                if modified {
                    self.cache.evict_l2_table(l2_offset);
                }

                // Clear COPIED on the L1 entry itself
                if l1_entry.is_copied() {
                    let cleared = L1Entry::with_l2_offset(l2_offset, false);
                    self.mapper.set_l1_entry(l1_idx, cleared)?;
                    let l1_disk_offset =
                        self.header.l1_table_offset.0 + (i as u64 * 8);
                    let mut entry_buf = [0u8; 8];
                    BigEndian::write_u64(&mut entry_buf, cleared.raw());
                    self.backend.write_all_at(&entry_buf, l1_disk_offset)?;
                }
            }
        }

        Ok(())
    }

    /// Restore COPIED flags on active L1/L2 entries where the refcount is 1.
    ///
    /// Called after deleting a snapshot to fix up entries whose refcounts
    /// dropped from >1 to exactly 1.
    fn restore_copied_flags_on_active(&mut self, cluster_size: usize) -> Result<()> {
        let l1_count = self.mapper.l1_table().entry_count();

        for i in 0..l1_count {
            let l1_idx = crate::format::types::L1Index(i as u32);
            let l1_entry = self.mapper.l1_entry(l1_idx)?;

            if let Some(l2_offset) = l1_entry.l2_table_offset() {
                // Check L2 table refcount
                let l2_rc = self.refcount_manager.get_refcount(
                    l2_offset.0,
                    self.backend,
                    self.cache,
                )?;

                // Load L2 table and restore COPIED flags on data entries
                let mut l2_buf = vec![0u8; cluster_size];
                self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
                let l2_table = L2Table::read_from(&l2_buf, self.header.geometry())?;

                let mut l2_modified = false;
                for j in 0..l2_table.len() {
                    let l2_entry = l2_table.get(crate::format::types::L2Index(j))?;
                    if let L2Entry::Standard {
                        host_offset,
                        copied: false,
                        subclusters,
                    } = l2_entry
                    {
                        let rc = self.refcount_manager.get_refcount(
                            host_offset.0,
                            self.backend,
                            self.cache,
                        )?;
                        if rc == 1 {
                            let restored = L2Entry::Standard {
                                host_offset,
                                copied: true,
                                subclusters,
                            };
                            let l2_entry_size = self.header.l2_entry_size();
                            let entry_offset = l2_offset.0 + (j as u64 * l2_entry_size as u64);
                            let mut entry_buf = [0u8; 8];
                            BigEndian::write_u64(
                                &mut entry_buf,
                                restored.encode(self.header.geometry()),
                            );
                            self.backend.write_all_at(&entry_buf, entry_offset)?;
                            l2_modified = true;
                        }
                    }
                }

                if l2_modified {
                    self.cache.evict_l2_table(l2_offset);
                }

                // Restore COPIED on L1 entry if L2 table refcount is 1
                if l2_rc == 1 && !l1_entry.is_copied() {
                    let restored = L1Entry::with_l2_offset(l2_offset, true);
                    self.mapper.set_l1_entry(l1_idx, restored)?;
                    let l1_disk_offset =
                        self.header.l1_table_offset.0 + (i as u64 * 8);
                    let mut entry_buf = [0u8; 8];
                    BigEndian::write_u64(&mut entry_buf, restored.raw());
                    self.backend.write_all_at(&entry_buf, l1_disk_offset)?;
                }
            }
        }

        Ok(())
    }

    /// Copy the active L1 table to newly allocated cluster(s).
    fn copy_active_l1_table(
        &mut self,
        l1_byte_size: usize,
        cluster_size: usize,
    ) -> Result<ClusterOffset> {
        let clusters_needed = (l1_byte_size + cluster_size - 1) / cluster_size;
        let total_size = clusters_needed * cluster_size;

        let first_offset = self
            .refcount_manager
            .allocate_cluster(self.backend, self.cache)?;
        for _ in 1..clusters_needed {
            self.refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
        }

        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Read active L1 table from disk (has COPIED flags already cleared)
        let mut l1_data = vec![0u8; total_size];
        self.backend.read_exact_at(
            &mut l1_data[..l1_byte_size],
            self.header.l1_table_offset.0,
        )?;

        // Write to new cluster(s)
        self.backend.write_all_at(&l1_data, first_offset.0)?;

        Ok(first_offset)
    }

    /// Increment refcounts for all clusters referenced by the active L1 table.
    fn increment_refcounts_for_l1(&mut self, cluster_size: usize) -> Result<()> {
        let l1_count = self.mapper.l1_table().entry_count();

        for i in 0..l1_count {
            let l1_idx = crate::format::types::L1Index(i as u32);
            let l1_entry = self.mapper.l1_entry(l1_idx)?;

            if let Some(l2_offset) = l1_entry.l2_table_offset() {
                // Increment refcount for the L2 table itself
                self.refcount_manager.increment_refcount(
                    l2_offset.0,
                    self.backend,
                    self.cache,
                )?;

                // Load L2 table and increment refcounts for data clusters
                let mut l2_buf = vec![0u8; cluster_size];
                self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
                let l2_table = L2Table::read_from(&l2_buf, self.header.geometry())?;

                for entry in l2_table.iter() {
                    self.increment_refcount_for_l2_entry(entry)?;
                }
            }
        }

        Ok(())
    }

    /// Increment the refcount for the cluster(s) referenced by an L2 entry.
    fn increment_refcount_for_l2_entry(&mut self, entry: L2Entry) -> Result<()> {
        match entry {
            L2Entry::Standard { host_offset, .. } => {
                self.refcount_manager.increment_refcount(
                    host_offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
            L2Entry::Zero {
                preallocated_offset: Some(offset), ..
            } => {
                self.refcount_manager.increment_refcount(
                    offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
            L2Entry::Compressed(descriptor) => {
                for cluster_offset in clusters_for_compressed(&descriptor, self.cluster_bits) {
                    self.refcount_manager.increment_refcount(
                        cluster_offset,
                        self.backend,
                        self.cache,
                    )?;
                }
            }
            L2Entry::Unallocated | L2Entry::Zero { preallocated_offset: None, .. } => {}
        }
        Ok(())
    }

    /// Decrement refcounts for all clusters referenced by the current active L1.
    fn decrement_refcounts_for_active(&mut self, cluster_size: usize) -> Result<()> {
        let l1_count = self.mapper.l1_table().entry_count();

        for i in 0..l1_count {
            let l1_idx = crate::format::types::L1Index(i as u32);
            let l1_entry = self.mapper.l1_entry(l1_idx)?;

            if let Some(l2_offset) = l1_entry.l2_table_offset() {
                // Load L2 and decrement data cluster refcounts
                let mut l2_buf = vec![0u8; cluster_size];
                self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
                let l2_table = L2Table::read_from(&l2_buf, self.header.geometry())?;

                for entry in l2_table.iter() {
                    self.decrement_refcount_for_l2_entry(entry)?;
                }

                // Decrement refcount for the L2 table itself
                self.refcount_manager.decrement_refcount(
                    l2_offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
        }

        Ok(())
    }

    /// Decrement refcounts for all clusters referenced by a given L1 table.
    fn decrement_refcounts_for_l1(
        &mut self,
        l1_table: &L1Table,
        cluster_size: usize,
    ) -> Result<()> {
        for entry in l1_table.iter() {
            if let Some(l2_offset) = entry.l2_table_offset() {
                // Load L2 and decrement data cluster refcounts
                let mut l2_buf = vec![0u8; cluster_size];
                self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
                let l2_table = L2Table::read_from(&l2_buf, self.header.geometry())?;

                for l2_entry in l2_table.iter() {
                    self.decrement_refcount_for_l2_entry(l2_entry)?;
                }

                // Decrement refcount for the L2 table
                self.refcount_manager.decrement_refcount(
                    l2_offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
        }
        Ok(())
    }

    /// Decrement the refcount for the cluster(s) referenced by an L2 entry.
    fn decrement_refcount_for_l2_entry(&mut self, entry: L2Entry) -> Result<()> {
        match entry {
            L2Entry::Standard { host_offset, .. } => {
                self.refcount_manager.decrement_refcount(
                    host_offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
            L2Entry::Zero {
                preallocated_offset: Some(offset), ..
            } => {
                self.refcount_manager.decrement_refcount(
                    offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
            L2Entry::Compressed(descriptor) => {
                for cluster_offset in clusters_for_compressed(&descriptor, self.cluster_bits) {
                    self.refcount_manager.decrement_refcount(
                        cluster_offset,
                        self.backend,
                        self.cache,
                    )?;
                }
            }
            L2Entry::Unallocated | L2Entry::Zero { preallocated_offset: None, .. } => {}
        }
        Ok(())
    }

    /// Read an L1 table from disk at the given offset.
    fn read_l1_table(
        &self,
        offset: ClusterOffset,
        entry_count: u32,
    ) -> Result<L1Table> {
        let byte_size = entry_count as usize * 8;
        let mut buf = vec![0u8; byte_size];
        self.backend.read_exact_at(&mut buf, offset.0)?;
        L1Table::read_from(&buf, entry_count)
    }

    // ---- Hash table snapshot helpers ----

    /// Find the active BLAKE3 hash extension.
    fn find_hash_extension(&self) -> Option<&Blake3Extension> {
        self.extensions.iter().find_map(|e| match e {
            HeaderExtension::Blake3Hashes(ext) => Some(ext),
            _ => None,
        })
    }

    /// Copy the active hash table for a snapshot.
    ///
    /// Copies the hash table to new clusters and increments refcounts for all
    /// hash data clusters. Returns (offset, entries, hash_size, extra_data_size).
    #[allow(clippy::type_complexity)]
    fn snapshot_hash_table(
        &mut self,
        cluster_size: usize,
    ) -> Result<(Option<u64>, Option<u32>, Option<u8>, Option<u8>, u32)> {
        let ext = match self.find_hash_extension() {
            Some(ext) => ext.clone(),
            None => return Ok((None, None, None, None, 16)),
        };

        if ext.hash_table_offset == 0 || ext.hash_table_entries == 0 {
            return Ok((None, None, None, None, 16));
        }

        // Read the hash table
        let table_byte_size = ext.hash_table_entries as usize * HASH_TABLE_ENTRY_SIZE;
        let table_clusters = (table_byte_size + cluster_size - 1) / cluster_size;

        // Allocate new clusters for the snapshot's hash table copy
        let snap_table_offset = self
            .refcount_manager
            .allocate_cluster(self.backend, self.cache)?;
        for _ in 1..table_clusters {
            self.refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
        }

        // Copy hash table data
        let total_size = table_clusters * cluster_size;
        let mut table_data = vec![0u8; total_size];
        self.backend
            .read_exact_at(&mut table_data[..table_byte_size], ext.hash_table_offset)?;
        self.backend
            .write_all_at(&table_data, snap_table_offset.0)?;

        // Update file size in mapper
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Increment refcounts for hash data clusters (shared between active and snapshot)
        let table = HashTable::read_from(&table_data[..table_byte_size], ext.hash_table_entries)?;
        for entry in table.iter() {
            if let Some(data_offset) = entry.data_offset() {
                self.refcount_manager
                    .increment_refcount(data_offset, self.backend, self.cache)?;
            }
        }

        Ok((
            Some(snap_table_offset.0),
            Some(ext.hash_table_entries),
            Some(ext.hash_size),
            Some(ext.hash_chunk_bits),
            32,
        ))
    }

    /// Free hash clusters referenced by a deleted snapshot.
    fn free_snapshot_hash_clusters(
        &mut self,
        snapshot: &SnapshotHeader,
        cluster_size: usize,
    ) -> Result<()> {
        let ht_offset = match snapshot.hash_table_offset {
            Some(off) if off != 0 => off,
            _ => return Ok(()),
        };
        let ht_entries = snapshot.hash_table_entries.unwrap_or(0);
        if ht_entries == 0 {
            return Ok(());
        }

        // Read the snapshot's hash table
        let table_byte_size = ht_entries as usize * HASH_TABLE_ENTRY_SIZE;
        let mut buf = vec![0u8; table_byte_size];
        self.backend.read_exact_at(&mut buf, ht_offset)?;
        let table = HashTable::read_from(&buf, ht_entries)?;

        // Decrement refcounts for hash data clusters
        for entry in table.iter() {
            if let Some(data_offset) = entry.data_offset() {
                self.refcount_manager
                    .decrement_refcount(data_offset, self.backend, self.cache)?;
            }
        }

        // Free the hash table cluster(s)
        let table_clusters = (table_byte_size + cluster_size - 1) / cluster_size;
        for i in 0..table_clusters {
            let offset = ht_offset + (i as u64 * cluster_size as u64);
            self.refcount_manager
                .decrement_refcount(offset, self.backend, self.cache)?;
        }

        Ok(())
    }

    /// Restore the active hash table from a snapshot.
    fn apply_snapshot_hash_table(
        &mut self,
        snapshot: &SnapshotHeader,
        cluster_size: usize,
    ) -> Result<()> {
        // First, decrement refcounts for current active hash data clusters
        if let Some(active_ext) = self.find_hash_extension().cloned() {
            if active_ext.hash_table_offset != 0 && active_ext.hash_table_entries > 0 {
                let table_byte_size =
                    active_ext.hash_table_entries as usize * HASH_TABLE_ENTRY_SIZE;
                let mut buf = vec![0u8; table_byte_size];
                self.backend
                    .read_exact_at(&mut buf, active_ext.hash_table_offset)?;
                let table = HashTable::read_from(&buf, active_ext.hash_table_entries)?;

                for entry in table.iter() {
                    if let Some(data_offset) = entry.data_offset() {
                        self.refcount_manager
                            .decrement_refcount(data_offset, self.backend, self.cache)?;
                    }
                }

                // Free old active hash table clusters
                let table_clusters = (table_byte_size + cluster_size - 1) / cluster_size;
                for i in 0..table_clusters {
                    let offset =
                        active_ext.hash_table_offset + (i as u64 * cluster_size as u64);
                    self.refcount_manager
                        .decrement_refcount(offset, self.backend, self.cache)?;
                }
            }
        }

        // Check if the snapshot has hash table info
        let snap_ht_offset = match snapshot.hash_table_offset {
            Some(off) if off != 0 => off,
            _ => {
                // Snapshot has no hashes — remove active hash extension if present
                self.extensions
                    .retain(|e| !matches!(e, HeaderExtension::Blake3Hashes(_)));
                return Ok(());
            }
        };
        let snap_ht_entries = snapshot.hash_table_entries.unwrap_or(0);
        let snap_hash_size = snapshot.hash_size.unwrap_or(32);
        let snap_chunk_bits = snapshot.hash_chunk_bits.unwrap_or(0);

        if snap_ht_entries == 0 {
            self.extensions
                .retain(|e| !matches!(e, HeaderExtension::Blake3Hashes(_)));
            return Ok(());
        }

        // Read the snapshot's hash table
        let table_byte_size = snap_ht_entries as usize * HASH_TABLE_ENTRY_SIZE;
        let table_clusters = (table_byte_size + cluster_size - 1) / cluster_size;

        // Allocate new clusters for the restored active hash table
        let new_table_offset = self
            .refcount_manager
            .allocate_cluster(self.backend, self.cache)?;
        for _ in 1..table_clusters {
            self.refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
        }

        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Copy snapshot hash table to new active location
        let total_size = table_clusters * cluster_size;
        let mut table_data = vec![0u8; total_size];
        self.backend
            .read_exact_at(&mut table_data[..table_byte_size], snap_ht_offset)?;
        self.backend
            .write_all_at(&table_data, new_table_offset.0)?;

        // Increment refcounts for hash data clusters (shared with snapshot)
        let table = HashTable::read_from(&table_data[..table_byte_size], snap_ht_entries)?;
        for entry in table.iter() {
            if let Some(data_offset) = entry.data_offset() {
                self.refcount_manager
                    .increment_refcount(data_offset, self.backend, self.cache)?;
            }
        }

        // Update or insert the active hash extension
        let new_ext = Blake3Extension {
            hash_table_offset: new_table_offset.0,
            hash_table_entries: snap_ht_entries,
            hash_size: snap_hash_size,
            hash_chunk_bits: snap_chunk_bits,
        };

        let mut found = false;
        for ext in self.extensions.iter_mut() {
            if let HeaderExtension::Blake3Hashes(ref mut e) = ext {
                *e = new_ext.clone();
                found = true;
                break;
            }
        }
        if !found {
            self.extensions
                .push(HeaderExtension::Blake3Hashes(new_ext));
        }

        // Write updated extensions to disk
        let ext_data = HeaderExtension::write_all(self.extensions);
        let ext_start = self.header.header_length as u64;
        self.backend.write_all_at(&ext_data, ext_start)?;

        Ok(())
    }

    /// Free the cluster(s) that held the old snapshot table.
    fn free_snapshot_table_clusters(
        &mut self,
        offset: ClusterOffset,
        snapshots: &[SnapshotHeader],
    ) -> Result<()> {
        // Compute the serialized size to know how many clusters to free
        let mut table_bytes = Vec::new();
        for snap in snapshots {
            snap.write_to(&mut table_bytes);
        }
        let cluster_size = 1usize << self.cluster_bits;
        let clusters = (table_bytes.len() + cluster_size - 1) / cluster_size;

        for i in 0..clusters {
            let cluster_offset = offset.0 + (i as u64 * cluster_size as u64);
            self.refcount_manager.decrement_refcount(
                cluster_offset,
                self.backend,
                self.cache,
            )?;
        }
        Ok(())
    }
}

/// Compute the host cluster offset(s) that contain a compressed cluster's data.
fn clusters_for_compressed(descriptor: &CompressedClusterDescriptor, cluster_bits: u32) -> Vec<u64> {
    let cluster_mask = !((1u64 << cluster_bits) - 1);
    let start_cluster = descriptor.host_offset & cluster_mask;
    let end = descriptor.host_offset + descriptor.compressed_size;
    if end == 0 {
        return vec![start_cluster];
    }
    let end_cluster = (end - 1) & cluster_mask;
    if end_cluster == start_cluster {
        vec![start_cluster]
    } else {
        vec![start_cluster, end_cluster]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::image::{CreateOptions, Qcow2Image};
    use crate::io::MemoryBackend;

    /// Create a minimal writable image on a MemoryBackend for snapshot tests.
    fn create_test_image(virtual_size: u64) -> Qcow2Image {
        Qcow2Image::create_on_backend(
            Box::new(MemoryBackend::zeroed(0)),
            CreateOptions {
                virtual_size,
                cluster_bits: None,
            extended_l2: false,
            },
        )
        .unwrap()
    }

    // ---- Table I/O tests ----

    #[test]
    fn load_empty_snapshot_table() {
        let image = create_test_image(1 << 20);
        let snapshots = image.snapshot_list().unwrap();
        assert!(snapshots.is_empty());
    }

    #[test]
    fn snapshot_table_write_and_load_round_trip() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("snap-1").unwrap();

        let snapshots = image.snapshot_list().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "snap-1");
        assert_eq!(snapshots[0].id, "1");
    }

    #[test]
    fn find_snapshot_by_name() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("alpha").unwrap();
        image.snapshot_create("beta").unwrap();

        // Delete by name — exercises the find_snapshot() path
        image.snapshot_delete("alpha").unwrap();

        let snapshots = image.snapshot_list().unwrap();
        assert_eq!(snapshots.len(), 1, "alpha should be deleted");
        assert_eq!(snapshots[0].name, "beta", "beta should remain");

        // Apply by name — also exercises find_snapshot()
        image.snapshot_apply("beta").unwrap();
    }

    #[test]
    fn find_snapshot_not_found() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("exists").unwrap();

        let result = image.snapshot_delete("nonexistent");
        assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
    }

    #[test]
    fn header_snapshot_fields_updated() {
        let mut image = create_test_image(1 << 20);
        assert_eq!(image.header().snapshot_count, 0);

        image.snapshot_create("snap-1").unwrap();
        assert_eq!(image.header().snapshot_count, 1);
        assert_ne!(image.header().snapshots_offset.0, 0);
    }

    // ---- Create tests ----

    #[test]
    fn create_snapshot_empty_name_rejected() {
        let mut image = create_test_image(1 << 20);
        let result = image.snapshot_create("");
        assert!(matches!(result, Err(Error::SnapshotNameEmpty)));
    }

    #[test]
    fn create_snapshot_duplicate_name_rejected() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("dup").unwrap();
        let result = image.snapshot_create("dup");
        assert!(matches!(result, Err(Error::SnapshotNameDuplicate { .. })));
    }

    #[test]
    fn create_snapshot_generates_sequential_ids() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("first").unwrap();
        image.snapshot_create("second").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps[0].id, "1");
        assert_eq!(snaps[1].id, "2");
    }

    #[test]
    fn create_snapshot_with_data_increments_refcounts() {
        let mut image = create_test_image(1 << 20);

        // Write some data
        image.write_at(&[0xAA; 4096], 0).unwrap();

        // Take snapshot
        image.snapshot_create("snap-1").unwrap();

        // The data cluster should now have refcount 2 (active + snapshot)
        // We verify indirectly: writing should trigger COW (allocate new cluster)
        image.write_at(&[0xBB; 4096], 0).unwrap();

        // Read back should return the new data
        let mut buf = vec![0u8; 4096];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn create_snapshot_clears_copied_flags() {
        let mut image = create_test_image(1 << 20);
        image.write_at(&[0xCC; 64], 0).unwrap();

        // Before snapshot: L1 and L2 should have copied=true
        image.snapshot_create("snap").unwrap();

        // After snapshot: writing to the same cluster triggers COW
        // (if COPIED were still set, it would write in-place, which is wrong)
        image.write_at(&[0xDD; 64], 0).unwrap();

        let mut buf = vec![0u8; 64];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn write_after_snapshot_preserves_snapshot_data() {
        let mut image = create_test_image(1 << 20);

        image.write_at(&[0x11; 512], 0).unwrap();
        image.snapshot_create("before-write").unwrap();
        image.write_at(&[0x22; 512], 0).unwrap();

        // Apply the snapshot to restore old data
        image.snapshot_apply("before-write").unwrap();

        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0x11),
            "snapshot data should be preserved after COW write"
        );
    }

    #[test]
    fn create_two_snapshots_sequentially() {
        let mut image = create_test_image(1 << 20);

        image.write_at(&[0xAA; 256], 0).unwrap();
        image.snapshot_create("snap-1").unwrap();

        image.write_at(&[0xBB; 256], 0).unwrap();
        image.snapshot_create("snap-2").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 2);
    }

    #[test]
    fn create_snapshot_empty_image() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("empty-snap").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "empty-snap");
    }

    // ---- List tests ----

    #[test]
    fn list_snapshots_metadata_correct() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("my-snap").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps[0].name, "my-snap");
        assert_eq!(snaps[0].virtual_size, Some(1 << 20));
        assert!(snaps[0].timestamp_seconds > 0);
    }

    // ---- Delete tests ----

    #[test]
    fn delete_only_snapshot() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("snap").unwrap();
        assert_eq!(image.snapshot_list().unwrap().len(), 1);

        image.snapshot_delete("snap").unwrap();
        assert_eq!(image.snapshot_list().unwrap().len(), 0);
        assert_eq!(image.header().snapshot_count, 0);
    }

    #[test]
    fn delete_first_of_two() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("first").unwrap();
        image.snapshot_create("second").unwrap();

        image.snapshot_delete("first").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "second");
    }

    #[test]
    fn delete_second_of_two() {
        let mut image = create_test_image(1 << 20);
        image.snapshot_create("first").unwrap();
        image.snapshot_create("second").unwrap();

        image.snapshot_delete("second").unwrap();

        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "first");
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let mut image = create_test_image(1 << 20);
        let result = image.snapshot_delete("nope");
        assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
    }

    #[test]
    fn delete_does_not_affect_active_data() {
        let mut image = create_test_image(1 << 20);
        image.write_at(&[0xAA; 256], 0).unwrap();
        image.snapshot_create("snap").unwrap();
        image.snapshot_delete("snap").unwrap();

        let mut buf = vec![0u8; 256];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    // ---- Apply tests ----

    #[test]
    fn apply_reverts_data() {
        let mut image = create_test_image(1 << 20);

        image.write_at(&[0x11; 256], 0).unwrap();
        image.snapshot_create("snap").unwrap();

        image.write_at(&[0x22; 256], 0).unwrap();
        image.snapshot_apply("snap").unwrap();

        let mut buf = vec![0u8; 256];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn apply_nonexistent_returns_error() {
        let mut image = create_test_image(1 << 20);
        let result = image.snapshot_apply("nonexistent");
        assert!(matches!(result, Err(Error::SnapshotNotFound { .. })));
    }

    #[test]
    fn apply_then_write_triggers_cow() {
        let mut image = create_test_image(1 << 20);

        image.write_at(&[0x11; 512], 0).unwrap();
        image.snapshot_create("snap").unwrap();
        image.snapshot_apply("snap").unwrap();

        // Writing after apply should trigger COW (shared clusters)
        image.write_at(&[0x33; 512], 0).unwrap();

        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0x33));
    }

    #[test]
    fn apply_modify_apply_cycle() {
        let mut image = create_test_image(1 << 20);

        // Phase 1: Write data, snapshot
        image.write_at(&[0xAA; 256], 0).unwrap();
        image.snapshot_create("base").unwrap();

        // Phase 2: Modify, then revert
        image.write_at(&[0xBB; 256], 0).unwrap();
        image.snapshot_apply("base").unwrap();

        let mut buf = vec![0u8; 256];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "first apply should revert");

        // Phase 3: Modify again, then revert again
        image.write_at(&[0xCC; 256], 0).unwrap();
        image.snapshot_apply("base").unwrap();

        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "second apply should revert");
    }

    #[test]
    fn apply_preserves_snapshot_table() {
        let mut image = create_test_image(1 << 20);

        image.write_at(&[0x55; 64], 0).unwrap();
        image.snapshot_create("snap-a").unwrap();
        image.snapshot_create("snap-b").unwrap();

        image.snapshot_apply("snap-a").unwrap();

        // Both snapshots should still exist
        let snaps = image.snapshot_list().unwrap();
        assert_eq!(snaps.len(), 2);
    }

    #[test]
    fn apply_to_empty_image_state() {
        let mut image = create_test_image(1 << 20);

        // Snapshot the empty state
        image.snapshot_create("empty").unwrap();

        // Write data
        image.write_at(&[0xFF; 1024], 0).unwrap();

        // Revert to empty
        image.snapshot_apply("empty").unwrap();

        let mut buf = vec![0u8; 1024];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0x00), "should revert to zeros");
    }
}
