//! Compressed cluster packing: writes pre-compressed data into shared host clusters.

use alloc::vec;

use crate::error::Result;
use crate::format::l2::L2Entry;
use crate::format::types::*;

use super::Qcow2Writer;

impl<'a> Qcow2Writer<'a> {
    /// Write a pre-compressed cluster to the image.
    ///
    /// Packs compressed data into shared host clusters to save space.
    /// Multiple compressed guest clusters can share one host cluster.
    /// Only allocates a new host cluster when the current one is full.
    ///
    /// The `guest_offset` must be cluster-aligned.
    pub fn write_compressed_at(
        &mut self,
        compressed_data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        let cluster_size = 1u64 << self.cluster_bits;
        let (l1_index, l2_index, _intra) =
            GuestOffset(guest_offset).split(self.mapper.geometry());

        // Ensure L2 table exists
        let l2_table_offset = self.ensure_l2_table(l1_index)?;

        // Round compressed size up to 512-byte sector boundary.
        let sector_aligned_size = ((compressed_data.len() as u64) + 511) & !511;
        let compressed_size = sector_aligned_size.max(512);

        // Determine where to write: pack into current host cluster or allocate new.
        let write_offset = if self.compressed_cursor == 0 {
            // No active packing cluster — allocate a fresh one.
            let host_cluster =
                self.refcount_manager
                    .allocate_cluster(self.backend, self.cache)?;
            self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);
            host_cluster.0
        } else {
            // Check if the data fits in the remainder of the current host cluster.
            let offset_in_cluster = self.compressed_cursor & (cluster_size - 1);
            if offset_in_cluster + compressed_size > cluster_size {
                // Doesn't fit — allocate a new host cluster.
                let host_cluster =
                    self.refcount_manager
                        .allocate_cluster(self.backend, self.cache)?;
                self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);
                host_cluster.0
            } else {
                // Packing into existing host cluster — increment its refcount
                // so it matches the number of L2 entries referencing it.
                let host_cluster_start =
                    self.compressed_cursor & !(cluster_size - 1);
                self.refcount_manager.increment_refcount(
                    host_cluster_start,
                    self.backend,
                    self.cache,
                )?;
                self.compressed_cursor
            }
        };

        // Write compressed data padded to sector alignment.
        // The L2 entry stores the sector-aligned size, so the on-disk data
        // must cover the full range to avoid short reads at EOF.
        let mut padded = vec![0u8; compressed_size as usize];
        padded[..compressed_data.len()].copy_from_slice(compressed_data);
        self.backend
            .write_all_at(&padded, write_offset)?;

        // Advance the cursor past the sector-aligned compressed data.
        self.compressed_cursor = write_offset + compressed_size;

        // Build the compressed descriptor.
        let descriptor =
            crate::format::compressed::CompressedClusterDescriptor {
                host_offset: write_offset,
                compressed_size,
            };

        let entry = L2Entry::Compressed(descriptor);

        // Handle the old L2 entry: decrement refcount if it was allocated.
        let l2_table = self.load_l2_table(l2_table_offset)?;
        let old_entry = l2_table.get(l2_index)?;
        match old_entry {
            L2Entry::Standard { host_offset, .. } => {
                self.refcount_manager.decrement_refcount(
                    host_offset.0,
                    self.backend,
                    self.cache,
                )?;
            }
            L2Entry::Compressed(old_desc) => {
                let old_cluster = ClusterOffset(
                    old_desc.host_offset & !(cluster_size - 1),
                );
                self.refcount_manager.decrement_refcount(
                    old_cluster.0,
                    self.backend,
                    self.cache,
                )?;
            }
            _ => {}
        }

        // Write the new L2 entry.
        self.write_l2_entry(l2_table_offset, l2_index, entry)?;

        Ok(())
    }
}
