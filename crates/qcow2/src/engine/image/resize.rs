//! Resize API: `resize`, `truncate_free_tail`, and related helpers.

use byteorder::{BigEndian, ByteOrder};

use crate::error::{Error, Result};
use crate::format::l1::L1Table;
use crate::format::types::ClusterOffset;

use super::Qcow2Image;

impl Qcow2Image {
    /// Resize the image to a new virtual size (grow only).
    ///
    /// If the new size requires more L1 table entries than currently allocated,
    /// the L1 table is grown in-place or relocated to a new cluster range.
    pub fn resize(&mut self, new_virtual_size: u64) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size();

        // Validate alignment
        if new_virtual_size % cluster_size != 0 {
            return Err(Error::ResizeNotAligned {
                size: new_virtual_size,
                cluster_size,
            });
        }

        let old_virtual_size = self.header.virtual_size;

        // No-op if same size
        if new_virtual_size == old_virtual_size {
            return Ok(());
        }

        // Calculate required L1 entries
        let l2_entries = cluster_size / 8;
        let bytes_per_l1_entry = l2_entries * cluster_size;
        let new_l1_entries =
            ((new_virtual_size + bytes_per_l1_entry - 1) / bytes_per_l1_entry) as u32;
        let old_l1_entries = self.header.l1_table_entries;

        if new_virtual_size < old_virtual_size {
            // Shrink
            self.shrink_image(new_virtual_size, new_l1_entries, old_l1_entries)?;
        } else if new_l1_entries > old_l1_entries {
            self.grow_l1_table(new_l1_entries, old_l1_entries, cluster_size)?;
        }

        // Flush dirty metadata before writing header and syncing
        self.flush_dirty_metadata()?;

        // Update header
        self.header.virtual_size = new_virtual_size;
        self.write_header_resize_fields()?;
        self.backend.flush()?;

        Ok(())
    }

    /// Grow the L1 table to accommodate more entries.
    fn grow_l1_table(
        &mut self,
        new_l1_entries: u32,
        old_l1_entries: u32,
        cluster_size: u64,
    ) -> Result<()> {
        let cluster_size_usize = cluster_size as usize;
        let old_l1_bytes = old_l1_entries as usize * 8;
        let new_l1_bytes = new_l1_entries as usize * 8;
        let old_l1_clusters = (old_l1_bytes + cluster_size_usize - 1) / cluster_size_usize;
        let new_l1_clusters = (new_l1_bytes + cluster_size_usize - 1) / cluster_size_usize;

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        if new_l1_clusters > old_l1_clusters {
            // L1 table must relocate: allocate new cluster(s), copy, free old

            // Read old L1 data
            let mut old_l1_data = vec![0u8; old_l1_clusters * cluster_size_usize];
            self.backend
                .read_exact_at(&mut old_l1_data, self.header.l1_table_offset.0)?;

            // Allocate contiguous clusters for the new L1 table
            let new_l1_offset = refcount_manager.allocate_contiguous_clusters(
                new_l1_clusters as u64,
                self.backend.as_ref(),
                &mut self.cache,
            )?;
            let file_size = self.backend.file_size()?;
            self.mapper.set_file_size(file_size);

            // Write old data to new location, zero-padded
            let mut new_l1_data = vec![0u8; new_l1_clusters * cluster_size_usize];
            new_l1_data[..old_l1_data.len()].copy_from_slice(&old_l1_data);
            self.backend.write_all_at(&new_l1_data, new_l1_offset.0)?;

            // Free old L1 clusters
            let old_l1_offset = self.header.l1_table_offset;
            for i in 0..old_l1_clusters {
                let cluster_off = ClusterOffset(old_l1_offset.0 + (i as u64 * cluster_size));
                refcount_manager.decrement_refcount(
                    cluster_off.0,
                    self.backend.as_ref(),
                    &mut self.cache,
                )?;
            }

            // Update header and mapper
            self.header.l1_table_offset = new_l1_offset;
            self.header.l1_table_entries = new_l1_entries;

            // Rebuild L1 table from new data
            let new_table = L1Table::read_from(&new_l1_data, new_l1_entries)?;
            self.mapper.replace_l1_table(new_table);
        } else {
            // In-place grow: just extend with zero entries at the end
            let zero_entries = new_l1_entries - old_l1_entries;
            let zero_bytes = vec![0u8; zero_entries as usize * 8];
            let write_offset =
                self.header.l1_table_offset.0 + old_l1_entries as u64 * 8;
            self.backend.write_all_at(&zero_bytes, write_offset)?;

            self.header.l1_table_entries = new_l1_entries;
            self.mapper.l1_table_mut().grow(new_l1_entries);
        }

        Ok(())
    }

    /// Shrink the virtual disk size.
    ///
    /// Refuses if there are snapshots (complex interaction) or if any
    /// clusters beyond the new boundary are still allocated.
    fn shrink_image(
        &mut self,
        new_virtual_size: u64,
        new_l1_entries: u32,
        old_l1_entries: u32,
    ) -> Result<()> {
        let cluster_size = self.cluster_size();

        // Refuse if snapshots exist — shrinking with snapshots is unsafe
        if self.header.snapshot_count > 0 {
            return Err(Error::ShrinkNotSupported {
                current: self.header.virtual_size,
                requested: new_virtual_size,
            });
        }

        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let entries_per_l2 = cluster_size / 8;

        // Check and free clusters beyond the new boundary.
        // Walk ALL L1 entries that could contain out-of-bounds references,
        // including the last kept L1 entry (which may partially cover
        // beyond new_virtual_size).
        let first_l1_to_check = if new_l1_entries > 0 {
            new_l1_entries - 1
        } else {
            0
        };

        for l1_idx in first_l1_to_check..old_l1_entries {
            let l1_entry = self
                .mapper
                .l1_entry(crate::format::types::L1Index(l1_idx))?;
            let l2_offset = match l1_entry.l2_table_offset() {
                Some(o) => o,
                None => continue,
            };

            // Read the L2 table
            let mut l2_buf = vec![0u8; cluster_size as usize];
            self.backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
            let l2_table =
                crate::format::l2::L2Table::read_from(&l2_buf, self.header.geometry())?;

            // Check entries that correspond to guest offsets >= new_virtual_size
            let l1_guest_base = l1_idx as u64 * entries_per_l2 * cluster_size;
            let mut has_data_beyond = false;

            for l2_idx in 0..entries_per_l2 as u32 {
                let guest_offset = l1_guest_base + l2_idx as u64 * cluster_size;
                if guest_offset < new_virtual_size {
                    continue; // within new boundary
                }
                let entry =
                    l2_table.get(crate::format::types::L2Index(l2_idx))?;
                match entry {
                    crate::format::l2::L2Entry::Unallocated
                    | crate::format::l2::L2Entry::Zero {
                        preallocated_offset: None, ..
                    } => {}
                    _ => {
                        has_data_beyond = true;
                    }
                }
            }

            if has_data_beyond {
                let first_oob = (new_virtual_size.max(l1_guest_base) - l1_guest_base)
                    / cluster_size
                    * cluster_size
                    + l1_guest_base;
                return Err(Error::ShrinkDataLoss {
                    cluster_offset: first_oob,
                    context: "allocated cluster beyond new virtual size",
                });
            }

            // For L1 entries being fully removed, free the L2 table
            if l1_idx >= new_l1_entries {
                refcount_manager.decrement_refcount(
                    l2_offset.0,
                    self.backend.as_ref(),
                    &mut self.cache,
                )?;

                // Null the L1 entry on disk
                let l1_disk_offset =
                    self.header.l1_table_offset.0 + l1_idx as u64 * 8;
                self.backend.write_all_at(&[0u8; 8], l1_disk_offset)?;
            }
        }

        // Shrink the in-memory L1 table
        self.mapper.l1_table_mut().shrink(new_l1_entries);
        self.header.l1_table_entries = new_l1_entries;

        // Flush dirty refcount blocks from shrink operations, then
        // invalidate cache — L2 tables and refcount blocks may reference
        // clusters that no longer exist after shrink.
        self.flush_dirty_metadata()?;
        self.cache.clear();

        Ok(())
    }

    /// Truncate the file after the last cluster with a non-zero refcount.
    ///
    /// Scans the refcount table backwards to find the last used cluster,
    /// then truncates the file to free unused space at the end. Returns
    /// the number of bytes saved.
    pub fn truncate_free_tail(&mut self) -> Result<u64> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size();
        let file_size = self.backend.file_size()?;
        let total_clusters = file_size / cluster_size;

        if total_clusters == 0 {
            return Ok(0);
        }

        let refcount_manager = self
            .refcount_manager
            .as_ref()
            .expect("writable image must have refcount_manager");

        // Find the last cluster with refcount > 0, scanning backwards
        let mut last_used = 0u64;
        for cluster_idx in (0..total_clusters).rev() {
            let rc = refcount_manager.get_refcount(
                cluster_idx * cluster_size,
                self.backend.as_ref(),
                &mut self.cache,
            )?;
            if rc > 0 {
                last_used = cluster_idx;
                break;
            }
        }

        let new_file_size = (last_used + 1) * cluster_size;
        if new_file_size >= file_size {
            return Ok(0); // nothing to truncate
        }

        let saved = file_size - new_file_size;
        self.backend.set_len(new_file_size)?;

        // Update mapper's file size
        self.mapper.set_file_size(new_file_size);

        // Flush dirty entries, then invalidate cache — refcount blocks may
        // reference truncated regions.
        self.flush_dirty_metadata()?;
        self.cache.clear();

        Ok(saved)
    }

    /// Write virtual_size, l1_table_entries, and l1_table_offset to the on-disk header.
    fn write_header_resize_fields(&self) -> Result<()> {
        // virtual_size at offset 24
        let mut buf8 = [0u8; 8];
        BigEndian::write_u64(&mut buf8, self.header.virtual_size);
        self.backend.write_all_at(&buf8, 24)?;

        // l1_table_entries at offset 36
        let mut buf4 = [0u8; 4];
        BigEndian::write_u32(&mut buf4, self.header.l1_table_entries);
        self.backend.write_all_at(&buf4, 36)?;

        // l1_table_offset at offset 40
        BigEndian::write_u64(&mut buf8, self.header.l1_table_offset.0);
        self.backend.write_all_at(&buf8, 40)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_helpers::*;
    use super::*;
    use crate::format::constants::*;

    #[test]
    fn resize_reject_read_only() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend(Box::new(backend)).unwrap();
        assert!(!image.is_writable());
        let result = image.resize(2 * 1024 * 1024);
        assert!(
            matches!(result, Err(Error::ReadOnly)),
            "resize on read-only image should return ReadOnly, got {result:?}"
        );
    }

    #[test]
    fn resize_shrink_rejected_with_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            super::super::CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
                extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();
        image.snapshot_create("snap").unwrap();
        let result = image.resize(image.cluster_size());
        assert!(matches!(result, Err(Error::ShrinkNotSupported { .. })));
    }

    #[test]
    fn resize_shrink_empty_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            super::super::CreateOptions {
                virtual_size: 4 * 1024 * 1024,
                cluster_bits: None,
                extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();
        // Shrink to half size (no data allocated)
        image.resize(2 * 1024 * 1024).unwrap();
        assert_eq!(image.virtual_size(), 2 * 1024 * 1024);

        // Reading beyond new size should fail
        let mut buf = vec![0u8; 512];
        let result = image.read_at(&mut buf, 3 * 1024 * 1024);
        assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
    }

    #[test]
    fn resize_shrink_with_data_beyond_boundary_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            super::super::CreateOptions {
                virtual_size: 4 * 1024 * 1024,
                cluster_bits: None,
                extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            },
        )
        .unwrap();
        // Write data at the end (beyond what will be the new boundary)
        image.write_at(&[0xAA; 512], 3 * 1024 * 1024).unwrap();
        image.flush().unwrap();

        let result = image.resize(2 * 1024 * 1024);
        assert!(matches!(result, Err(Error::ShrinkDataLoss { .. })));
    }

    #[test]
    fn resize_reject_unaligned() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let new_size = image.virtual_size() + 1000; // not cluster-aligned
        let result = image.resize(new_size);
        assert!(matches!(result, Err(Error::ResizeNotAligned { .. })));
    }

    #[test]
    fn resize_same_size_is_noop() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let old_size = image.virtual_size();
        image.resize(old_size).unwrap();
        assert_eq!(image.virtual_size(), old_size);
    }

    #[test]
    fn resize_grow_within_existing_l1() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();
        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        // Grow by one cluster — should stay within existing L1 capacity
        let new_size = old_size + cluster_size;
        image.resize(new_size).unwrap();
        assert_eq!(image.virtual_size(), new_size);
    }

    #[test]
    fn resize_data_survives() {
        let data_offset = 3 * CLUSTER_SIZE as u64;
        let l2_raw = data_offset | L2_COPIED_FLAG;
        let data = vec![0xAA; 512];
        let backend = build_test_image(&[(0, l2_raw)], &[(3, &data)]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        let new_size = old_size + 4 * cluster_size;
        image.resize(new_size).unwrap();

        // Original data still readable
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn resize_new_area_reads_zeros() {
        let backend = build_test_image(&[], &[]);
        let mut image = Qcow2Image::from_backend_rw(Box::new(backend)).unwrap();

        let old_size = image.virtual_size();
        let cluster_size = image.cluster_size();
        let new_size = old_size + 2 * cluster_size;
        image.resize(new_size).unwrap();

        // Read from the new area (just beyond old size)
        let mut buf = vec![0u8; 512];
        image.read_at(&mut buf, old_size).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "new area should read as zeros");
    }
}
