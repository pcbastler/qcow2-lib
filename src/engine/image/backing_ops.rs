//! Backing chain operations: `commit` and `rebase_unsafe`.

use std::path::Path;

use crate::engine::backing::BackingChain;
use crate::engine::compression;
use crate::error::{Error, Result};

use super::Qcow2Image;

impl Qcow2Image {
    /// Merge all allocated clusters from this overlay into its backing file.
    ///
    /// After a successful commit, the backing file contains all data that
    /// was written to the overlay. The overlay itself is not modified.
    ///
    /// Requires the image to have a backing file (`CommitNoBacking` otherwise).
    pub fn commit(&mut self) -> Result<()> {
        // Must have a backing chain
        let backing_path = self
            .backing_chain
            .as_ref()
            .and_then(|c| c.entries().first())
            .map(|e| e.path.clone())
            .ok_or(Error::CommitNoBacking)?;

        // Open backing file separately for writing
        let mut backing = Qcow2Image::open_rw(&backing_path)?;

        // Resize backing if overlay has a larger virtual size (matches qemu-img commit behavior)
        if self.virtual_size() > backing.virtual_size() {
            backing.resize(self.virtual_size())?;
        }

        let cluster_size = self.header.cluster_size();
        let l1_len = self.mapper.l1_table().len();
        let l2_entries_per_table = self.header.l2_entries_per_table();

        // Walk L1 → L2 → entries, copy allocated data to backing
        for l1_idx in 0..l1_len {
            let l1_entry = self
                .mapper
                .l1_table()
                .get(crate::format::types::L1Index(l1_idx))?;
            let l2_offset = match l1_entry.l2_table_offset() {
                Some(off) => off,
                None => continue, // entire L2 range unallocated
            };

            // Load L2 table from our backend
            let l2_table = {
                let mut buf = vec![0u8; cluster_size as usize];
                self.backend.read_exact_at(&mut buf, l2_offset.0)?;
                crate::format::l2::L2Table::read_from(&buf, self.header.geometry())?
            };

            for l2_idx in 0..l2_entries_per_table {
                let l2_entry = l2_table
                    .get(crate::format::types::L2Index(l2_idx as u32))?;

                let guest_offset =
                    l1_idx as u64 * l2_entries_per_table * cluster_size
                    + l2_idx * cluster_size;

                match l2_entry {
                    crate::format::l2::L2Entry::Unallocated => {
                        // Not our data — comes from backing itself
                    }
                    crate::format::l2::L2Entry::Zero { .. } => {
                        // Write zeros to backing
                        let zeros = vec![0u8; cluster_size as usize];
                        backing.write_at(&zeros, guest_offset)?;
                    }
                    crate::format::l2::L2Entry::Standard { host_offset, .. } => {
                        // Read cluster data from our image
                        let mut data = vec![0u8; cluster_size as usize];
                        self.backend
                            .read_exact_at(&mut data, host_offset.0)?;
                        backing.write_at(&data, guest_offset)?;
                    }
                    crate::format::l2::L2Entry::Compressed(desc) => {
                        // Read compressed data, decompress, write to backing
                        let mut compressed =
                            vec![0u8; desc.compressed_size as usize];
                        self.backend
                            .read_exact_at(&mut compressed, desc.host_offset)?;
                        let decompressed = compression::decompress_cluster(
                            &compressed,
                            cluster_size as usize,
                            guest_offset,
                        )?;
                        backing.write_at(&decompressed, guest_offset)?;
                    }
                }
            }
        }

        backing.flush()?;
        Ok(())
    }

    /// Change (or remove) the backing file reference in the header.
    ///
    /// This is an **unsafe** rebase: it only updates the backing file path
    /// stored in the header without migrating any data. The caller must
    /// ensure that the new backing file is content-compatible with the old one,
    /// or that `None` is used only when all guest data is allocated in this image.
    ///
    /// Pass `None` to remove the backing file reference entirely.
    pub fn rebase_unsafe(&mut self, new_backing: Option<&Path>) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.header.cluster_size();

        match new_backing {
            None => {
                // Remove backing file reference
                // Zero out old name on disk
                if self.header.has_backing_file() {
                    let old_offset = self.header.backing_file_offset;
                    let old_size = self.header.backing_file_size as usize;
                    let zeros = vec![0u8; old_size];
                    self.backend.write_all_at(&zeros, old_offset)?;
                }

                self.header.backing_file_offset = 0;
                self.header.backing_file_size = 0;

                // Rewrite header
                let mut header_buf = vec![0u8; self.header.serialized_length()];
                self.header.write_to(&mut header_buf)?;
                self.backend.write_all_at(&header_buf, 0)?;
                self.backend.flush()?;

                // Update in-memory state
                self.backing_chain = None;
                self.backing_image = None;
            }
            Some(path) => {
                let name = path.to_string_lossy();
                let name_bytes = name.as_bytes();

                // Determine where to write the backing file name.
                // Use the standard position: right after the header extensions terminator.
                let ext_end_offset = crate::format::constants::HEADER_V3_MIN_LENGTH;
                let backing_file_offset = (ext_end_offset + 8) as u64; // after 8-byte end marker

                // Verify it fits in cluster 0
                if backing_file_offset + name_bytes.len() as u64 > cluster_size {
                    return Err(Error::WriteFailed {
                        guest_offset: 0,
                        message: format!(
                            "backing file name ({} bytes) too long for header cluster",
                            name_bytes.len()
                        ),
                    });
                }

                // Zero out old name if present
                if self.header.has_backing_file() {
                    let old_offset = self.header.backing_file_offset;
                    let old_size = self.header.backing_file_size as usize;
                    let zeros = vec![0u8; old_size];
                    self.backend.write_all_at(&zeros, old_offset)?;
                }

                // Write new name
                self.backend
                    .write_all_at(name_bytes, backing_file_offset)?;

                // Update header
                self.header.backing_file_offset = backing_file_offset;
                self.header.backing_file_size = name_bytes.len() as u32;

                // Rewrite header
                let mut header_buf = vec![0u8; self.header.serialized_length()];
                self.header.write_to(&mut header_buf)?;
                self.backend.write_all_at(&header_buf, 0)?;
                self.backend.flush()?;

                // Update in-memory state
                let image_dir = path.parent().unwrap_or(Path::new("."));
                match BackingChain::resolve(&name, image_dir) {
                    Ok(chain) => {
                        match Qcow2Image::open(path) {
                            Ok(img) => {
                                self.backing_image = Some(Box::new(img));
                            }
                            Err(_) => {
                                self.backing_image = None;
                            }
                        }
                        self.backing_chain = Some(chain);
                    }
                    Err(_) => {
                        self.backing_chain = None;
                        self.backing_image = None;
                    }
                }
            }
        }

        Ok(())
    }
}
