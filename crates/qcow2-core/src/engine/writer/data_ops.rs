//! Data cluster write operations: allocate, in-place, COW, and compressed-to-standard.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::constants::SUBCLUSTERS_PER_CLUSTER;
use crate::format::l2::{L2Entry, SubclusterBitmap, SubclusterState};
use crate::format::types::*;

use super::Qcow2Writer;

impl<'a> Qcow2Writer<'a> {
    /// Write data to a newly allocated cluster (for unallocated/zero entries).
    ///
    /// The `old_bitmap` preserves subcluster state from the previous entry
    /// (e.g. zero-bits from a Zero entry). For full-cluster writes this is
    /// skipped entirely.
    pub(super) fn write_to_new_cluster(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
        old_bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        // With raw external data: host_offset = guest_offset (identity mapping),
        // no refcount allocation needed for data clusters.
        let new_offset = if self.raw_external {
            ClusterOffset(guest_cluster_offset)
        } else {
            let off = self.refcount_manager.allocate_cluster(
                self.backend,
                self.cache,
            )?;
            self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);
            off
        };

        if buf.len() == cluster_size as usize {
            // Fast path: full cluster write — no subcluster handling needed
            if let Some(crypt) = self.crypt_context {
                let mut cluster_buf = buf.to_vec();
                crypt.encrypt_cluster(new_offset.0, &mut cluster_buf)?;
                self.data_backend.write_all_at(&cluster_buf, new_offset.0)?;
            } else {
                self.data_backend.write_all_at(buf, new_offset.0)?;
            }
            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        if old_bitmap.is_all_zero() || old_bitmap.is_all_unallocated() {
            // Fast path: no meaningful subcluster state to preserve.
            let cluster_buf = self.build_cluster_from_backing(
                buf, intra, cluster_size, guest_cluster_offset,
            )?;
            self.encrypt_and_write_cluster(new_offset, cluster_buf)?;

            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        // Subcluster-aware path: preserve existing subcluster state.
        self.write_subclusters(
            buf, intra, cluster_size, guest_cluster_offset, new_offset, old_bitmap,
        )
    }

    /// Build a full cluster buffer: read backing data (or zeros), overlay the write.
    fn build_cluster_from_backing(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
    ) -> Result<Vec<u8>> {
        let mut cluster_buf = vec![0u8; cluster_size as usize];
        if let Some(ref mut backing) = self.backing_image {
            let backing_vs = backing.virtual_size();
            if guest_cluster_offset < backing_vs {
                let available =
                    (backing_vs - guest_cluster_offset).min(cluster_size) as usize;
                backing.read_at(&mut cluster_buf[..available], guest_cluster_offset)?;
            }
        }
        let start = intra.0 as usize;
        cluster_buf[start..start + buf.len()].copy_from_slice(buf);
        Ok(cluster_buf)
    }

    /// Optionally encrypt, then write a full cluster buffer.
    fn encrypt_and_write_cluster(
        &self,
        offset: ClusterOffset,
        mut data: Vec<u8>,
    ) -> Result<()> {
        if let Some(crypt) = self.crypt_context {
            crypt.encrypt_cluster(offset.0, &mut data)?;
        }
        self.data_backend.write_all_at(&data, offset.0)
    }

    /// Subcluster-aware write: preserve existing subcluster state from the old bitmap.
    fn write_subclusters(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
        new_offset: ClusterOffset,
        mut bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        // Build a cluster buffer, reading backing data for unallocated
        // subclusters that are only partially covered by the write.
        let mut cluster_buf = vec![0u8; cluster_size as usize];

        if let Some(ref mut backing) = self.backing_image {
            let backing_vs = backing.virtual_size();
            for sc in first_sc..=last_sc {
                if matches!(bitmap.get(sc), SubclusterState::Unallocated) {
                    let sc_start = sc as u64 * sc_size;
                    let sc_end_off = sc_start + sc_size;
                    let write_covers_sc = start <= sc_start && end >= sc_end_off;
                    if !write_covers_sc && guest_cluster_offset + sc_start < backing_vs {
                        let guest_sc = guest_cluster_offset + sc_start;
                        let avail = (backing_vs - guest_sc).min(sc_size) as usize;
                        backing.read_at(
                            &mut cluster_buf[sc_start as usize..sc_start as usize + avail],
                            guest_sc,
                        )?;
                    }
                }
            }
        }

        // Overlay the write data
        cluster_buf[start as usize..end as usize].copy_from_slice(buf);

        if let Some(crypt) = self.crypt_context {
            // Encrypted: write full cluster (encryption requires full cluster)
            crypt.encrypt_cluster(new_offset.0, &mut cluster_buf)?;
            self.data_backend.write_all_at(&cluster_buf, new_offset.0)?;
        } else {
            // Unencrypted: write only the affected subclusters
            for sc in first_sc..=last_sc {
                let sc_start = sc as u64 * sc_size;
                self.data_backend.write_all_at(
                    &cluster_buf[sc_start as usize..(sc_start + sc_size) as usize],
                    new_offset.0 + sc_start,
                )?;
            }
        }

        for sc in first_sc..=last_sc {
            bitmap.set(sc, SubclusterState::Allocated);
        }

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: bitmap,
        })
    }

    /// Overwrite data in-place in an existing standard (copied) cluster.
    ///
    /// For subclusters that were previously Zero or Unallocated and are only
    /// partially covered by the write, initializes the unwritten part with zeros.
    pub(super) fn write_in_place(
        &mut self,
        buf: &[u8],
        host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        cluster_size: u64,
        mut bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        if self.crypt_context.is_some() {
            // Encrypted: must read-decrypt-modify-encrypt-write the full cluster.
            let crypt = self.crypt_context.unwrap();
            let mut cluster_buf = vec![0u8; cluster_size as usize];
            self.data_backend.read_exact_at(&mut cluster_buf, host_offset.0)?;
            crypt.decrypt_cluster(host_offset.0, &mut cluster_buf)?;
            let start = intra.0 as usize;
            cluster_buf[start..start + buf.len()].copy_from_slice(buf);
            crypt.encrypt_cluster(host_offset.0, &mut cluster_buf)?;
            self.data_backend.write_all_at(&cluster_buf, host_offset.0)?;

            // Mark written subclusters as Allocated
            let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
            let end = start as u64 + buf.len() as u64;
            let first_sc = (start as u64 / sc_size) as u32;
            let last_sc = ((end - 1) / sc_size) as u32;
            for sc in first_sc..=last_sc {
                bitmap.set(sc, SubclusterState::Allocated);
            }
            return Ok(L2Entry::Standard {
                host_offset,
                copied: true,
                subclusters: bitmap,
            });
        }

        if bitmap.is_all_allocated() {
            // Fast path: all subclusters already allocated → direct write
            self.data_backend
                .write_all_at(buf, host_offset.0 + intra.0 as u64)?;
            return Ok(L2Entry::Standard {
                host_offset,
                copied: true,
                subclusters: bitmap,
            });
        }

        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        // For partially-covered subclusters that were Zero/Unallocated,
        // initialize the non-written part with zeros before overlaying.
        for sc in first_sc..=last_sc {
            let state = bitmap.get(sc);
            let sc_start = sc as u64 * sc_size;
            let sc_end = sc_start + sc_size;
            let write_covers_sc = start <= sc_start && end >= sc_end;

            if !write_covers_sc && matches!(state, SubclusterState::Zero | SubclusterState::Unallocated) {
                let mut sc_buf = vec![0u8; sc_size as usize];
                let overlap_start = start.max(sc_start);
                let overlap_end = end.min(sc_end);
                let buf_off = (overlap_start - start) as usize;
                let sc_off = (overlap_start - sc_start) as usize;
                let overlap_len = (overlap_end - overlap_start) as usize;
                sc_buf[sc_off..sc_off + overlap_len]
                    .copy_from_slice(&buf[buf_off..buf_off + overlap_len]);
                self.data_backend.write_all_at(&sc_buf, host_offset.0 + sc_start)?;
            }
        }

        // Write the user data
        self.data_backend
            .write_all_at(buf, host_offset.0 + intra.0 as u64)?;

        // Mark written subclusters as Allocated
        for sc in first_sc..=last_sc {
            bitmap.set(sc, SubclusterState::Allocated);
        }

        Ok(L2Entry::Standard {
            host_offset,
            copied: true,
            subclusters: bitmap,
        })
    }

    /// Copy-on-write a shared data cluster (refcount > 1, copied flag clear).
    ///
    /// For all_allocated bitmaps: bulk-copies the full cluster.
    /// Otherwise: copies only Allocated subclusters, preserves Zero-bits.
    pub(super) fn cow_data_cluster(
        &mut self,
        buf: &[u8],
        old_host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        cluster_size: u64,
        old_bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        if old_bitmap.is_all_allocated() {
            // Fast path: bulk copy entire cluster
            let mut cluster_data = vec![0u8; cluster_size as usize];
            self.data_backend.read_exact_at(&mut cluster_data, old_host_offset.0)?;

            // Decrypt with old host offset, modify, encrypt with new host offset
            if let Some(crypt) = self.crypt_context {
                crypt.decrypt_cluster(old_host_offset.0, &mut cluster_data)?;
            }

            let start = intra.0 as usize;
            cluster_data[start..start + buf.len()].copy_from_slice(buf);

            let new_offset = if self.raw_external {
                // Identity mapping — COW doesn't apply for raw external
                old_host_offset
            } else {
                let off = self.refcount_manager.allocate_cluster(
                    self.backend, self.cache,
                )?;
                self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);
                off
            };

            if let Some(crypt) = self.crypt_context {
                crypt.encrypt_cluster(new_offset.0, &mut cluster_data)?;
            }
            self.data_backend.write_all_at(&cluster_data, new_offset.0)?;

            if !self.raw_external {
                self.refcount_manager.decrement_refcount(
                    old_host_offset.0, self.backend, self.cache,
                )?;
            }

            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        let new_offset = if self.raw_external {
            old_host_offset
        } else {
            let off = self.refcount_manager.allocate_cluster(
                self.backend, self.cache,
            )?;
            self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);
            off
        };

        if self.crypt_context.is_some() {
            // Encrypted subcluster COW: read full cluster, decrypt, modify, encrypt, write full
            let crypt = self.crypt_context.unwrap();
            let mut cluster_data = vec![0u8; cluster_size as usize];
            self.data_backend.read_exact_at(&mut cluster_data, old_host_offset.0)?;
            crypt.decrypt_cluster(old_host_offset.0, &mut cluster_data)?;

            // Overlay the user data
            cluster_data[start as usize..end as usize].copy_from_slice(buf);

            // Encrypt with new host offset and write full cluster
            crypt.encrypt_cluster(new_offset.0, &mut cluster_data)?;
            self.data_backend.write_all_at(&cluster_data, new_offset.0)?;

            // Preserve subcluster bitmap, marking written ones as allocated
            let mut new_bitmap = old_bitmap;
            for sc in first_sc..=last_sc {
                new_bitmap.set(sc, SubclusterState::Allocated);
            }

            self.refcount_manager.decrement_refcount(
                old_host_offset.0, self.backend, self.cache,
            )?;

            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: new_bitmap,
            });
        }

        // Unencrypted: copy per-subcluster, preserving state
        let mut new_bitmap = SubclusterBitmap::all_unallocated();
        for sc in 0..SUBCLUSTERS_PER_CLUSTER {
            match old_bitmap.get(sc) {
                SubclusterState::Allocated => {
                    let sc_start = sc as u64 * sc_size;
                    let mut sc_buf = vec![0u8; sc_size as usize];
                    self.data_backend.read_exact_at(&mut sc_buf, old_host_offset.0 + sc_start)?;
                    self.data_backend.write_all_at(&sc_buf, new_offset.0 + sc_start)?;
                    new_bitmap.set(sc, SubclusterState::Allocated);
                }
                SubclusterState::Zero => {
                    new_bitmap.set(sc, SubclusterState::Zero);
                }
                _ => {} // Unallocated/Invalid: stays unallocated
            }
        }

        // Write the user data
        self.data_backend.write_all_at(buf, new_offset.0 + start)?;

        // Mark written subclusters as Allocated
        for sc in first_sc..=last_sc {
            new_bitmap.set(sc, SubclusterState::Allocated);
        }

        // Decrement refcount of old cluster
        self.refcount_manager.decrement_refcount(
            old_host_offset.0, self.backend, self.cache,
        )?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: new_bitmap,
        })
    }

    /// Handle writing to a compressed cluster: decompress, apply write, re-allocate.
    pub(super) fn write_to_compressed_cluster(
        &mut self,
        buf: &[u8],
        descriptor: crate::format::compressed::CompressedClusterDescriptor,
        intra: IntraClusterOffset,
        cluster_size: u64,
    ) -> Result<L2Entry> {
        if self.raw_external {
            return Err(Error::CompressedWithExternalData);
        }
        if self.crypt_context.is_some() {
            return Err(Error::EncryptionWithCompression);
        }
        let compressed_size = descriptor.compressed_size as usize;
        let mut compressed_buf = vec![0u8; compressed_size];
        self.backend
            .read_exact_at(&mut compressed_buf, descriptor.host_offset)?;

        let mut decompressed = vec![0u8; cluster_size as usize];
        self.compressor.decompress(
            &compressed_buf,
            &mut decompressed,
            self.compression_type,
        )?;

        let start = intra.0 as usize;
        decompressed[start..start + buf.len()].copy_from_slice(buf);

        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend, self.cache,
        )?;
        self.mapper.set_file_size(self.refcount_manager.state().next_cluster_offset);

        self.backend.write_all_at(&decompressed, new_offset.0)?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        })
    }
}
