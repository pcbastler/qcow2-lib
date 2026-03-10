//! QCOW2 write engine: translates guest writes into host cluster operations.
//!
//! Handles cluster allocation, L1/L2 table updates, and metadata
//! persistence. In **WriteBack** mode, L2 modifications stay in the cache
//! and are flushed lazily; in **WriteThrough** mode, every L2 update is
//! written to disk immediately. Supports writing to unallocated, zero, and
//! standard (copied) clusters. Compressed clusters are decompressed
//! before applying the write.

extern crate alloc;

use alloc::vec;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::io::Compressor;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, Result};
use crate::format::constants::{L2_ENTRY_SIZE, L2_ENTRY_SIZE_EXTENDED, SUBCLUSTERS_PER_CLUSTER};
use crate::format::l1::L1Entry;
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap, SubclusterState};
use crate::format::types::*;
use crate::engine::encryption::CryptContext;
use crate::io::IoBackend;

/// Writes guest data to a QCOW2 image.
///
/// Borrows the mutable state needed for write operations. Created on
/// demand by `Qcow2Image` for each write call.
///
/// When a backing image is provided, partial writes to unallocated
/// clusters read the existing data from the backing image before
/// merging the new data, instead of zero-filling.
pub struct Qcow2Writer<'a> {
    mapper: &'a mut ClusterMapper,
    l1_table_offset: ClusterOffset,
    backend: &'a dyn IoBackend,
    /// Backend for guest data clusters (external data file or same as backend).
    data_backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    cluster_bits: u32,
    virtual_size: u64,
    compression_type: u8,
    /// When true, data clusters use identity-mapped offsets (host = guest).
    raw_external: bool,
    backing_image: Option<&'a mut dyn crate::io::BackingImage>,
    /// Byte offset for the next compressed write within a shared host cluster.
    /// Zero means no active compressed packing cluster.
    compressed_cursor: u64,
    crypt_context: Option<&'a CryptContext>,
    compressor: &'a dyn Compressor,
}

impl<'a> Qcow2Writer<'a> {
    /// Create a new writer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapper: &'a mut ClusterMapper,
        l1_table_offset: ClusterOffset,
        backend: &'a dyn IoBackend,
        data_backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        cluster_bits: u32,
        virtual_size: u64,
        compression_type: u8,
        raw_external: bool,
        backing_image: Option<&'a mut dyn crate::io::BackingImage>,
        crypt_context: Option<&'a CryptContext>,
        compressor: &'a dyn Compressor,
    ) -> Self {
        Self {
            mapper,
            l1_table_offset,
            backend,
            data_backend,
            cache,
            refcount_manager,
            cluster_bits,
            virtual_size,
            compression_type,
            raw_external,
            backing_image,
            compressed_cursor: 0,
            crypt_context,
            compressor,
        }
    }

    /// Set the compressed packing cursor from previous state.
    pub fn set_compressed_cursor(&mut self, cursor: u64) {
        self.compressed_cursor = cursor;
    }

    /// Return the current compressed packing cursor.
    pub fn compressed_cursor(&self) -> u64 {
        self.compressed_cursor
    }

    /// Write `buf` starting at the given guest offset.
    ///
    /// Handles writes that span multiple clusters by splitting them
    /// into per-cluster chunks.
    pub fn write_at(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        let write_end = guest_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            })?;

        if write_end > self.virtual_size {
            return Err(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            });
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left_in_cluster = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left_in_cluster);
            let (chunk, rest) = remaining.split_at(chunk_size);

            self.write_cluster_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Write a chunk of data to a single cluster.
    fn write_cluster_chunk(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        let (l1_index, l2_index, intra) = GuestOffset(guest_offset).split(self.mapper.geometry());
        let cluster_size = 1u64 << self.cluster_bits;

        // Step 1: Ensure L2 table exists
        let l2_offset = self.ensure_l2_table(l1_index)?;

        // Step 2: Load L2 table
        let l2_table = self.load_l2_table(l2_offset)?;
        let l2_entry = l2_table.get(l2_index)?;

        // Step 3: Dispatch on L2 entry type
        let guest_cluster_offset = guest_offset - intra.0 as u64;
        let new_l2_entry = match l2_entry {
            L2Entry::Unallocated => {
                self.write_to_new_cluster(
                    buf, intra, cluster_size, guest_cluster_offset,
                    SubclusterBitmap::all_unallocated(),
                )?
            }
            L2Entry::Zero { preallocated_offset, subclusters } => {
                let result = self.write_to_new_cluster(
                    buf, intra, cluster_size, guest_cluster_offset, subclusters,
                )?;
                if let Some(prealloc) = preallocated_offset {
                    self.refcount_manager.decrement_refcount(
                        prealloc.0, self.backend, self.cache,
                    )?;
                }
                result
            }
            L2Entry::Standard { host_offset, copied, subclusters } => {
                if copied {
                    self.write_in_place(buf, host_offset, intra, cluster_size, subclusters)?
                } else {
                    self.cow_data_cluster(buf, host_offset, intra, cluster_size, subclusters)?
                }
            }
            L2Entry::Compressed(descriptor) => {
                self.write_to_compressed_cluster(buf, descriptor, intra, cluster_size)?
            }
        };

        // Step 4: Update L2 entry on disk if changed
        if new_l2_entry != l2_entry {
            self.write_l2_entry(l2_offset, l2_index, new_l2_entry)?;
        }

        Ok(())
    }

    /// Ensure an L2 table exists for the given L1 index, allocating one if needed.
    ///
    /// If the L1 entry has the COPIED flag clear (shared with a snapshot),
    /// performs copy-on-write on the L2 table before returning.
    fn ensure_l2_table(&mut self, l1_index: L1Index) -> Result<ClusterOffset> {
        let l1_entry = self.mapper.l1_entry(l1_index)?;

        match l1_entry.l2_table_offset() {
            Some(offset) if l1_entry.is_copied() => return Ok(offset),
            Some(old_offset) => return self.cow_l2_table(l1_index, old_offset),
            None => {}
        }

        // Allocate a new L2 table cluster
        let new_l2_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;

        // Write a zeroed L2 table to disk
        let cluster_size = 1usize << self.cluster_bits;
        let zeroed = vec![0u8; cluster_size];
        self.backend.write_all_at(&zeroed, new_l2_offset.0)?;

        // Update the file size in the mapper
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Update L1 entry (with COPIED flag since refcount is 1)
        let new_l1_entry = L1Entry::with_l2_offset(new_l2_offset, true);
        self.mapper.set_l1_entry(l1_index, new_l1_entry)?;

        // Write L1 entry to disk (write-through)
        self.write_l1_entry(l1_index, new_l1_entry)?;

        Ok(new_l2_offset)
    }

    /// Copy-on-write an L2 table shared with a snapshot (L1 COPIED flag clear).
    ///
    /// Allocates a new cluster, copies the L2 table data, decrements the old
    /// cluster's refcount, and updates the L1 entry with the COPIED flag set.
    fn cow_l2_table(
        &mut self,
        l1_index: L1Index,
        old_offset: ClusterOffset,
    ) -> Result<ClusterOffset> {
        let cluster_size = 1usize << self.cluster_bits;

        // Flush dirty L2 to disk before COW reads from disk, otherwise
        // dirty modifications would be lost (the disk read would see stale data).
        self.cache.flush_single_l2(old_offset, |offset, table| {
            let mut buf = vec![0u8; cluster_size];
            // flush_single_l2 only calls us if dirty, ignore write errors
            // (they'll surface on the next explicit write).
            let _ = table.write_to(&mut buf);
            let _ = self.backend.write_all_at(&buf, offset);
        });

        // Read existing L2 table
        let mut l2_data = vec![0u8; cluster_size];
        self.backend.read_exact_at(&mut l2_data, old_offset.0)?;

        // Allocate new cluster for L2 table
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Write L2 table to new cluster
        self.backend.write_all_at(&l2_data, new_offset.0)?;

        // Decrement refcount of old L2 table
        self.refcount_manager.decrement_refcount(
            old_offset.0,
            self.backend,
            self.cache,
        )?;

        // Update L1 entry: new offset, copied=true
        let new_l1_entry = L1Entry::with_l2_offset(new_offset, true);
        self.mapper.set_l1_entry(l1_index, new_l1_entry)?;
        self.write_l1_entry(l1_index, new_l1_entry)?;

        // Evict old L2 from cache
        self.cache.evict_l2_table(old_offset);

        Ok(new_offset)
    }

    /// Write data to a newly allocated cluster (for unallocated/zero entries).
    ///
    /// The `old_bitmap` preserves subcluster state from the previous entry
    /// (e.g. zero-bits from a Zero entry). For full-cluster writes this is
    /// skipped entirely.
    fn write_to_new_cluster(
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
            let file_size = self.backend.file_size()?;
            self.mapper.set_file_size(file_size);
            off
        };

        if buf.len() == cluster_size as usize && self.crypt_context.is_none() {
            // Fast path: full cluster write, unencrypted — no subcluster handling needed
            self.data_backend.write_all_at(buf, new_offset.0)?;
            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        if buf.len() == cluster_size as usize && self.crypt_context.is_some() {
            // Full cluster write, encrypted — copy, encrypt, write
            let mut cluster_buf = buf.to_vec();
            self.crypt_context.unwrap().encrypt_cluster(new_offset.0, &mut cluster_buf)?;
            self.data_backend.write_all_at(&cluster_buf, new_offset.0)?;
            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        if old_bitmap.is_all_zero() || old_bitmap.is_all_unallocated() {
            // Fast path: no meaningful subcluster state to preserve.
            // Write the full cluster with backing data or zeros.
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
            if let Some(crypt) = self.crypt_context {
                crypt.encrypt_cluster(new_offset.0, &mut cluster_buf)?;
            }
            self.data_backend.write_all_at(&cluster_buf, new_offset.0)?;

            return Ok(L2Entry::Standard {
                host_offset: new_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            });
        }

        // Subcluster-aware path: preserve existing subcluster state.
        // For encrypted images, we must always write the full cluster.
        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;
        let mut bitmap = old_bitmap;

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

        if self.crypt_context.is_some() {
            // Encrypted: write full cluster (encryption requires full cluster)
            self.crypt_context.unwrap().encrypt_cluster(new_offset.0, &mut cluster_buf)?;
            self.data_backend.write_all_at(&cluster_buf, new_offset.0)?;
            // Mark all written subclusters as allocated
            for sc in first_sc..=last_sc {
                bitmap.set(sc, SubclusterState::Allocated);
            }
        } else {
            // Unencrypted: write only the affected subclusters
            for sc in first_sc..=last_sc {
                let sc_start = sc as u64 * sc_size;
                self.data_backend.write_all_at(
                    &cluster_buf[sc_start as usize..(sc_start + sc_size) as usize],
                    new_offset.0 + sc_start,
                )?;
                bitmap.set(sc, SubclusterState::Allocated);
            }
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
    fn write_in_place(
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
    fn cow_data_cluster(
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
                let file_size = self.backend.file_size()?;
                self.mapper.set_file_size(file_size);
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
            let file_size = self.backend.file_size()?;
            self.mapper.set_file_size(file_size);
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
    fn write_to_compressed_cluster(
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
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        self.backend.write_all_at(&decompressed, new_offset.0)?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        })
    }

    /// Write a single L1 entry to disk (write-through).
    fn write_l1_entry(&self, index: L1Index, entry: L1Entry) -> Result<()> {
        let offset = self.l1_table_offset.0 + (index.0 as u64 * 8);
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, entry.raw());
        self.backend.write_all_at(&buf, offset)?;
        Ok(())
    }

    /// Update a single L2 entry.
    ///
    /// In **WriteBack** mode: modifies the entry in the cache and marks it dirty.
    /// In **WriteThrough** mode: writes to disk and evicts the cache entry (legacy).
    fn write_l2_entry(
        &mut self,
        l2_table_offset: ClusterOffset,
        index: L2Index,
        entry: L2Entry,
    ) -> Result<()> {
        // WriteBack path: modify in-place in cache
        if let Some(cache_entry) = self.cache.get_l2_entry_mut(l2_table_offset) {
            cache_entry.value.set(index, entry)?;
            cache_entry.dirty = true;
            return Ok(());
        }

        // WriteThrough path (or WriteBack cache miss — shouldn't happen after load_l2_table):
        // write entry bytes to disk
        let geo = self.mapper.geometry();
        let entry_size = geo.l2_entry_size() as u64;
        let offset = l2_table_offset.0 + (index.0 as u64 * entry_size);

        if geo.extended_l2 {
            let mut buf = [0u8; L2_ENTRY_SIZE_EXTENDED];
            BigEndian::write_u64(&mut buf[..8], entry.encode(geo));
            BigEndian::write_u64(&mut buf[8..], entry.encode_bitmap());
            self.backend.write_all_at(&buf, offset)?;
        } else {
            let mut buf = [0u8; L2_ENTRY_SIZE];
            BigEndian::write_u64(&mut buf, entry.encode(geo));
            self.backend.write_all_at(&buf, offset)?;
        }

        // Evict so next read reloads the updated table
        self.cache.evict_l2_table(l2_table_offset);
        Ok(())
    }

    /// Load an L2 table from cache or disk.
    fn load_l2_table(&mut self, offset: ClusterOffset) -> Result<L2Table> {
        if let Some(table) = self.cache.get_l2_table(offset) {
            return Ok(table.clone());
        }

        let cluster_size = 1usize << self.cluster_bits;
        let mut buf = vec![0u8; cluster_size];
        self.backend.read_exact_at(&mut buf, offset.0)?;
        let table = L2Table::read_from(&buf, self.mapper.geometry())?;

        self.cache.insert_l2_table(offset, table.clone(), false);
        self.flush_pending_l2_evictions()?;
        Ok(table)
    }

    /// Write any dirty L2 tables that were evicted from the cache by LRU pressure.
    fn flush_pending_l2_evictions(&mut self) -> Result<()> {
        let pending = self.cache.take_pending_l2_evictions();
        let cluster_size = 1usize << self.cluster_bits;
        for (offset, table) in &pending {
            let mut buf = vec![0u8; cluster_size];
            table.write_to(&mut buf)?;
            self.backend.write_all_at(&buf, *offset)?;
        }
        Ok(())
    }

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
            let file_size = self.backend.file_size()?;
            self.mapper.set_file_size(file_size);
            host_cluster.0
        } else {
            // Check if the data fits in the remainder of the current host cluster.
            let offset_in_cluster = self.compressed_cursor & (cluster_size - 1);
            if offset_in_cluster + compressed_size > cluster_size {
                // Doesn't fit — allocate a new host cluster.
                let host_cluster =
                    self.refcount_manager
                        .allocate_cluster(self.backend, self.cache)?;
                let file_size = self.backend.file_size()?;
                self.mapper.set_file_size(file_size);
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
