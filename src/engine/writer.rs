//! QCOW2 write engine: translates guest writes into host cluster operations.
//!
//! Handles cluster allocation, L1/L2 table updates, and write-through
//! metadata persistence. Supports writing to unallocated, zero, and
//! standard (copied) clusters. Compressed clusters are decompressed
//! before applying the write.

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::compression;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, Result};
use crate::format::constants::{L2_ENTRY_SIZE, L2_ENTRY_SIZE_EXTENDED, SUBCLUSTERS_PER_CLUSTER};
use crate::format::l1::L1Entry;
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap, SubclusterState};
use crate::format::types::*;
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
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    cluster_bits: u32,
    virtual_size: u64,
    backing_image: Option<&'a mut crate::engine::image::Qcow2Image>,
    /// Byte offset for the next compressed write within a shared host cluster.
    /// Zero means no active compressed packing cluster.
    compressed_cursor: u64,
}

impl<'a> Qcow2Writer<'a> {
    /// Create a new writer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapper: &'a mut ClusterMapper,
        l1_table_offset: ClusterOffset,
        backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        cluster_bits: u32,
        virtual_size: u64,
        backing_image: Option<&'a mut crate::engine::image::Qcow2Image>,
    ) -> Self {
        Self {
            mapper,
            l1_table_offset,
            backend,
            cache,
            refcount_manager,
            cluster_bits,
            virtual_size,
            backing_image,
            compressed_cursor: 0,
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
        let extended_l2 = self.mapper.extended_l2();
        let (l1_index, l2_index, intra) = GuestOffset(guest_offset).split(self.cluster_bits, extended_l2);
        let cluster_size = 1u64 << self.cluster_bits;

        // Step 1: Ensure L2 table exists
        let l2_offset = self.ensure_l2_table(l1_index)?;

        // Step 2: Load L2 table
        let l2_table = self.load_l2_table(l2_offset)?;
        let l2_entry = l2_table.get(l2_index)?;

        // Step 3: Dispatch on L2 entry type
        let guest_cluster_offset = guest_offset - intra.0 as u64;
        let new_l2_entry = if extended_l2 {
            self.write_cluster_chunk_extended(buf, intra, cluster_size, guest_cluster_offset, l2_entry)?
        } else {
            match l2_entry {
                L2Entry::Unallocated | L2Entry::Zero { .. } => {
                    self.write_to_new_cluster(buf, intra, cluster_size, guest_cluster_offset)?
                }
                L2Entry::Standard { host_offset, copied, .. } => {
                    if copied {
                        self.write_in_place(buf, host_offset, intra, cluster_size)?;
                        l2_entry // No change to L2 entry
                    } else {
                        self.cow_data_cluster(buf, host_offset, intra, cluster_size)?
                    }
                }
                L2Entry::Compressed(descriptor) => {
                    self.write_to_compressed_cluster(buf, descriptor, intra, cluster_size)?
                }
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
    /// For partial writes, reads existing data from the backing image
    /// (if available) to preserve backing data in the non-written region.
    /// Falls back to zero-fill when there is no backing image.
    fn write_to_new_cluster(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
    ) -> Result<L2Entry> {
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;

        // Update file size in mapper
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        if buf.len() == cluster_size as usize {
            // Full cluster write — no need to read backing data
            self.backend.write_all_at(buf, new_offset.0)?;
        } else if let Some(ref mut backing) = self.backing_image {
            // Partial write with backing: read what's available from backing,
            // zero-fill anything beyond the backing's virtual size.
            let mut cluster_buf = vec![0u8; cluster_size as usize];
            let backing_vs = backing.virtual_size();
            if guest_cluster_offset < backing_vs {
                let available =
                    (backing_vs - guest_cluster_offset).min(cluster_size) as usize;
                backing.read_at(&mut cluster_buf[..available], guest_cluster_offset)?;
            }
            let start = intra.0 as usize;
            cluster_buf[start..start + buf.len()].copy_from_slice(buf);
            self.backend.write_all_at(&cluster_buf, new_offset.0)?;
        } else {
            // Partial write without backing: zero-fill, then write data
            let zeroed = vec![0u8; cluster_size as usize];
            self.backend.write_all_at(&zeroed, new_offset.0)?;
            self.backend
                .write_all_at(buf, new_offset.0 + intra.0 as u64)?;
        }

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: None,
        })
    }

    /// Overwrite data in-place in an existing standard (copied) cluster.
    fn write_in_place(
        &self,
        buf: &[u8],
        host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        _cluster_size: u64,
    ) -> Result<()> {
        self.backend
            .write_all_at(buf, host_offset.0 + intra.0 as u64)?;
        Ok(())
    }

    /// Copy-on-write a shared data cluster (refcount > 1, copied flag clear).
    ///
    /// Reads the full cluster from the old location, applies the partial write,
    /// allocates a new cluster, writes the merged data, and decrements the old
    /// cluster's refcount.
    fn cow_data_cluster(
        &mut self,
        buf: &[u8],
        old_host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        cluster_size: u64,
    ) -> Result<L2Entry> {
        // Read existing cluster data
        let mut cluster_data = vec![0u8; cluster_size as usize];
        self.backend
            .read_exact_at(&mut cluster_data, old_host_offset.0)?;

        // Apply partial write
        let start = intra.0 as usize;
        cluster_data[start..start + buf.len()].copy_from_slice(buf);

        // Allocate new cluster
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Write merged data to new cluster
        self.backend.write_all_at(&cluster_data, new_offset.0)?;

        // Decrement refcount of old cluster
        self.refcount_manager.decrement_refcount(
            old_host_offset.0,
            self.backend,
            self.cache,
        )?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: None,
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
        // Read and decompress the full cluster
        let compressed_size = descriptor.compressed_size as usize;
        let mut compressed_buf = vec![0u8; compressed_size];
        self.backend
            .read_exact_at(&mut compressed_buf, descriptor.host_offset)?;

        let mut decompressed = compression::decompress_cluster(
            &compressed_buf,
            cluster_size as usize,
            0, // guest_offset for error context
        )?;

        // Apply the write on top of the decompressed data
        let start = intra.0 as usize;
        decompressed[start..start + buf.len()].copy_from_slice(buf);

        // Allocate a new cluster and write the full decompressed+modified data
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;

        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        self.backend.write_all_at(&decompressed, new_offset.0)?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: None,
        })
    }

    // ---- Extended L2 (subcluster-granular) write methods ----

    /// Dispatch a single-cluster write in extended L2 mode.
    fn write_cluster_chunk_extended(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
        l2_entry: L2Entry,
    ) -> Result<L2Entry> {
        match l2_entry {
            L2Entry::Unallocated => {
                self.write_to_new_cluster_extended(
                    buf, intra, cluster_size, guest_cluster_offset, None,
                )
            }
            L2Entry::Zero { preallocated_offset, subclusters } => {
                // Zero entry: allocate a new cluster.  Preserve zero-bits for
                // non-written subclusters so they don't fall to backing.
                let result = self.write_to_new_cluster_extended(
                    buf, intra, cluster_size, guest_cluster_offset, subclusters,
                )?;
                // Decrement refcount of the preallocated cluster if it existed
                if let Some(prealloc) = preallocated_offset {
                    self.refcount_manager.decrement_refcount(
                        prealloc.0,
                        self.backend,
                        self.cache,
                    )?;
                }
                Ok(result)
            }
            L2Entry::Standard { host_offset, copied, subclusters } => {
                let bitmap = subclusters.unwrap_or_else(SubclusterBitmap::all_allocated);
                if copied {
                    self.write_in_place_extended(buf, host_offset, intra, cluster_size, bitmap)
                } else {
                    self.cow_data_cluster_extended(
                        buf, host_offset, intra, cluster_size, bitmap,
                    )
                }
            }
            L2Entry::Compressed(descriptor) => {
                self.write_to_compressed_cluster_extended(buf, descriptor, intra, cluster_size)
            }
        }
    }

    /// Allocate a new cluster and write data with subcluster-granular bitmap.
    ///
    /// For extended L2: only the written bytes go to the host cluster.
    /// The bitmap marks written subclusters as Allocated; zero-bits from
    /// a previous `Zero` entry are preserved so those subclusters don't
    /// fall through to backing.
    fn write_to_new_cluster_extended(
        &mut self,
        buf: &[u8],
        intra: IntraClusterOffset,
        cluster_size: u64,
        guest_cluster_offset: u64,
        old_subclusters: Option<SubclusterBitmap>,
    ) -> Result<L2Entry> {
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;

        // Compute the range of subclusters we're writing to.
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        // Build the new bitmap: start from old (preserves zero-bits) or empty.
        let mut bitmap = old_subclusters.unwrap_or_else(SubclusterBitmap::all_unallocated);

        // For subclusters that are Unallocated in the old bitmap and overlap
        // with our write, we need to read backing data for the non-written
        // parts of those subclusters.  Build the full cluster buffer.
        let mut cluster_buf = vec![0u8; cluster_size as usize];

        // Copy data from backing for Unallocated subclusters within the write
        // range that are only partially covered by the write.
        if let Some(ref mut backing) = self.backing_image {
            let backing_vs = backing.virtual_size();
            for sc in first_sc..=last_sc {
                if matches!(bitmap.get(sc), SubclusterState::Unallocated) {
                    let sc_start = sc as u64 * sc_size;
                    let sc_end = sc_start + sc_size;
                    let write_covers_sc = start <= sc_start && end >= sc_end;
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

        // Write only the affected subclusters to the host cluster.
        for sc in first_sc..=last_sc {
            let sc_start = sc as u64 * sc_size;
            self.backend.write_all_at(
                &cluster_buf[sc_start as usize..(sc_start + sc_size) as usize],
                new_offset.0 + sc_start,
            )?;
            bitmap.set(sc, SubclusterState::Allocated);
        }

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: Some(bitmap),
        })
    }

    /// Write in-place to an existing copied cluster (extended L2).
    ///
    /// Updates the subcluster bitmap to mark written subclusters as Allocated.
    /// For subclusters that were previously Zero or Unallocated and are only
    /// partially covered by the write, we must initialize the unwritten part
    /// (zeros for Zero state, existing host data for Allocated).
    fn write_in_place_extended(
        &mut self,
        buf: &[u8],
        host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        cluster_size: u64,
        mut bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        // For partially-covered subclusters that were Zero, we must write
        // zeros to the host for the non-written part before overlaying.
        for sc in first_sc..=last_sc {
            let state = bitmap.get(sc);
            let sc_start = sc as u64 * sc_size;
            let sc_end = sc_start + sc_size;
            let write_covers_sc = start <= sc_start && end >= sc_end;

            if !write_covers_sc && matches!(state, SubclusterState::Zero | SubclusterState::Unallocated) {
                // Build the subcluster from zeros, overlay write data, write whole SC
                let mut sc_buf = vec![0u8; sc_size as usize];
                let overlap_start = start.max(sc_start);
                let overlap_end = end.min(sc_end);
                let buf_off = (overlap_start - start) as usize;
                let sc_off = (overlap_start - sc_start) as usize;
                let overlap_len = (overlap_end - overlap_start) as usize;
                sc_buf[sc_off..sc_off + overlap_len]
                    .copy_from_slice(&buf[buf_off..buf_off + overlap_len]);
                self.backend.write_all_at(&sc_buf, host_offset.0 + sc_start)?;
            }
        }

        // Write the user data (for fully-covered SCs and the non-edge parts)
        self.backend
            .write_all_at(buf, host_offset.0 + intra.0 as u64)?;

        // Mark written subclusters as Allocated
        for sc in first_sc..=last_sc {
            bitmap.set(sc, SubclusterState::Allocated);
        }

        Ok(L2Entry::Standard {
            host_offset,
            copied: true,
            subclusters: Some(bitmap),
        })
    }

    /// COW a shared data cluster in extended L2 mode.
    ///
    /// Only copies subclusters that were Allocated; preserves Zero-bits.
    /// Writes the new user data and updates the bitmap accordingly.
    fn cow_data_cluster_extended(
        &mut self,
        buf: &[u8],
        old_host_offset: ClusterOffset,
        intra: IntraClusterOffset,
        cluster_size: u64,
        old_bitmap: SubclusterBitmap,
    ) -> Result<L2Entry> {
        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let start = intra.0 as u64;
        let end = start + buf.len() as u64;
        let first_sc = (start / sc_size) as u32;
        let last_sc = ((end - 1) / sc_size) as u32;

        // Allocate new cluster
        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        // Build new bitmap from old, copying only Allocated subclusters
        let mut new_bitmap = SubclusterBitmap::all_unallocated();
        for sc in 0..SUBCLUSTERS_PER_CLUSTER {
            match old_bitmap.get(sc) {
                SubclusterState::Allocated => {
                    // Copy this subcluster's data from old to new
                    let sc_start = sc as u64 * sc_size;
                    let mut sc_buf = vec![0u8; sc_size as usize];
                    self.backend.read_exact_at(&mut sc_buf, old_host_offset.0 + sc_start)?;
                    self.backend.write_all_at(&sc_buf, new_offset.0 + sc_start)?;
                    new_bitmap.set(sc, SubclusterState::Allocated);
                }
                SubclusterState::Zero => {
                    // Preserve zero-bit — don't copy data, don't fall to backing
                    new_bitmap.set(sc, SubclusterState::Zero);
                }
                SubclusterState::Unallocated => {
                    // Stays unallocated — falls to backing on read
                }
                SubclusterState::Invalid => {
                    // Shouldn't happen; treat as unallocated
                }
            }
        }

        // Write the user data
        self.backend
            .write_all_at(buf, new_offset.0 + start)?;

        // Mark written subclusters as Allocated
        for sc in first_sc..=last_sc {
            new_bitmap.set(sc, SubclusterState::Allocated);
        }

        // Decrement refcount of old cluster
        self.refcount_manager.decrement_refcount(
            old_host_offset.0,
            self.backend,
            self.cache,
        )?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: Some(new_bitmap),
        })
    }

    /// Handle writing to a compressed cluster in extended L2 mode.
    ///
    /// Decompresses, applies write, allocates new cluster.
    /// All subclusters become Allocated since we have the full decompressed data.
    fn write_to_compressed_cluster_extended(
        &mut self,
        buf: &[u8],
        descriptor: crate::format::compressed::CompressedClusterDescriptor,
        intra: IntraClusterOffset,
        cluster_size: u64,
    ) -> Result<L2Entry> {
        let compressed_size = descriptor.compressed_size as usize;
        let mut compressed_buf = vec![0u8; compressed_size];
        self.backend
            .read_exact_at(&mut compressed_buf, descriptor.host_offset)?;

        let mut decompressed = compression::decompress_cluster(
            &compressed_buf,
            cluster_size as usize,
            0,
        )?;

        let start = intra.0 as usize;
        decompressed[start..start + buf.len()].copy_from_slice(buf);

        let new_offset = self.refcount_manager.allocate_cluster(
            self.backend,
            self.cache,
        )?;
        let file_size = self.backend.file_size()?;
        self.mapper.set_file_size(file_size);

        self.backend.write_all_at(&decompressed, new_offset.0)?;

        Ok(L2Entry::Standard {
            host_offset: new_offset,
            copied: true,
            subclusters: Some(SubclusterBitmap::all_allocated()),
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

    /// Write a single L2 entry to disk and evict the L2 table from cache.
    fn write_l2_entry(
        &mut self,
        l2_table_offset: ClusterOffset,
        index: L2Index,
        entry: L2Entry,
    ) -> Result<()> {
        if self.mapper.extended_l2() {
            let entry_size = L2_ENTRY_SIZE_EXTENDED as u64;
            let offset = l2_table_offset.0 + (index.0 as u64 * entry_size);
            let mut buf = [0u8; L2_ENTRY_SIZE_EXTENDED];
            let encoded = entry.encode(self.cluster_bits);
            // In extended mode, bit 0 of the first word must be 0
            BigEndian::write_u64(&mut buf[..8], encoded & !1);
            BigEndian::write_u64(
                &mut buf[8..],
                entry.subclusters().map_or(0, |b| b.0),
            );
            self.backend.write_all_at(&buf, offset)?;
        } else {
            let offset = l2_table_offset.0 + (index.0 as u64 * L2_ENTRY_SIZE as u64);
            let mut buf = [0u8; L2_ENTRY_SIZE];
            BigEndian::write_u64(&mut buf, entry.encode(self.cluster_bits));
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
        let table = L2Table::read_from(&buf, self.cluster_bits, self.mapper.extended_l2())?;

        self.cache.insert_l2_table(offset, table.clone());
        Ok(table)
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
            GuestOffset(guest_offset).split(self.cluster_bits, self.mapper.extended_l2());

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

        // Write compressed data.
        self.backend
            .write_all_at(compressed_data, write_offset)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cache::CacheConfig;
    use crate::engine::refcount_manager::RefcountManager;
    use crate::format::constants::*;
    use crate::format::l1::{L1Entry, L1Table};
    use crate::io::MemoryBackend;

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;
    const VIRTUAL_SIZE: u64 = 1 << 30; // 1 GiB

    /// Standard test image layout:
    /// - Cluster 0: Header
    /// - Cluster 1: L1 table (1 entry)
    /// - Cluster 2: Refcount table (1 cluster)
    /// - Cluster 3: Refcount block 0
    /// - Cluster 4+: Free
    struct TestSetup {
        backend: MemoryBackend,
        mapper: ClusterMapper,
        cache: MetadataCache,
        refcount_manager: RefcountManager,
        l1_table_offset: ClusterOffset,
    }

    fn make_header() -> crate::format::header::Header {
        crate::format::header::Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: CLUSTER_BITS,
            virtual_size: VIRTUAL_SIZE,
            crypt_method: 0,
            l1_table_entries: 1,
            l1_table_offset: ClusterOffset(CLUSTER_SIZE as u64),
            refcount_table_offset: ClusterOffset(2 * CLUSTER_SIZE as u64),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: crate::format::feature_flags::IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order: 4,
            header_length: 104,
            compression_type: 0,
        }
    }

    fn setup() -> TestSetup {
        setup_with_l2(None)
    }

    /// Setup with an optional pre-populated L2 table.
    /// If l2_entries is Some, an L2 table is placed at cluster 4,
    /// and the L1 entry points to it.
    fn setup_with_l2(l2_entries: Option<&[(u32, L2Entry)]>) -> TestSetup {
        let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;

        let initial_clusters = if l2_entries.is_some() { 5 } else { 4 };
        let mut data = vec![0u8; initial_clusters * CLUSTER_SIZE];

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: set refcounts for clusters 0-3 (or 0-4) to 1
        for i in 0..initial_clusters {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }

        // L1 table
        let l1_entry = if l2_entries.is_some() {
            L1Entry::with_l2_offset(ClusterOffset(4 * CLUSTER_SIZE as u64), true)
        } else {
            L1Entry::unallocated()
        };
        BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

        // L2 table at cluster 4 (if requested)
        if let Some(entries) = l2_entries {
            let l2_base = 4 * CLUSTER_SIZE;
            for &(index, entry) in entries {
                let offset = l2_base + index as usize * L2_ENTRY_SIZE;
                BigEndian::write_u64(&mut data[offset..], entry.encode(CLUSTER_BITS));
            }
        }

        let backend = MemoryBackend::new(data);

        // Build L1 table
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let file_size = backend.file_size().unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, file_size, false);

        let header = make_header();
        let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
        let cache = MetadataCache::new(CacheConfig::default());

        TestSetup {
            backend,
            mapper,
            cache,
            refcount_manager,
            l1_table_offset: l1_offset,
        }
    }

    fn make_writer<'a>(s: &'a mut TestSetup) -> Qcow2Writer<'a> {
        Qcow2Writer::new(
            &mut s.mapper,
            s.l1_table_offset,
            &s.backend,
            &mut s.cache,
            &mut s.refcount_manager,
            CLUSTER_BITS,
            VIRTUAL_SIZE,
            None,
        )
    }

    // ---- Basic write tests ----

    #[test]
    fn write_to_unallocated_allocates_cluster() {
        let mut s = setup();
        let data = vec![0xAB; 512];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // L1 should now point to an L2 table
        assert!(!s.mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());

        // Read back via backend to verify data
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();

        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        let l2_entry = l2_table.get(L2Index(0)).unwrap();

        if let L2Entry::Standard { host_offset, copied, .. } = l2_entry {
            assert!(copied);
            let mut read_back = vec![0u8; 512];
            s.backend
                .read_exact_at(&mut read_back, host_offset.0)
                .unwrap();
            assert_eq!(read_back, data);
        } else {
            panic!("expected Standard L2 entry, got {l2_entry:?}");
        }
    }

    #[test]
    fn write_full_cluster() {
        let mut s = setup();
        let data = vec![0xCD; CLUSTER_SIZE];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // Verify round-trip
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
            let mut read_back = vec![0u8; CLUSTER_SIZE];
            s.backend
                .read_exact_at(&mut read_back, host_offset.0)
                .unwrap();
            assert_eq!(read_back, data);
        } else {
            panic!("expected Standard L2 entry");
        }
    }

    #[test]
    fn write_in_place_to_standard_copied() {
        let data_cluster = 5 * CLUSTER_SIZE as u64;
        let l2_entry = L2Entry::Standard {
            host_offset: ClusterOffset(data_cluster),
            copied: true,
            subclusters: None,
        };
        let mut s = setup_with_l2(Some(&[(0, l2_entry)]));

        // Write initial data at the data cluster location
        let initial = vec![0xFF; CLUSTER_SIZE];
        s.backend.write_all_at(&initial, data_cluster).unwrap();

        // Set refcount for cluster 5 to 1 (consistent with L2 pointing here)
        s.refcount_manager
            .set_refcount(data_cluster, 1, &s.backend, &mut s.cache)
            .unwrap();

        // Partial write at offset 100 within the first guest cluster
        let patch = vec![0x42; 64];
        make_writer(&mut s).write_at(&patch, 100).unwrap();

        // Verify in-place write
        let mut read_back = vec![0u8; CLUSTER_SIZE];
        s.backend
            .read_exact_at(&mut read_back, data_cluster)
            .unwrap();
        assert_eq!(&read_back[100..164], &patch[..]);
        assert_eq!(read_back[0], 0xFF); // Unchanged
        assert_eq!(read_back[164], 0xFF); // Unchanged
    }

    #[test]
    fn write_to_zero_cluster_allocates_new() {
        let l2_entry = L2Entry::Zero {
            preallocated_offset: None,
            subclusters: None,
        };
        let mut s = setup_with_l2(Some(&[(0, l2_entry)]));

        let data = vec![0xBB; 256];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // The L2 entry should now be Standard
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, copied, .. } => {
                assert!(copied);
                let mut read_back = vec![0u8; CLUSTER_SIZE];
                s.backend
                    .read_exact_at(&mut read_back, host_offset.0)
                    .unwrap();
                assert_eq!(&read_back[..256], &data[..]);
                // Rest should be zeros (from zero-fill)
                assert!(read_back[256..].iter().all(|&b| b == 0));
            }
            other => panic!("expected Standard, got {other:?}"),
        }
    }

    /// Build a custom setup with a pre-existing data cluster for COW tests.
    ///
    /// Layout: 0=header, 1=L1, 2=reftable, 3=refblock, 4=L2, 5=data cluster.
    /// The data cluster at 5 has refcount=2 (shared) and L2 entry has copied=false.
    fn setup_with_shared_data(pattern: u8) -> TestSetup {
        let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;
        let l2_offset = 4 * CLUSTER_SIZE;
        let data_offset = 5 * CLUSTER_SIZE;

        let mut data = vec![0u8; 6 * CLUSTER_SIZE];

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-4 refcount=1, cluster 5 refcount=2
        for i in 0..5 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }
        BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

        // Data cluster: fill with pattern
        data[data_offset..data_offset + CLUSTER_SIZE].fill(pattern);

        // L1 table: entry 0 → L2 at cluster 4, copied=true
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), true);
        BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

        // L2 table: entry 0 → data at cluster 5, copied=false (shared)
        let l2_entry = L2Entry::Standard {
            host_offset: ClusterOffset(data_offset as u64),
            copied: false,
            subclusters: None,
        };
        BigEndian::write_u64(
            &mut data[l2_offset..],
            l2_entry.encode(CLUSTER_BITS),
        );

        let backend = MemoryBackend::new(data);

        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();

        let file_size = backend.file_size().unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, file_size, false);

        let header = make_header();
        let refcount_manager =
            RefcountManager::load(&backend, &header).unwrap();
        let cache = MetadataCache::new(CacheConfig::default());

        TestSetup {
            backend,
            mapper,
            cache,
            refcount_manager,
            l1_table_offset: l1_offset,
        }
    }

    #[test]
    fn cow_shared_data_cluster_allocates_new() {
        let mut s = setup_with_shared_data(0xAA);

        let data_offset = 5 * CLUSTER_SIZE as u64;

        // Verify initial refcount is 2
        let rc = s
            .refcount_manager
            .get_refcount(data_offset, &s.backend, &mut s.cache)
            .unwrap();
        assert_eq!(rc, 2, "shared cluster should start with refcount 2");

        // Write a small amount of data — should trigger COW
        let write_data = vec![0x11; 64];
        make_writer(&mut s).write_at(&write_data, 0).unwrap();

        // Old cluster refcount should have been decremented from 2 to 1
        let old_rc = s
            .refcount_manager
            .get_refcount(data_offset, &s.backend, &mut s.cache)
            .unwrap();
        assert_eq!(old_rc, 1, "old cluster refcount should be decremented");
    }

    #[test]
    fn write_beyond_virtual_size_rejected() {
        let mut s = setup();
        let data = vec![0x00; 64];
        let result = make_writer(&mut s).write_at(&data, VIRTUAL_SIZE);
        assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
    }

    #[test]
    fn write_spanning_beyond_virtual_size_rejected() {
        let mut s = setup();
        let data = vec![0x00; 128];
        let result = make_writer(&mut s).write_at(&data, VIRTUAL_SIZE - 64);
        assert!(matches!(result, Err(Error::OffsetBeyondDiskSize { .. })));
    }

    #[test]
    fn write_spanning_two_clusters() {
        let mut s = setup();
        // Write starting near end of cluster 0, spanning into cluster 1
        let offset = CLUSTER_SIZE as u64 - 100; // virtual offset
        // This maps to L1[0], L2[0] (last 100 bytes) + L1[0], L2[1] (first 156 bytes)
        let data = vec![0xEE; 256];
        make_writer(&mut s).write_at(&data, offset).unwrap();

        // Both L2 entries [0] and [1] should now be allocated
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        let host0 = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, copied: true, .. } => host_offset,
            other => panic!("expected Standard+copied for cluster 0, got {other:?}"),
        };
        let host1 = match l2_table.get(L2Index(1)).unwrap() {
            L2Entry::Standard { host_offset, copied: true, .. } => host_offset,
            other => panic!("expected Standard+copied for cluster 1, got {other:?}"),
        };

        // Verify data in cluster 0: last 100 bytes should be 0xEE
        let mut tail = vec![0u8; 100];
        s.backend
            .read_exact_at(&mut tail, host0.0 + CLUSTER_SIZE as u64 - 100)
            .unwrap();
        assert!(tail.iter().all(|&b| b == 0xEE), "cluster 0 tail should be 0xEE");

        // Verify data in cluster 1: first 156 bytes should be 0xEE
        let mut head = vec![0u8; 156];
        s.backend.read_exact_at(&mut head, host1.0).unwrap();
        assert!(head.iter().all(|&b| b == 0xEE), "cluster 1 head should be 0xEE");
    }

    #[test]
    fn write_empty_buffer_is_noop() {
        let mut s = setup();
        make_writer(&mut s).write_at(&[], 0).unwrap();
        // L1 should still be unallocated
        assert!(s.mapper.l1_entry(L1Index(0)).unwrap().is_unallocated());
    }

    #[test]
    fn partial_write_to_unallocated_zero_fills_rest() {
        let mut s = setup();
        let data = vec![0xAA; 100];
        make_writer(&mut s).write_at(&data, 200).unwrap();

        // Read the full cluster and verify zero-fill
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
            let mut cluster_data = vec![0u8; CLUSTER_SIZE];
            s.backend
                .read_exact_at(&mut cluster_data, host_offset.0)
                .unwrap();
            assert!(cluster_data[..200].iter().all(|&b| b == 0));
            assert_eq!(&cluster_data[200..300], &data[..]);
            assert!(cluster_data[300..].iter().all(|&b| b == 0));
        } else {
            panic!("expected Standard L2 entry");
        }
    }

    #[test]
    fn write_allocates_refcounted_clusters() {
        let mut s = setup();
        let data = vec![0x55; CLUSTER_SIZE];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // The newly allocated L2 table and data cluster should have refcount 1
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();

        let rc = s
            .refcount_manager
            .get_refcount(l2_offset.0, &s.backend, &mut s.cache)
            .unwrap();
        assert_eq!(rc, 1, "L2 table should have refcount 1");
    }

    #[test]
    fn write_through_l1_persisted_to_disk() {
        let mut s = setup();
        let data = vec![0x77; 64];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // Read L1 entry directly from the backend
        let mut l1_buf = [0u8; 8];
        s.backend
            .read_exact_at(&mut l1_buf, CLUSTER_SIZE as u64)
            .unwrap();
        let raw = BigEndian::read_u64(&l1_buf);
        let l1_entry = L1Entry::from_raw(raw);
        assert!(!l1_entry.is_unallocated());
    }

    #[test]
    fn write_through_l2_persisted_to_disk() {
        let mut s = setup();
        let data = vec![0x88; 64];
        make_writer(&mut s).write_at(&data, 0).unwrap();

        // Get L2 table offset from L1
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();

        // Read L2 entry 0 directly from backend
        let mut l2_entry_buf = [0u8; 8];
        s.backend
            .read_exact_at(&mut l2_entry_buf, l2_offset.0)
            .unwrap();
        let raw = BigEndian::read_u64(&l2_entry_buf);
        let l2_entry = L2Entry::decode(raw, CLUSTER_BITS);
        assert!(matches!(
            l2_entry,
            L2Entry::Standard { copied: true, .. }
        ));
    }

    #[test]
    fn multiple_writes_to_same_cluster_reuse_allocation() {
        let mut s = setup();

        // First write
        let data1 = vec![0xAA; 100];
        make_writer(&mut s).write_at(&data1, 0).unwrap();

        // Get the allocated data cluster offset
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        let first_host_offset = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, .. } => host_offset,
            other => panic!("expected Standard, got {other:?}"),
        };

        // Second write to same cluster should reuse (in-place write)
        let data2 = vec![0xBB; 100];
        make_writer(&mut s).write_at(&data2, 200).unwrap();

        // Verify same data cluster offset
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        let second_host_offset = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, .. } => host_offset,
            other => panic!("expected Standard, got {other:?}"),
        };
        assert_eq!(first_host_offset, second_host_offset);

        // Verify both writes present
        let mut cluster_data = vec![0u8; CLUSTER_SIZE];
        s.backend
            .read_exact_at(&mut cluster_data, first_host_offset.0)
            .unwrap();
        assert_eq!(&cluster_data[..100], &data1[..]);
        assert_eq!(&cluster_data[200..300], &data2[..]);
    }

    // ---- COW tests ----

    #[test]
    fn cow_preserves_existing_data_on_partial_write() {
        let mut s = setup_with_shared_data(0xAA);

        // Write 64 bytes at offset 100 within the cluster
        let write_data = vec![0x11; 64];
        make_writer(&mut s).write_at(&write_data, 100).unwrap();

        // Find the new data cluster from the L2 table
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        let new_host = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, .. } => host_offset,
            other => panic!("expected Standard, got {other:?}"),
        };

        // New cluster should NOT be at the old data offset (cluster 5)
        assert_ne!(new_host.0, 5 * CLUSTER_SIZE as u64);

        // Read the new cluster and verify contents
        let mut cluster_data = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut cluster_data, new_host.0).unwrap();

        // Bytes 0-99 should be preserved from old cluster (0xAA)
        assert!(cluster_data[..100].iter().all(|&b| b == 0xAA));
        // Bytes 100-163 should be our write (0x11)
        assert_eq!(&cluster_data[100..164], &write_data[..]);
        // Bytes 164+ should be preserved from old cluster (0xAA)
        assert!(cluster_data[164..CLUSTER_SIZE].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn cow_sets_copied_flag_on_new_entry() {
        let mut s = setup_with_shared_data(0xBB);

        make_writer(&mut s).write_at(&[0x22; 16], 0).unwrap();

        // Read L2 entry from disk
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { copied: true, .. } => {}
            other => panic!("expected Standard{{copied:true}}, got {other:?}"),
        }
    }

    #[test]
    fn cow_full_cluster_write() {
        let mut s = setup_with_shared_data(0xCC);
        let data_offset = 5 * CLUSTER_SIZE as u64;

        // Full cluster write should still COW (allocate new, decrement old)
        let write_data = vec![0x33; CLUSTER_SIZE];
        make_writer(&mut s).write_at(&write_data, 0).unwrap();

        let old_rc = s
            .refcount_manager
            .get_refcount(data_offset, &s.backend, &mut s.cache)
            .unwrap();
        assert_eq!(old_rc, 1, "old cluster refcount should be decremented");

        // Verify new cluster has the written data
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        if let L2Entry::Standard { host_offset, .. } = l2_table.get(L2Index(0)).unwrap() {
            let mut cluster_data = vec![0u8; CLUSTER_SIZE];
            s.backend.read_exact_at(&mut cluster_data, host_offset.0).unwrap();
            assert!(cluster_data.iter().all(|&b| b == 0x33));
        }
    }

    #[test]
    fn cow_second_write_is_in_place() {
        let mut s = setup_with_shared_data(0xDD);

        // First write triggers COW
        make_writer(&mut s).write_at(&[0x44; 64], 0).unwrap();

        // Get the new cluster offset
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        let first_host = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, copied, .. } => {
                assert!(copied, "should be copied after COW");
                host_offset
            }
            other => panic!("expected Standard, got {other:?}"),
        };

        // Second write should be in-place (same host offset)
        make_writer(&mut s).write_at(&[0x55; 64], 100).unwrap();

        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        let second_host = match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, .. } => host_offset,
            other => panic!("expected Standard, got {other:?}"),
        };
        assert_eq!(first_host, second_host, "second write should reuse cluster");
    }

    #[test]
    fn cow_l2_table_when_l1_not_copied() {
        // Create a setup where L1 entry has copied=false (shared L2 table)
        let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;
        let l2_offset = 4 * CLUSTER_SIZE;

        let mut data = vec![0u8; 5 * CLUSTER_SIZE];

        // Refcount table: entry 0 → block at cluster 3
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-3 refcount=1, cluster 4 (L2 table) refcount=2
        for i in 0..4 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }
        BigEndian::write_u16(&mut data[rb_offset + 4 * 2..], 2);

        // L1 entry: points to L2 table, copied=FALSE (shared with snapshot)
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset as u64), false);
        BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

        // L2 table: entry 0 unallocated (for simplicity)
        // (We'll write to a new cluster)

        let backend = MemoryBackend::new(data);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
        let file_size = backend.file_size().unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, file_size, false);
        let header = make_header();
        let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
        let cache = MetadataCache::new(CacheConfig::default());

        let mut s = TestSetup {
            backend,
            mapper,
            cache,
            refcount_manager,
            l1_table_offset: l1_offset,
        };

        // Write should trigger L2 table COW first, then allocate data cluster
        make_writer(&mut s).write_at(&[0x77; 64], 0).unwrap();

        // L1 entry should now be copied=true and point to a new L2 table
        let new_l1 = s.mapper.l1_entry(L1Index(0)).unwrap();
        assert!(new_l1.is_copied(), "L1 should be copied after L2 COW");
        assert_ne!(
            new_l1.l2_table_offset().unwrap().0,
            l2_offset as u64,
            "L1 should point to new L2 table"
        );

        // Old L2 table refcount should have been decremented from 2 to 1
        let old_l2_rc = s
            .refcount_manager
            .get_refcount(l2_offset as u64, &s.backend, &mut s.cache)
            .unwrap();
        assert_eq!(old_l2_rc, 1, "old L2 table refcount should be decremented");
    }

    #[test]
    fn cow_l2_table_preserves_existing_entries() {
        // Setup: L2 table at cluster 4 with existing entry, L1 copied=false
        let l1_offset = ClusterOffset(CLUSTER_SIZE as u64);
        let rt_offset = 2 * CLUSTER_SIZE;
        let rb_offset = 3 * CLUSTER_SIZE;
        let l2_offset_val = 4 * CLUSTER_SIZE;
        let data_offset = 5 * CLUSTER_SIZE;

        let mut data = vec![0u8; 6 * CLUSTER_SIZE];

        // Refcount table
        BigEndian::write_u64(&mut data[rt_offset..], rb_offset as u64);

        // Refcount block: clusters 0-3 ref=1, cluster 4 (L2) ref=2, cluster 5 (data) ref=2
        for i in 0..4 {
            BigEndian::write_u16(&mut data[rb_offset + i * 2..], 1);
        }
        BigEndian::write_u16(&mut data[rb_offset + 4 * 2..], 2);
        BigEndian::write_u16(&mut data[rb_offset + 5 * 2..], 2);

        // L1: copied=false (shared with snapshot)
        let l1_entry = L1Entry::with_l2_offset(ClusterOffset(l2_offset_val as u64), false);
        BigEndian::write_u64(&mut data[CLUSTER_SIZE..], l1_entry.raw());

        // L2 table: entry 1 → data at cluster 5, copied=false
        let l2_entry = L2Entry::Standard {
            host_offset: ClusterOffset(data_offset as u64),
            copied: false,
            subclusters: None,
        };
        BigEndian::write_u64(
            &mut data[l2_offset_val + 8..], // entry 1
            l2_entry.encode(CLUSTER_BITS),
        );

        // Data cluster: fill with pattern
        data[data_offset..data_offset + CLUSTER_SIZE].fill(0xEE);

        let backend = MemoryBackend::new(data);
        let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
        BigEndian::write_u64(&mut l1_buf, l1_entry.raw());
        let l1_table = L1Table::read_from(&l1_buf, 1).unwrap();
        let file_size = backend.file_size().unwrap();
        let mapper = ClusterMapper::new(l1_table, CLUSTER_BITS, file_size, false);
        let header = make_header();
        let refcount_manager = RefcountManager::load(&backend, &header).unwrap();
        let cache = MetadataCache::new(CacheConfig::default());

        let mut s = TestSetup {
            backend,
            mapper,
            cache,
            refcount_manager,
            l1_table_offset: l1_offset,
        };

        // Write to virtual cluster 1 (L2 index 1) — should COW the L2 table,
        // then COW the data cluster
        let write_data = vec![0xFF; 64];
        make_writer(&mut s)
            .write_at(&write_data, CLUSTER_SIZE as u64)
            .unwrap();

        // The new L2 table should exist at a new offset
        let new_l1 = s.mapper.l1_entry(L1Index(0)).unwrap();
        let new_l2_offset = new_l1.l2_table_offset().unwrap();
        assert_ne!(new_l2_offset.0, l2_offset_val as u64);

        // Read the new L2 table — entry 0 should still be unallocated
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, new_l2_offset.0).unwrap();
        let new_l2 = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();
        assert!(matches!(new_l2.get(L2Index(0)).unwrap(), L2Entry::Unallocated));

        // Entry 1 should point to a NEW data cluster (COW'd), with copied=true
        match new_l2.get(L2Index(1)).unwrap() {
            L2Entry::Standard { host_offset, copied, .. } => {
                assert!(copied, "COW'd entry should be copied");
                assert_ne!(host_offset.0, data_offset as u64, "should be a new cluster");
            }
            other => panic!("expected Standard, got {other:?}"),
        }
    }

    // ---- Overflow and compressed write tests ----

    #[test]
    fn write_u64_overflow_rejected() {
        let mut s = setup();
        // guest_offset near u64::MAX + buf.len() would overflow
        let buf = vec![0xAA; 100];
        let result = make_writer(&mut s).write_at(&buf, u64::MAX - 10);
        assert!(result.is_err(), "should reject write that overflows u64");
    }

    #[test]
    fn write_to_compressed_cluster_decompresses_and_reallocates() {
        use crate::engine::compression;
        use crate::format::compressed::CompressedClusterDescriptor;

        // Create setup with an L2 table (at cluster 4)
        let mut s = setup();

        // First, write a full cluster so we get an L2 table allocated
        let original_data = vec![0xAA; CLUSTER_SIZE];
        make_writer(&mut s).write_at(&original_data, 0).unwrap();

        // Now find where the data cluster landed
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();

        // Compress the original data
        let compressed = compression::compress_cluster(&original_data, CLUSTER_SIZE)
            .unwrap()
            .expect("all-0xAA should compress");

        // Allocate a cluster for the compressed data
        let comp_host = s
            .refcount_manager
            .allocate_cluster(&s.backend, &mut s.cache)
            .unwrap();
        let file_size = s.backend.file_size().unwrap();
        s.mapper.set_file_size(file_size);

        // Write compressed data to backend, padded to sector alignment
        let sector_aligned = ((compressed.len() + 511) & !511).max(512);
        let mut padded = vec![0u8; sector_aligned];
        padded[..compressed.len()].copy_from_slice(&compressed);
        s.backend.write_all_at(&padded, comp_host.0).unwrap();

        // Patch L2 entry 0 to be Compressed
        let descriptor = CompressedClusterDescriptor {
            host_offset: comp_host.0,
            compressed_size: sector_aligned as u64,
        };
        let comp_entry = L2Entry::Compressed(descriptor);
        let encoded = comp_entry.encode(CLUSTER_BITS);
        let entry_offset = l2_offset.0; // entry index 0
        let mut entry_buf = [0u8; 8];
        BigEndian::write_u64(&mut entry_buf, encoded);
        s.backend.write_all_at(&entry_buf, entry_offset).unwrap();
        s.cache.evict_l2_table(l2_offset);

        // Now write 64 bytes of 0xBB at offset 100 within that compressed cluster
        let write_data = vec![0xBB; 64];
        make_writer(&mut s).write_at(&write_data, 100).unwrap();

        // The L2 entry should now be Standard (decompressed + reallocated)
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_off = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_off.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Standard { host_offset, copied, .. } => {
                assert!(copied);
                // Read back the full cluster
                let mut readback = vec![0u8; CLUSTER_SIZE];
                s.backend.read_exact_at(&mut readback, host_offset.0).unwrap();
                // Bytes 0..100 should be 0xAA (original)
                assert!(readback[..100].iter().all(|&b| b == 0xAA));
                // Bytes 100..164 should be 0xBB (our write)
                assert!(readback[100..164].iter().all(|&b| b == 0xBB));
                // Bytes 164.. should be 0xAA (original)
                assert!(readback[164..].iter().all(|&b| b == 0xAA));
            }
            other => panic!("expected Standard after write to compressed, got {other:?}"),
        }
    }

    #[test]
    fn write_compressed_at_packs_cluster() {
        use crate::engine::compression;

        let mut s = setup();

        // Compress a full cluster of 0xAA data
        let data = vec![0xAA; CLUSTER_SIZE];
        let compressed = compression::compress_cluster(&data, CLUSTER_SIZE)
            .unwrap()
            .expect("all-0xAA should compress");

        // Write compressed data at guest offset 0
        make_writer(&mut s)
            .write_compressed_at(&compressed, 0)
            .unwrap();

        // Verify L2 entry is Compressed
        let l1_entry = s.mapper.l1_entry(L1Index(0)).unwrap();
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; CLUSTER_SIZE];
        s.backend.read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, CLUSTER_BITS, false).unwrap();

        match l2_table.get(L2Index(0)).unwrap() {
            L2Entry::Compressed(desc) => {
                // Read the actual compressed bytes (deflate is self-terminating,
                // so we only need the raw bytes, not the sector-aligned size)
                let mut comp_buf = vec![0u8; compressed.len()];
                s.backend.read_exact_at(&mut comp_buf, desc.host_offset).unwrap();
                let decompressed =
                    compression::decompress_cluster(&comp_buf, CLUSTER_SIZE, 0).unwrap();
                assert_eq!(decompressed, data, "decompressed data should match original");
            }
            other => panic!("expected Compressed L2 entry, got {other:?}"),
        }
    }
}
