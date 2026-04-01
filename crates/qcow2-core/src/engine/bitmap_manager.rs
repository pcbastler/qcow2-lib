//! Bitmap lifecycle management: create, list, delete, set/get dirty, clear, merge.
//!
//! The [`BitmapManager`] is a transient helper that borrows components from
//! [`Qcow2Image`](super::image::Qcow2Image) for the duration of a bitmap
//! operation. This follows the same borrow-based pattern as
//! [`SnapshotManager`](super::snapshot_manager::SnapshotManager).

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::engine::cache::MetadataCache;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, FormatError, Result};
use crate::format::bitmap::{
    BitmapDirectoryEntry, BitmapExtension, BitmapTable, BitmapTableEntry, BitmapTableEntryState,
};
use crate::format::constants::*;
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::types::{BitmapIndex, ClusterOffset};
use crate::io::IoBackend;

/// Information about a bitmap, suitable for display.
#[derive(Debug, Clone)]
pub struct BitmapInfo {
    /// Bitmap name.
    pub name: String,
    /// Granularity in bytes (1 << granularity_bits).
    pub granularity: u64,
    /// Raw granularity_bits value.
    pub granularity_bits: u8,
    /// Whether the bitmap is in use (potentially inconsistent).
    pub in_use: bool,
    /// Whether auto-tracking is enabled.
    pub auto: bool,
    /// Bitmap type (1 = dirty tracking).
    pub bitmap_type: u8,
    /// Number of bitmap table entries.
    pub table_size: u32,
}

/// Transient helper for bitmap operations.
///
/// Borrows the mutable state needed from `Qcow2Image` for the duration
/// of a single bitmap operation.
pub struct BitmapManager<'a> {
    backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    header: &'a mut Header,
    extensions: &'a mut Vec<HeaderExtension>,
    cluster_bits: u32,
    virtual_size: u64,
}

impl<'a> BitmapManager<'a> {
    /// Create a new bitmap manager borrowing the image's state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        header: &'a mut Header,
        extensions: &'a mut Vec<HeaderExtension>,
        cluster_bits: u32,
        virtual_size: u64,
    ) -> Self {
        Self {
            backend,
            cache,
            refcount_manager,
            header,
            extensions,
            cluster_bits,
            virtual_size,
        }
    }

    // ---- Helpers ----

    fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    /// Find the bitmap extension in the extensions list.
    fn find_bitmap_extension(&self) -> Option<&BitmapExtension> {
        self.extensions.iter().find_map(|ext| match ext {
            HeaderExtension::Bitmaps(b) => Some(b),
            _ => None,
        })
    }

    /// Load the bitmap directory from disk.
    fn load_directory(&self) -> Result<Vec<BitmapDirectoryEntry>> {
        let ext = match self.find_bitmap_extension() {
            Some(ext) => ext.clone(),
            None => return Ok(Vec::new()),
        };

        let mut buf = vec![0u8; ext.bitmap_directory_size as usize];
        self.backend
            .read_exact_at(&mut buf, ext.bitmap_directory_offset)?;

        Ok(BitmapDirectoryEntry::read_directory(&buf, ext.nb_bitmaps)?)
    }

    /// Load a bitmap table from disk.
    fn load_bitmap_table(&self, entry: &BitmapDirectoryEntry) -> Result<BitmapTable> {
        let byte_count = entry.bitmap_table_size as usize * BITMAP_TABLE_ENTRY_SIZE;
        let mut buf = vec![0u8; byte_count];
        self.backend
            .read_exact_at(&mut buf, entry.bitmap_table_offset.0)?;
        Ok(BitmapTable::read_from(&buf, entry.bitmap_table_size)?)
    }

    /// Write a bitmap table to disk at an existing offset (in-place update).
    fn write_bitmap_table_at(
        &self,
        table: &BitmapTable,
        offset: ClusterOffset,
    ) -> Result<()> {
        let byte_count = table.len() as usize * BITMAP_TABLE_ENTRY_SIZE;
        let mut buf = vec![0u8; byte_count];
        table.write_to(&mut buf)?;
        self.backend.write_all_at(&buf, offset.0)?;
        Ok(())
    }

    /// Allocate cluster(s) for a bitmap table and write it.
    fn allocate_and_write_bitmap_table(&mut self, table: &BitmapTable) -> Result<ClusterOffset> {
        let byte_count = table.len() as usize * BITMAP_TABLE_ENTRY_SIZE;
        let clusters_needed =
            ((byte_count as u64 + self.cluster_size() - 1) / self.cluster_size()).max(1);

        let first_offset = self
            .refcount_manager
            .allocate_contiguous_clusters(clusters_needed, self.backend, self.cache)?;

        // Write table into a zero-padded buffer (single I/O)
        let alloc_size = clusters_needed as usize * self.cluster_size() as usize;
        let mut buf = vec![0u8; alloc_size];
        table.write_to(&mut buf[..byte_count])?;
        self.backend.write_all_at(&buf, first_offset.0)?;

        Ok(first_offset)
    }

    /// Write the bitmap directory to newly allocated clusters.
    fn write_directory(&mut self, entries: &[BitmapDirectoryEntry]) -> Result<(ClusterOffset, u64)> {
        let dir_data = BitmapDirectoryEntry::write_directory(entries);
        let dir_size = dir_data.len() as u64;
        let clusters_needed = ((dir_size + self.cluster_size() - 1) / self.cluster_size()).max(1);

        let first_offset = self
            .refcount_manager
            .allocate_contiguous_clusters(clusters_needed, self.backend, self.cache)?;

        // Write directory data into a zero-padded buffer (single I/O)
        let alloc_size = clusters_needed as usize * self.cluster_size() as usize;
        let mut buf = vec![0u8; alloc_size];
        buf[..dir_data.len()].copy_from_slice(&dir_data);
        self.backend.write_all_at(&buf, first_offset.0)?;

        Ok((first_offset, dir_size))
    }

    /// Free cluster(s) at a given offset covering `byte_count` bytes.
    fn free_clusters(&mut self, offset: ClusterOffset, byte_count: u64) -> Result<()> {
        let cluster_size = self.cluster_size();
        let clusters = (byte_count + cluster_size - 1) / cluster_size;
        for i in 0..clusters {
            let cluster_offset = ClusterOffset(offset.0 + i * cluster_size);
            self.refcount_manager
                .free_cluster(cluster_offset.0, self.backend, self.cache)?;
        }
        Ok(())
    }

    /// Update the bitmap extension in the in-memory extensions list,
    /// then rewrite the header extension area in cluster 0.
    fn update_extension(
        &mut self,
        nb_bitmaps: u32,
        dir_size: u64,
        dir_offset: u64,
    ) -> Result<()> {
        let new_ext = BitmapExtension {
            nb_bitmaps,
            bitmap_directory_size: dir_size,
            bitmap_directory_offset: dir_offset,
        };

        // Replace or add the Bitmaps extension
        let mut found = false;
        for ext in self.extensions.iter_mut() {
            if matches!(ext, HeaderExtension::Bitmaps(_)) {
                *ext = HeaderExtension::Bitmaps(new_ext.clone());
                found = true;
                break;
            }
        }
        if !found {
            self.extensions
                .push(HeaderExtension::Bitmaps(new_ext));
        }

        self.write_extensions_to_disk()
    }

    /// Remove the bitmap extension entirely and rewrite.
    fn remove_extension(&mut self) -> Result<()> {
        self.extensions
            .retain(|ext| !matches!(ext, HeaderExtension::Bitmaps(_)));
        self.write_extensions_to_disk()
    }

    /// Rewrite all header extensions to cluster 0.
    fn write_extensions_to_disk(&self) -> Result<()> {
        super::metadata_io::write_header_extensions(
            self.backend,
            self.header,
            self.extensions,
            self.cluster_size(),
        )
    }

    /// Write autoclear features to the on-disk header.
    fn write_autoclear_features(&self) -> Result<()> {
        super::metadata_io::write_autoclear_features(
            self.backend,
            self.header.autoclear_features,
        )
    }

    /// Find a bitmap directory entry by name.
    fn find_entry_index(entries: &[BitmapDirectoryEntry], name: &str) -> Result<usize> {
        entries
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::BitmapNotFound {
                name: name.to_string(),
            })
    }

    /// Calculate the number of bitmap table entries needed.
    fn bitmap_table_entries(&self, granularity_bits: u8) -> u32 {
        let granularity = 1u64 << granularity_bits;
        let cluster_size = self.cluster_size();
        let bits_per_cluster = cluster_size * 8;
        let total_bits = (self.virtual_size + granularity - 1) / granularity;
        ((total_bits + bits_per_cluster - 1) / bits_per_cluster) as u32
    }

    /// Decompose a guest offset into bitmap addressing components.
    ///
    /// Returns (table_index, byte_in_cluster, bit_in_byte).
    /// Uses MSB-first bit ordering as required by the spec.
    fn bit_address(
        &self,
        guest_offset: u64,
        granularity_bits: u8,
    ) -> (u32, u32, u8) {
        let granularity = 1u64 << granularity_bits;
        let bit_number = guest_offset / granularity;
        let bits_per_cluster = self.cluster_size() * 8;
        let table_index = (bit_number / bits_per_cluster) as u32;
        let bit_within_cluster = bit_number % bits_per_cluster;
        let byte_in_cluster = (bit_within_cluster / 8) as u32;
        let bit_in_byte = 7 - (bit_within_cluster % 8) as u8; // MSB-first
        (table_index, byte_in_cluster, bit_in_byte)
    }

    /// Load a bitmap data cluster (with cache).
    fn load_data_cluster(&mut self, offset: ClusterOffset) -> Result<Vec<u8>> {
        if let Some(data) = self.cache.get_bitmap_data(offset) {
            return Ok(data.clone());
        }

        let cluster_size = self.cluster_size() as usize;
        let mut buf = vec![0u8; cluster_size];
        self.backend.read_exact_at(&mut buf, offset.0)?;
        self.cache.insert_bitmap_data(offset, buf.clone());
        Ok(buf)
    }

    /// Write a bitmap data cluster and update cache.
    fn write_data_cluster(&mut self, offset: ClusterOffset, data: &[u8]) -> Result<()> {
        self.backend.write_all_at(data, offset.0)?;
        self.cache.evict_bitmap_data(offset);
        Ok(())
    }

    // ---- Public operations ----

    /// List all bitmaps in the image.
    pub fn list_bitmaps(&self) -> Result<Vec<BitmapInfo>> {
        let entries = self.load_directory()?;
        Ok(entries
            .iter()
            .map(|e| BitmapInfo {
                name: e.name.clone(),
                granularity: e.granularity(),
                granularity_bits: e.granularity_bits,
                in_use: e.is_in_use(),
                auto: e.is_auto(),
                bitmap_type: e.bitmap_type,
                table_size: e.bitmap_table_size,
            })
            .collect())
    }

    /// Create a new dirty-tracking bitmap.
    pub fn create_bitmap(
        &mut self,
        name: &str,
        granularity_bits: u8,
        auto: bool,
    ) -> Result<()> {
        // Validate
        if name.is_empty() {
            return Err(Error::BitmapNameEmpty);
        }
        if name.len() > BITMAP_MAX_NAME_SIZE as usize {
            return Err(FormatError::InvalidBitmapExtension {
                message: format!(
                    "bitmap name length {} exceeds maximum {}",
                    name.len(),
                    BITMAP_MAX_NAME_SIZE
                ),
            }
            .into());
        }

        let valid_range = BITMAP_MIN_GRANULARITY_BITS..=BITMAP_MAX_GRANULARITY_BITS;
        if !valid_range.contains(&granularity_bits) {
            return Err(FormatError::InvalidBitmapExtension {
                message: format!(
                    "granularity_bits {} out of range [{}, {}]",
                    granularity_bits, BITMAP_MIN_GRANULARITY_BITS, BITMAP_MAX_GRANULARITY_BITS
                ),
            }
            .into());
        }

        let mut entries = self.load_directory()?;

        // Check for duplicate name
        if entries.iter().any(|e| e.name == name) {
            return Err(Error::BitmapNameDuplicate {
                name: name.to_string(),
            });
        }

        if entries.len() as u32 >= BITMAP_MAX_COUNT {
            return Err(FormatError::InvalidBitmapExtension {
                message: format!("bitmap count would exceed maximum {}", BITMAP_MAX_COUNT),
            }
            .into());
        }

        // Allocate and write an all-zeros bitmap table
        let table_entries = self.bitmap_table_entries(granularity_bits);
        let table = BitmapTable::new_all_zeros(table_entries);
        let table_offset = self.allocate_and_write_bitmap_table(&table)?;

        // Build directory entry
        let mut flags = 0u32;
        if auto {
            flags |= BME_FLAG_AUTO;
        }
        let new_entry = BitmapDirectoryEntry {
            bitmap_table_offset: table_offset,
            bitmap_table_size: table_entries,
            flags,
            bitmap_type: BITMAP_TYPE_DIRTY,
            granularity_bits,
            name: name.to_string(),
            extra_data: vec![],
        };
        entries.push(new_entry);

        // Free old directory clusters if they exist
        if let Some(old_ext) = self.find_bitmap_extension().cloned() {
            self.free_clusters(
                ClusterOffset(old_ext.bitmap_directory_offset),
                old_ext.bitmap_directory_size,
            )?;
        }

        // Write new directory
        let (dir_offset, dir_size) = self.write_directory(&entries)?;

        // Update extension
        self.update_extension(entries.len() as u32, dir_size, dir_offset.0)?;

        // Set autoclear BITMAPS flag
        self.header.autoclear_features |= AutoclearFeatures::BITMAPS;
        self.write_autoclear_features()?;

        self.backend.flush()?;
        Ok(())
    }

    /// Delete a bitmap by name.
    pub fn delete_bitmap(&mut self, name: &str) -> Result<()> {
        let mut entries = self.load_directory()?;
        let idx = Self::find_entry_index(&entries, name)?;

        let entry = &entries[idx];

        // Free bitmap data clusters
        let table = self.load_bitmap_table(entry)?;
        for te in table.iter() {
            if let Some(offset) = te.data_cluster_offset() {
                self.free_clusters(offset, self.cluster_size())?;
            }
        }

        // Free bitmap table clusters
        let table_bytes = entry.bitmap_table_size as u64 * BITMAP_TABLE_ENTRY_SIZE as u64;
        self.free_clusters(entry.bitmap_table_offset, table_bytes)?;

        entries.remove(idx);

        // Free old directory clusters
        if let Some(old_ext) = self.find_bitmap_extension().cloned() {
            self.free_clusters(
                ClusterOffset(old_ext.bitmap_directory_offset),
                old_ext.bitmap_directory_size,
            )?;
        }

        if entries.is_empty() {
            // Remove extension entirely
            self.remove_extension()?;
            self.header.autoclear_features -= AutoclearFeatures::BITMAPS;
            self.write_autoclear_features()?;
        } else {
            let (dir_offset, dir_size) = self.write_directory(&entries)?;
            self.update_extension(entries.len() as u32, dir_size, dir_offset.0)?;
        }

        self.backend.flush()?;
        Ok(())
    }

    /// Query whether a specific guest offset is dirty in the named bitmap.
    pub fn get_dirty(&mut self, name: &str, guest_offset: u64) -> Result<bool> {
        let entries = self.load_directory()?;
        let idx = Self::find_entry_index(&entries, name)?;
        let entry = &entries[idx];

        let (table_idx, byte_off, bit_off) =
            self.bit_address(guest_offset, entry.granularity_bits);

        let table = self.load_bitmap_table(entry)?;
        let te = table.get(BitmapIndex(table_idx))?;

        match te.state() {
            BitmapTableEntryState::AllZeros => Ok(false),
            BitmapTableEntryState::AllOnes => Ok(true),
            BitmapTableEntryState::Data(offset) => {
                let data = self.load_data_cluster(offset)?;
                Ok(data[byte_off as usize] & (1 << bit_off) != 0)
            }
        }
    }

    /// Mark a range of guest bytes as dirty in the named bitmap.
    pub fn set_dirty(
        &mut self,
        name: &str,
        guest_offset: u64,
        len: u64,
    ) -> Result<()> {
        let entries = self.load_directory()?;
        let idx = Self::find_entry_index(&entries, name)?;
        let entry = entries[idx].clone();

        let granularity = entry.granularity();
        let mut table = self.load_bitmap_table(&entry)?;
        let mut table_dirty = false;

        let first_bit = guest_offset / granularity;
        let last_bit = (guest_offset + len - 1) / granularity;
        let bits_per_cluster = self.cluster_size() * 8;

        let mut bit = first_bit;
        while bit <= last_bit {
            let table_idx = BitmapIndex((bit / bits_per_cluster) as u32);
            let entry_first_bit = table_idx.0 as u64 * bits_per_cluster;
            let entry_last_bit = entry_first_bit + bits_per_cluster - 1;
            let covers_all = first_bit <= entry_first_bit && last_bit >= entry_last_bit;
            let te = table.get(table_idx)?;

            match te.state() {
                BitmapTableEntryState::AllOnes => {}
                _ if covers_all => {
                    // Range covers entire entry — promote to AllOnes, free data if any.
                    if let BitmapTableEntryState::Data(offset) = te.state() {
                        self.free_clusters(offset, self.cluster_size())?;
                    }
                    table.set(table_idx, BitmapTableEntry::all_ones())?;
                    table_dirty = true;
                }
                BitmapTableEntryState::AllZeros => {
                    let data_offset = self
                        .refcount_manager
                        .allocate_cluster(self.backend, self.cache)?;
                    let mut data = vec![0u8; self.cluster_size() as usize];
                    Self::set_bits_msb(&mut data, bit - entry_first_bit, last_bit.min(entry_last_bit) - entry_first_bit)?;
                    self.write_data_cluster(data_offset, &data)?;
                    table.set(table_idx, BitmapTableEntry::with_data_offset(data_offset))?;
                    table_dirty = true;
                }
                BitmapTableEntryState::Data(data_offset) => {
                    let mut data = self.load_data_cluster(data_offset)?;
                    let before = data.clone();
                    Self::set_bits_msb(&mut data, bit - entry_first_bit, last_bit.min(entry_last_bit) - entry_first_bit)?;
                    if data != before {
                        self.write_data_cluster(data_offset, &data)?;
                    }
                }
            }

            bit = entry_last_bit + 1;
        }

        if table_dirty {
            self.write_bitmap_table_at(&table, entry.bitmap_table_offset)?;
        }

        Ok(())
    }

    /// Set bits [start..=end] in `data` using MSB-first bit ordering.
    fn set_bits_msb(data: &mut [u8], start: u64, end: u64) -> Result<()> {
        for b in start..=end {
            let byte_idx = (b / 8) as usize;
            let bit_idx = 7 - (b % 8) as u8;
            let byte = data.get_mut(byte_idx).ok_or(Error::ShouldBeUnreachable)?;
            *byte |= 1 << bit_idx;
        }
        Ok(())
    }

    /// Clear all bits in a bitmap (reset to all-clean).
    pub fn clear_bitmap(&mut self, name: &str) -> Result<()> {
        let entries = self.load_directory()?;
        let idx = Self::find_entry_index(&entries, name)?;
        let entry = &entries[idx];

        // Free all data clusters
        let table = self.load_bitmap_table(entry)?;
        for te in table.iter() {
            if let Some(offset) = te.data_cluster_offset() {
                self.free_clusters(offset, self.cluster_size())?;
            }
        }

        // Write an all-zeros table (in-place)
        let new_table = BitmapTable::new_all_zeros(entry.bitmap_table_size);
        self.write_bitmap_table_at(&new_table, entry.bitmap_table_offset)?;

        self.backend.flush()?;
        Ok(())
    }

    /// Set the AUTO flag on a bitmap.
    pub fn enable_tracking(&mut self, name: &str) -> Result<()> {
        self.update_flag(name, BME_FLAG_AUTO, true)
    }

    /// Clear the AUTO flag on a bitmap.
    pub fn disable_tracking(&mut self, name: &str) -> Result<()> {
        self.update_flag(name, BME_FLAG_AUTO, false)
    }

    /// Merge source bitmap into destination bitmap (OR operation).
    pub fn merge_bitmaps(&mut self, source: &str, destination: &str) -> Result<()> {
        let entries = self.load_directory()?;
        let src_idx = Self::find_entry_index(&entries, source)?;
        let dst_idx = Self::find_entry_index(&entries, destination)?;

        let src_entry = entries[src_idx].clone();
        let dst_entry = entries[dst_idx].clone();

        if src_entry.granularity_bits != dst_entry.granularity_bits {
            return Err(FormatError::InvalidBitmapExtension {
                message: format!(
                    "cannot merge bitmaps with different granularity: {} vs {}",
                    src_entry.granularity_bits, dst_entry.granularity_bits
                ),
            }
            .into());
        }

        let src_table = self.load_bitmap_table(&src_entry)?;
        let mut dst_table = self.load_bitmap_table(&dst_entry)?;
        let mut dst_table_dirty = false;

        let count = src_table.len().min(dst_table.len());

        for i in 0..count {
            let idx = BitmapIndex(i);
            let src_te = src_table.get(idx)?;
            let dst_te = dst_table.get(idx)?;

            match (src_te.state(), dst_te.state()) {
                // Nothing to merge: source is clean, or destination is already all dirty.
                (BitmapTableEntryState::AllZeros, _) | (_, BitmapTableEntryState::AllOnes) => {}
                (BitmapTableEntryState::AllOnes, _) => {
                    // Promote destination to AllOnes, free any data cluster.
                    if let Some(offset) = dst_te.data_cluster_offset() {
                        self.free_clusters(offset, self.cluster_size())?;
                    }
                    dst_table.set(idx, BitmapTableEntry::all_ones())?;
                    dst_table_dirty = true;
                }
                (BitmapTableEntryState::Data(src_offset), BitmapTableEntryState::AllZeros) => {
                    // Copy source data cluster to a new destination cluster.
                    let src_data = self.load_data_cluster(src_offset)?;
                    let new_offset = self
                        .refcount_manager
                        .allocate_cluster(self.backend, self.cache)?;
                    self.write_data_cluster(new_offset, &src_data)?;
                    dst_table.set(idx, BitmapTableEntry::with_data_offset(new_offset))?;
                    dst_table_dirty = true;
                }
                (BitmapTableEntryState::Data(src_offset), BitmapTableEntryState::Data(dst_offset)) => {
                    // OR source bits into destination.
                    let src_data = self.load_data_cluster(src_offset)?;
                    let mut dst_data = self.load_data_cluster(dst_offset)?;
                    for (d, s) in dst_data.iter_mut().zip(src_data.iter()) {
                        *d |= *s;
                    }
                    self.write_data_cluster(dst_offset, &dst_data)?;
                }
            }
        }

        if dst_table_dirty {
            self.write_bitmap_table_at(&dst_table, dst_entry.bitmap_table_offset)?;
        }

        self.backend.flush()?;
        Ok(())
    }

    /// Check if any bitmap has the AUTO flag set.
    pub fn has_auto_bitmaps(&self) -> Result<bool> {
        let entries = self.load_directory()?;
        Ok(entries.iter().any(|e| e.is_auto()))
    }

    /// Set dirty bits for all AUTO bitmaps covering a write range.
    pub fn track_write(&mut self, guest_offset: u64, len: u64) -> Result<()> {
        let entries = self.load_directory()?;
        let auto_names: Vec<String> = entries
            .iter()
            .filter(|e| e.is_auto())
            .map(|e| e.name.clone())
            .collect();

        for name in auto_names {
            self.set_dirty(&name, guest_offset, len)?;
        }

        Ok(())
    }

    // ---- Internal helpers ----

    /// Update a flag on a bitmap directory entry.
    fn update_flag(&mut self, name: &str, flag: u32, set: bool) -> Result<()> {
        let mut entries = self.load_directory()?;
        let idx = Self::find_entry_index(&entries, name)?;

        if set {
            entries[idx].flags |= flag;
        } else {
            entries[idx].flags &= !flag;
        }

        // Free old directory clusters
        if let Some(old_ext) = self.find_bitmap_extension().cloned() {
            self.free_clusters(
                ClusterOffset(old_ext.bitmap_directory_offset),
                old_ext.bitmap_directory_size,
            )?;
        }

        let (dir_offset, dir_size) = self.write_directory(&entries)?;
        self.update_extension(entries.len() as u32, dir_size, dir_offset.0)?;

        self.backend.flush()?;
        Ok(())
    }
}
