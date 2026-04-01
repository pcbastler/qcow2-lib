//! Bitmap API delegation on `Qcow2Image`.

use crate::engine::bitmap_manager::{BitmapInfo, BitmapManager};
use crate::error::{Error, Result};
use crate::format::bitmap::BitmapDirectoryEntry;
use crate::format::constants::BITMAP_DEFAULT_GRANULARITY_BITS;
use crate::format::header_extension::HeaderExtension;
use super::Qcow2Image;

impl Qcow2Image {
    /// List all persistent bitmaps in the image.
    pub fn bitmap_list(&self) -> Result<Vec<BitmapInfo>> {
        let ext = match self.meta.extensions.iter().find_map(|e| match e {
            HeaderExtension::Bitmaps(b) => Some(b),
            _ => None,
        }) {
            Some(ext) => ext,
            None => return Ok(Vec::new()),
        };

        if ext.nb_bitmaps == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; ext.bitmap_directory_size as usize];
        self.backend
            .read_exact_at(&mut buf, ext.bitmap_directory_offset)?;

        let entries = BitmapDirectoryEntry::read_directory(&buf, ext.nb_bitmaps)?;
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

    /// Create a new persistent bitmap.
    ///
    /// `granularity_bits` defaults to 16 (64 KiB) if `None`.
    /// If `auto` is true, the bitmap automatically tracks writes.
    pub fn bitmap_create(
        &mut self,
        name: &str,
        granularity_bits: Option<u8>,
        auto: bool,
    ) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let granularity = granularity_bits.unwrap_or(BITMAP_DEFAULT_GRANULARITY_BITS);

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.create_bitmap(name, granularity, auto)?;

        // Update cached auto-bitmap flag
        if auto {
            self.meta.has_auto_bitmaps = true;
        }
        Ok(())
    }

    /// Delete a persistent bitmap by name.
    pub fn bitmap_delete(&mut self, name: &str) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.delete_bitmap(name)?;

        // Re-check auto-bitmap flag
        self.meta.has_auto_bitmaps = Self::detect_auto_bitmaps(
            self.backend.as_ref(),
            &self.meta.extensions,
        );
        Ok(())
    }

    /// Query whether a specific guest offset is dirty in a bitmap.
    pub fn bitmap_get_dirty(&mut self, name: &str, guest_offset: u64) -> Result<bool> {
        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.get_dirty(name, guest_offset)
    }

    /// Mark a range of guest offsets as dirty in a bitmap.
    pub fn bitmap_set_dirty(
        &mut self,
        name: &str,
        guest_offset: u64,
        len: u64,
    ) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.set_dirty(name, guest_offset, len)
    }

    /// Clear all dirty bits in a bitmap (reset to all-zeros).
    pub fn bitmap_clear(&mut self, name: &str) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.clear_bitmap(name)
    }

    /// Enable auto-tracking (set the AUTO flag) on a bitmap.
    pub fn bitmap_enable_tracking(&mut self, name: &str) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.enable_tracking(name)?;
        self.meta.has_auto_bitmaps = true;
        Ok(())
    }

    /// Track a write in all auto-tracking bitmaps.
    ///
    /// Called internally by `write_at()` when auto-bitmaps are active.
    pub(super) fn track_bitmap_write(&mut self, guest_offset: u64, len: u64) -> Result<()> {
        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.track_write(guest_offset, len)
    }

    /// Disable auto-tracking (clear the AUTO flag) on a bitmap.
    pub fn bitmap_disable_tracking(&mut self, name: &str) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.meta.header.cluster_bits;
        let virtual_size = self.meta.header.virtual_size;
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .ok_or(Error::NoRefcountManager)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            &mut self.meta.header,
            &mut self.meta.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.disable_tracking(name)?;

        // Re-check auto-bitmap flag
        self.meta.has_auto_bitmaps = Self::detect_auto_bitmaps(
            self.backend.as_ref(),
            &self.meta.extensions,
        );
        Ok(())
    }
}
