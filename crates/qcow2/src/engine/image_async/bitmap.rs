//! Bitmap API on `Qcow2ImageAsync`.

use crate::engine::bitmap_manager::{BitmapInfo, BitmapManager};
use crate::error::{Error, Result};
use crate::format::bitmap::BitmapDirectoryEntry;
use crate::format::header_extension::HeaderExtension;

use super::{poisoned_err, Qcow2ImageAsync};

impl Qcow2ImageAsync {
    /// List all persistent bitmaps in the image.
    pub fn bitmap_list(&self) -> Result<Vec<BitmapInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;

        let ext = match meta.extensions.iter().find_map(|e| match e {
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
        self.backend.read_exact_at(&mut buf, ext.bitmap_directory_offset)?;

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
    pub fn bitmap_create(&self, name: &str, granularity_bits: Option<u8>, auto: bool) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let granularity = granularity_bits.unwrap_or(crate::format::constants::BITMAP_DEFAULT_GRANULARITY_BITS);
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.create_bitmap(name, granularity, auto)?;
        if auto {
            meta_ref.has_auto_bitmaps = true;
        }
        Ok(())
    }

    /// Delete a persistent bitmap by name.
    pub fn bitmap_delete(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.delete_bitmap(name)?;

        meta_ref.has_auto_bitmaps = crate::engine::image::Qcow2Image::detect_auto_bitmaps(self.backend.as_ref(), &meta_ref.extensions);
        Ok(())
    }

    /// Query whether a specific guest offset is dirty in a bitmap.
    pub fn bitmap_get_dirty(&self, name: &str, guest_offset: u64) -> Result<bool> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.get_dirty(name, guest_offset)
    }

    /// Mark a range of guest offsets as dirty in a bitmap.
    pub fn bitmap_set_dirty(&self, name: &str, guest_offset: u64, len: u64) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.set_dirty(name, guest_offset, len)
    }

    /// Clear all dirty bits in a bitmap.
    pub fn bitmap_clear(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.clear_bitmap(name)
    }

    /// Enable auto-tracking on a bitmap.
    pub fn bitmap_enable_tracking(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.enable_tracking(name)?;
        meta_ref.has_auto_bitmaps = true;
        Ok(())
    }

    /// Disable auto-tracking on a bitmap.
    pub fn bitmap_disable_tracking(&self, name: &str) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let cluster_bits = self.cluster_bits;
        let virtual_size = meta_ref.header.virtual_size;
        let refcount_manager = meta_ref.refcount_manager.as_mut().expect("writable image must have refcount_manager");

        let mut mgr = BitmapManager::new(
            self.backend.as_ref(),
            &mut meta_ref.cache,
            refcount_manager,
            &mut meta_ref.header,
            &mut meta_ref.extensions,
            cluster_bits,
            virtual_size,
        );
        mgr.disable_tracking(name)?;

        meta_ref.has_auto_bitmaps = crate::engine::image::Qcow2Image::detect_auto_bitmaps(self.backend.as_ref(), &meta_ref.extensions);
        Ok(())
    }
}
