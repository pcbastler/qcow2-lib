//! Read, write, flush, and compressed write operations on `Qcow2Image`.

use crate::engine::compression;
use crate::engine::reader::Qcow2Reader;
use crate::engine::writer::Qcow2Writer;
use crate::error::{Error, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::io::IoBackend;

use super::Qcow2Image;

impl Qcow2Image {
    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Handles reads that span multiple clusters, zero clusters,
    /// compressed clusters, and unallocated regions.
    ///
    /// In [`ReadMode::Lenient`], unreadable regions are filled with zeros
    /// and warnings are collected (see [`warnings`](Self::warnings)).
    pub fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        // RAW_EXTERNAL: data is always at guest offset in the raw file.
        // No L2 lookup needed — identity mapping is guaranteed.
        if let Some(ref data_be) = self.data_backend {
            return data_be.read_exact_at(buf, guest_offset);
        }

        let mut reader = Qcow2Reader::new(
            &self.meta.mapper,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.meta.cache,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            self.meta.read_mode,
            &mut self.meta.warnings,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        reader.read_at(buf, guest_offset)
    }

    /// Write `buf` starting at the given guest offset.
    ///
    /// Requires the image to be opened with `open_rw` or `from_backend_rw`.
    /// Sets the DIRTY flag on the first write. All metadata updates are
    /// written through to disk immediately.
    pub fn write_at(&mut self, buf: &[u8], guest_offset: u64) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        // Set dirty flag on first write
        if !self.meta.dirty {
            self.mark_dirty()?;
        }

        let raw_external = self.data_backend.is_some();
        let data_be: &dyn IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.meta.mapper,
            self.meta.header.l1_table_offset,
            self.backend.as_ref(),
            data_be,
            &mut self.meta.cache,
            refcount_manager,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            raw_external,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.write_at(buf, guest_offset)?;

        // Auto-track dirty bitmaps
        if self.meta.has_auto_bitmaps {
            self.track_bitmap_write(guest_offset, buf.len() as u64)?;
        }

        // Update per-cluster hashes
        if self.meta.has_hashes {
            self.update_hashes_for_write(guest_offset, buf.len() as u64)?;
        }

        Ok(())
    }

    /// Flush all dirty cached metadata to disk and clear the DIRTY flag.
    ///
    /// In WriteBack mode, flushes refcount blocks first (crash consistency:
    /// leaked space is recoverable, dangling L2 refs are not), then L2 tables,
    /// then issues an fsync, and finally clears the DIRTY header bit.
    pub fn flush(&mut self) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        self.flush_dirty_metadata()?;

        self.backend.flush()?;

        if self.meta.dirty {
            self.clear_dirty()?;
        }

        Ok(())
    }

    /// Write all dirty refcount blocks and L2 tables from cache to disk.
    pub(super) fn flush_dirty_metadata(&mut self) -> Result<()> {
        qcow2_core::engine::metadata_io::flush_dirty_metadata(
            self.backend.as_ref(),
            &mut self.meta.cache,
            self.meta.header.cluster_bits,
        )
    }

    // ---- Compressed write API ----

    /// Write a cluster, attempting compression first.
    ///
    /// If deflate compression reduces the data size below the cluster size,
    /// writes a compressed cluster. Otherwise falls back to a normal
    /// uncompressed write.
    ///
    /// The `guest_offset` must be cluster-aligned and `data.len()` must
    /// equal the cluster size.
    pub fn write_cluster_maybe_compressed(
        &mut self,
        data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        if !self.meta.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_size = self.cluster_size() as usize;
        match compression::compress_cluster(data, cluster_size, self.meta.header.compression_type)? {
            Some(compressed) => self.write_compressed_at(&compressed, guest_offset),
            None => self.write_at(data, guest_offset),
        }
    }

    /// Write pre-compressed data as a compressed cluster.
    fn write_compressed_at(
        &mut self,
        compressed_data: &[u8],
        guest_offset: u64,
    ) -> Result<()> {
        if !self.meta.dirty {
            self.mark_dirty()?;
        }

        if self.data_backend.is_some() {
            return Err(Error::CompressedWithExternalData);
        }
        if self.crypt_context.is_some() {
            return Err(Error::EncryptionWithCompression);
        }

        let refcount_manager = self
            .meta.refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut writer = Qcow2Writer::new(
            &mut self.meta.mapper,
            self.meta.header.l1_table_offset,
            self.backend.as_ref(),
            self.backend.as_ref(),
            &mut self.meta.cache,
            refcount_manager,
            self.meta.header.cluster_bits,
            self.meta.header.virtual_size,
            self.meta.header.compression_type,
            false,
            self.backing_image.as_deref_mut().map(|b| b as &mut dyn crate::io::BackingImage),
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        writer.set_compressed_cursor(self.meta.compressed_cursor);
        let result = writer.write_compressed_at(compressed_data, guest_offset);
        self.meta.compressed_cursor = writer.compressed_cursor();
        result
    }

    // ---- Dirty flag management ----

    /// Set the DIRTY incompatible feature flag in the on-disk header.
    ///
    /// Also clears the BITMAPS autoclear bit if bitmaps exist, since
    /// bitmaps may be inconsistent while the image is dirty.
    pub(super) fn mark_dirty(&mut self) -> Result<()> {
        if self.meta.skip_dirty_marking {
            self.meta.dirty = true;
            return Ok(());
        }
        self.meta.header.incompatible_features |= IncompatibleFeatures::DIRTY;

        // Clear autoclear bits while image is dirty
        if self.meta.has_auto_bitmaps
            && self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.meta.header.autoclear_features -= AutoclearFeatures::BITMAPS;
        }
        if self.meta.has_hashes
            && self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.meta.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
        }

        // Single batched I/O for both feature fields
        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            self.backend.as_ref(),
            self.meta.header.incompatible_features,
            self.meta.header.autoclear_features,
        )?;

        self.backend.flush()?;
        self.meta.dirty = true;
        Ok(())
    }

    /// Clear the DIRTY incompatible feature flag from the on-disk header.
    ///
    /// Restores the BITMAPS autoclear bit if bitmaps exist.
    fn clear_dirty(&mut self) -> Result<()> {
        self.meta.header.incompatible_features -= IncompatibleFeatures::DIRTY;

        // Restore autoclear bits on clean close
        if self.meta.has_auto_bitmaps
            && !self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BITMAPS)
        {
            self.meta.header.autoclear_features |= AutoclearFeatures::BITMAPS;
        }
        if self.meta.has_hashes
            && !self
                .meta.header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            self.meta.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
        }

        // Single batched I/O for both feature fields
        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            self.backend.as_ref(),
            self.meta.header.incompatible_features,
            self.meta.header.autoclear_features,
        )?;

        self.backend.flush()?;
        self.meta.dirty = false;
        Ok(())
    }
}
