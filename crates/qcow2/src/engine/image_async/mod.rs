//! Thread-safe parallel I/O wrapper for QCOW2 images.
//!
//! [`Qcow2ImageAsync`] wraps a [`Qcow2Image`] with per-L2 `RwLock`s and a
//! global `Mutex<ImageMeta>` to allow safe concurrent reads and writes from
//! multiple threads. The metadata mutex is held only for microseconds
//! (cluster resolution), never during data I/O.
//!
//! # Concurrency
//!
//! | Thread A | Thread B | Same L2? | Behavior |
//! |----------|----------|----------|----------|
//! | Read | Read | yes | Parallel (shared lock) |
//! | Read | Read | no | Parallel |
//! | Read | Write | yes | Write waits |
//! | Read | Write | no | Parallel |
//! | Write | Write | yes | Serialized |
//! | Write | Write | no | Parallel |
//!
//! The implementation is split across sub-modules by functional area:
//! - [`read_write`]: read, write, flush, and compressed writes
//! - [`accessors`]: public getters
//! - [`hash`]: BLAKE3 per-chunk hash API
//! - [`snapshot`]: snapshot management
//! - [`bitmap`]: persistent dirty bitmap API
//! - [`integrity`]: integrity checks and repair

mod accessors;
mod bitmap;
mod hash;
mod integrity;
mod read_write;
mod snapshot;

use std::sync::{Mutex, RwLock};

use crate::engine::compression;
use crate::engine::image::Qcow2Image;
use crate::engine::image_meta::ImageMeta;
use crate::error::{Error, IoErrorKind, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::io::IoBackend;

/// Helper to create a lock-poisoned error.
pub(crate) fn poisoned_err() -> Error {
    Error::Io {
        kind: IoErrorKind::Other,
        message: "lock poisoned".into(),
        offset: 0,
        context: "Qcow2ImageAsync lock acquisition",
    }
}

/// Zero-cost adapter: implements `BackingImage` (`&mut self`) by delegating
/// to `Qcow2ImageAsync::read_at` (`&self`). Lives on the stack, no allocation.
pub(crate) struct AsyncBackingAdapter<'a>(pub(crate) &'a Qcow2ImageAsync);

impl crate::io::BackingImage for AsyncBackingAdapter<'_> {
    fn virtual_size(&self) -> u64 {
        self.0.virtual_size().unwrap_or(0)
    }

    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        self.0.read_at(buf, guest_offset)
    }
}

/// Thread-safe QCOW2 image supporting parallel reads and writes.
///
/// Created from a [`Qcow2Image`] via [`from_image`](Self::from_image) and can
/// be converted back via [`into_image`](Self::into_image). All methods take
/// `&self` — concurrent access is safe through internal locking.
pub struct Qcow2ImageAsync {
    /// Global metadata state, held ~1-5 µs per operation.
    pub(crate) meta: Mutex<ImageMeta>,
    /// Per-L2 table locks (one per L1 index = per 512 MB guest range at 64K clusters).
    pub(crate) l2_locks: Vec<RwLock<()>>,
    /// Main I/O backend (metadata + data unless external data file).
    pub(crate) backend: Box<dyn IoBackend>,
    /// Separate I/O backend for guest data when using an external data file.
    pub(crate) data_backend: Option<Box<dyn IoBackend>>,
    /// Encryption context for encrypted images.
    pub(crate) crypt_context: Option<crate::engine::encryption::CryptContext>,
    /// Compression backend.
    pub(crate) compressor: compression::StdCompressor,
    /// Cached cluster_bits from header (immutable after open).
    pub(crate) cluster_bits: u32,
    /// Cached extended_l2 flag from header (immutable after open).
    pub(crate) extended_l2: bool,
    /// Backing image for unallocated cluster fallback (recursively async).
    pub(crate) backing: Option<Box<Qcow2ImageAsync>>,
}


impl Qcow2ImageAsync {
    /// Create a thread-safe image from an existing `Qcow2Image`.
    ///
    /// If the image has a backing file, it is recursively converted to
    /// a `Qcow2ImageAsync` so backing reads are also parallel.
    pub fn from_image(image: Qcow2Image) -> Result<Self> {
        let (meta, backend, data_backend, _backing_chain, backing_image, crypt_context, compressor) =
            image.into_parts();

        let backing = match backing_image {
            Some(img) => Some(Box::new(Qcow2ImageAsync::from_image(*img)?)),
            None => None,
        };

        let cluster_bits = meta.header.cluster_bits;
        let extended_l2 = meta.mapper.geometry().extended_l2;
        let l1_len = meta.mapper.l1_table().len() as usize;
        let l2_locks: Vec<RwLock<()>> = (0..l1_len).map(|_| RwLock::new(())).collect();

        Ok(Self {
            meta: Mutex::new(meta),
            l2_locks,
            backend,
            data_backend,
            crypt_context,
            compressor,
            cluster_bits,
            extended_l2,
            backing,
        })
    }

    /// Convert back to a single-threaded `Qcow2Image`.
    pub fn into_image(self) -> Qcow2Image {
        // Use ManuallyDrop to prevent Drop from running, then extract fields.
        let me = std::mem::ManuallyDrop::new(self);

        // Safety: we take ownership of each field exactly once and never use `me` again.
        let (meta, backend, data_backend, crypt_context, compressor, backing) = unsafe {
            (
                std::ptr::read(&me.meta),
                std::ptr::read(&me.backend),
                std::ptr::read(&me.data_backend),
                std::ptr::read(&me.crypt_context),
                std::ptr::read(&me.compressor),
                std::ptr::read(&me.backing),
            )
        };
        let meta = meta.into_inner().expect("mutex poisoned");

        let backing_image = backing.map(|b| Box::new(b.into_image()));

        Qcow2Image::from_parts(
            meta,
            backend,
            data_backend,
            None, // backing_chain
            backing_image,
            crypt_context,
            compressor,
        )
    }

    /// Compute L1 index for a guest offset.
    pub(crate) fn l1_index_for(&self, guest_offset: u64) -> usize {
        let l2_entry_shift = if self.extended_l2 { 4 } else { 3 };
        let l2_bits = self.cluster_bits - l2_entry_shift;
        (guest_offset >> (self.cluster_bits as u64 + l2_bits as u64)) as usize
    }

    /// Set DIRTY flag on the on-disk header.
    pub(crate) fn mark_dirty_inner(meta: &mut ImageMeta, backend: &dyn IoBackend) -> Result<()> {
        meta.header.incompatible_features |= IncompatibleFeatures::DIRTY;

        if meta.has_auto_bitmaps
            && meta.header.autoclear_features.contains(AutoclearFeatures::BITMAPS)
        {
            meta.header.autoclear_features -= AutoclearFeatures::BITMAPS;
        }
        if meta.has_hashes
            && meta.header.autoclear_features.contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            meta.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
        }

        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            backend,
            meta.header.incompatible_features,
            meta.header.autoclear_features,
        )?;

        backend.flush()?;
        meta.dirty = true;
        Ok(())
    }

    /// Clear DIRTY flag on the on-disk header.
    pub(crate) fn clear_dirty_inner(meta: &mut ImageMeta, backend: &dyn IoBackend) -> Result<()> {
        meta.header.incompatible_features -= IncompatibleFeatures::DIRTY;

        if meta.has_auto_bitmaps
            && !meta.header.autoclear_features.contains(AutoclearFeatures::BITMAPS)
        {
            meta.header.autoclear_features |= AutoclearFeatures::BITMAPS;
        }
        if meta.has_hashes
            && !meta.header.autoclear_features.contains(AutoclearFeatures::BLAKE3_HASHES)
        {
            meta.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
        }

        qcow2_core::engine::metadata_io::write_dirty_header_fields(
            backend,
            meta.header.incompatible_features,
            meta.header.autoclear_features,
        )?;

        backend.flush()?;
        meta.dirty = false;
        Ok(())
    }
}

impl Drop for Qcow2ImageAsync {
    fn drop(&mut self) {
        if let Ok(mut meta) = self.meta.lock() {
            if meta.writable {
                let cluster_bits = meta.header.cluster_bits;
                let _ = qcow2_core::engine::metadata_io::flush_dirty_metadata(
                    self.backend.as_ref(),
                    &mut meta.cache,
                    cluster_bits,
                );
                let _ = self.backend.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests;
