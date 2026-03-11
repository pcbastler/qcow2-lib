//! Public accessor methods on `Qcow2Image`.

use crate::engine::backing::BackingChain;
use crate::engine::cache::{CacheMode, CacheStats};
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::error::Result;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::io::IoBackend;

use super::Qcow2Image;

impl Qcow2Image {
    /// The parsed image header.
    pub fn header(&self) -> &Header {
        &self.meta.header
    }

    /// The header extensions found in the image.
    pub fn extensions(&self) -> &[HeaderExtension] {
        &self.meta.extensions
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> u64 {
        self.meta.header.virtual_size
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.meta.header.cluster_size()
    }

    /// The cluster_bits value from the header.
    pub fn cluster_bits(&self) -> u32 {
        self.meta.header.cluster_bits
    }

    /// Whether the image is encrypted (crypt_method != 0).
    pub fn is_encrypted(&self) -> bool {
        self.crypt_context.is_some()
    }

    /// The resolved backing file chain, if any.
    pub fn backing_chain(&self) -> Option<&BackingChain> {
        self.backing_chain.as_ref()
    }

    /// Current cache statistics for diagnostics.
    pub fn cache_stats(&self) -> &CacheStats {
        self.meta.cache.stats()
    }

    /// Current cache write mode.
    pub fn cache_mode(&self) -> CacheMode {
        self.meta.cache.mode()
    }

    /// Set the cache write mode.
    ///
    /// When switching from WriteBack to WriteThrough, all dirty entries are
    /// flushed to disk first. Switching from WriteThrough to WriteBack is
    /// always safe (no flush needed).
    pub fn set_cache_mode(&mut self, mode: CacheMode) -> Result<()> {
        if self.meta.cache.mode() == mode {
            return Ok(());
        }
        // Flush dirty entries before switching to WriteThrough
        if mode == CacheMode::WriteThrough {
            self.flush_dirty_metadata()?;
        }
        self.meta.cache.set_mode(mode);
        Ok(())
    }

    /// Access the underlying I/O backend.
    ///
    /// Useful for CLI tools that need to read raw metadata directly.
    pub fn backend(&self) -> &dyn IoBackend {
        self.backend.as_ref()
    }

    /// The I/O backend for guest data clusters.
    ///
    /// Returns the external data file backend if present, otherwise the main backend.
    pub fn data_backend(&self) -> &dyn IoBackend {
        self.data_backend
            .as_deref()
            .unwrap_or(self.backend.as_ref())
    }

    /// Whether this image uses an external data file.
    pub fn has_external_data_file(&self) -> bool {
        self.data_backend.is_some()
    }

    /// Set the external data backend (for testing or caller-provided backends).
    pub fn set_data_backend(&mut self, backend: Box<dyn IoBackend>) {
        self.data_backend = Some(backend);
    }

    /// The current read mode.
    pub fn read_mode(&self) -> ReadMode {
        self.meta.read_mode
    }

    /// Change the read mode for subsequent reads.
    pub fn set_read_mode(&mut self, mode: ReadMode) {
        self.meta.read_mode = mode;
    }

    /// Warnings collected during lenient-mode reads.
    ///
    /// Empty in strict mode since errors are returned immediately.
    pub fn warnings(&self) -> &[ReadWarning] {
        &self.meta.warnings
    }

    /// Clear all collected warnings.
    pub fn clear_warnings(&mut self) {
        self.meta.warnings.clear();
    }

    /// Whether the image is opened for writing.
    pub fn is_writable(&self) -> bool {
        self.meta.writable
    }

    /// Whether the DIRTY flag is currently set.
    pub fn is_dirty(&self) -> bool {
        self.meta.dirty
    }

    /// Enable or disable dirty flag suppression.
    ///
    /// When enabled, write operations set `dirty = true` in memory but do NOT
    /// write the DIRTY incompatible feature flag to the on-disk header.
    /// This is used with streaming backends where the header must remain
    /// clean (no patching of already-written regions).
    pub fn set_skip_dirty_marking(&mut self, skip: bool) {
        self.meta.skip_dirty_marking = skip;
    }
}
