//! BLAKE3 hash API delegation on `Qcow2Image`.

use crate::engine::hash_manager::{self, HashEntry, HashInfo, HashManager, HashMismatch};
use crate::error::{Error, Result};
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::header_extension::HeaderExtension;

use super::Qcow2Image;

impl Qcow2Image {
    /// Initialize the BLAKE3 per-hash-chunk hash extension.
    ///
    /// Creates an empty hash table without hashing any data yet.
    /// Call `hash_rehash` afterwards to compute hashes for all allocated hash chunks.
    ///
    /// `hash_chunk_bits` controls hash granularity: `None` or `Some(0)` = default 64KB,
    /// otherwise must be 12–24 (4KB–16MB).
    pub fn hash_init(
        &mut self,
        hash_size: Option<u8>,
        hash_chunk_bits: Option<u8>,
    ) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let hs = hash_size.unwrap_or(crate::format::constants::BLAKE3_DEFAULT_HASH_SIZE);
        let hcb = hash_chunk_bits.unwrap_or(0);
        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.init_hashes(hs, hcb)?;
        self.has_hashes = true;
        Ok(())
    }

    /// Rehash all allocated clusters. Returns the number of clusters hashed.
    pub fn hash_rehash(&mut self) -> Result<u64> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.rehash()
    }

    /// Remove the hash extension and free all hash clusters.
    pub fn hash_remove(&mut self) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }

        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.remove_hashes()?;
        self.has_hashes = false;
        Ok(())
    }

    /// Verify all stored hashes. Returns a list of mismatches (empty = all OK).
    pub fn hash_verify(&mut self) -> Result<Vec<HashMismatch>> {
        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.verify()
    }

    /// Get the stored hash for a specific hash chunk index.
    pub fn hash_get(&mut self, hash_chunk_index: u64) -> Result<Option<Vec<u8>>> {
        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.get_hash(hash_chunk_index)
    }

    /// Export hashes for a range of guest bytes (or all if range is None).
    pub fn hash_export(&mut self, range: Option<(u64, u64)>) -> Result<Vec<HashEntry>> {
        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.export_hashes(range)
    }

    /// Update hashes for a written range.
    ///
    /// Called internally by `write_at()` when hashes are active.
    pub(super) fn update_hashes_for_write(&mut self, guest_offset: u64, len: u64) -> Result<()> {
        let cluster_bits = self.header.cluster_bits;
        let virtual_size = self.header.virtual_size;
        let compression_type = self.header.compression_type;
        let data_be: &dyn crate::io::IoBackend = match &self.data_backend {
            Some(db) => db.as_ref(),
            None => self.backend.as_ref(),
        };
        let refcount_manager = self
            .refcount_manager
            .as_mut()
            .expect("writable image must have refcount_manager");

        let mut mgr = HashManager::new(
            self.backend.as_ref(),
            data_be,
            &mut self.cache,
            refcount_manager,
            &mut self.header,
            &mut self.extensions,
            &self.mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            self.crypt_context.as_ref(),
            &self.compressor,
        );
        mgr.update_hashes_for_range(guest_offset, len)
    }

    /// Get summary info about the hash extension.
    pub fn hash_info(&self) -> Option<HashInfo> {
        hash_manager::detect_hashes(&self.extensions).then(|| {
            let ext = self.extensions.iter().find_map(|e| match e {
                HeaderExtension::Blake3Hashes(ext) => Some(ext),
                _ => None,
            });
            match ext {
                Some(ext) => {
                    let resolved_bits = if ext.hash_chunk_bits == 0 {
                        crate::format::constants::BLAKE3_DEFAULT_HASH_CHUNK_BITS
                    } else {
                        ext.hash_chunk_bits
                    };
                    HashInfo {
                        hash_size: ext.hash_size,
                        hash_table_entries: ext.hash_table_entries,
                        consistent: self
                            .header
                            .autoclear_features
                            .contains(AutoclearFeatures::BLAKE3_HASHES),
                        hash_chunk_bits: resolved_bits,
                    }
                }
                None => unreachable!(),
            }
        })
    }

    /// Whether the image has a BLAKE3 hash extension.
    pub fn has_hashes(&self) -> bool {
        self.has_hashes
    }
}
