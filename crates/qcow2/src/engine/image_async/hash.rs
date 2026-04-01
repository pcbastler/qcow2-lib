//! BLAKE3 hash API on `Qcow2ImageAsync`.

use crate::engine::hash_manager::{self, HashEntry, HashInfo, HashManager, HashMismatch};
use crate::error::{Error, Result};
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::header_extension::HeaderExtension;

use super::{poisoned_err, Qcow2ImageAsync};

impl Qcow2ImageAsync {
    /// Whether the image has a BLAKE3 hash extension.
    pub fn has_hashes(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.has_hashes)
    }

    /// Get summary info about the hash extension.
    pub fn hash_info(&self) -> Result<Option<HashInfo>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;

        if !hash_manager::detect_hashes(&meta.extensions) {
            return Ok(None);
        }
        let ext = meta.extensions.iter().find_map(|e| match e {
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
                Ok(Some(HashInfo {
                    hash_size: ext.hash_size,
                    hash_table_entries: ext.hash_table_entries,
                    consistent: meta
                        .header
                        .autoclear_features
                        .contains(AutoclearFeatures::BLAKE3_HASHES),
                    hash_chunk_bits: resolved_bits,
                }))
            }
            None => unreachable!(),
        }
    }

    /// Get the stored hash for a specific hash chunk index.
    pub fn hash_get(&self, hash_chunk_index: u64) -> Result<Option<Vec<u8>>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.get_hash(hash_chunk_index)
    }

    /// Export hashes for a range of guest bytes (or all if range is None).
    pub fn hash_export(&self, range: Option<(u64, u64)>) -> Result<Vec<HashEntry>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.export_hashes(range)
    }

    /// Verify all stored hashes. Returns a list of mismatches (empty = all OK).
    pub fn hash_verify(&self) -> Result<Vec<HashMismatch>> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::ReadOnly)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.verify()
    }

    /// Initialize the BLAKE3 per-hash-chunk hash extension.
    pub fn hash_init(&self, hash_size: Option<u8>, hash_chunk_bits: Option<u8>) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;

        let hs = hash_size.unwrap_or(crate::format::constants::BLAKE3_DEFAULT_HASH_SIZE);
        let hcb = hash_chunk_bits.unwrap_or(0);

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.init_hashes(hs, hcb)?;
        meta_ref.has_hashes = true;
        Ok(())
    }

    /// Rehash all allocated clusters. Returns the number of clusters hashed.
    pub fn hash_rehash(&self) -> Result<u64> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.rehash()
    }

    /// Remove the hash extension and free all hash clusters.
    pub fn hash_remove(&self) -> Result<()> {
        let mut meta = self.meta.lock().map_err(|_| poisoned_err())?;
        if !meta.writable {
            return Err(Error::ReadOnly);
        }
        let meta_ref = &mut *meta;
        let data_be = self.data_backend.as_deref().unwrap_or(self.backend.as_ref());
        let virtual_size = meta_ref.header.virtual_size;
        let compression_type = meta_ref.header.compression_type;
        let refcount_manager = meta_ref.refcount_manager.as_mut().ok_or(Error::NoRefcountManager)?;

        let mut mgr = HashManager::new(
            self.backend.as_ref(), data_be, &mut meta_ref.cache, refcount_manager,
            &mut meta_ref.header, &mut meta_ref.extensions, &meta_ref.mapper,
            self.cluster_bits, virtual_size, compression_type,
            self.crypt_context.as_ref(), &self.compressor,
        );
        mgr.remove_hashes()?;
        meta_ref.has_hashes = false;
        Ok(())
    }
}
