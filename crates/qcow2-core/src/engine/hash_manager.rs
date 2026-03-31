//! BLAKE3 per-hash-chunk hash management.
//!
//! The [`HashManager`] is a transient helper that borrows components from
//! [`Qcow2Image`](super::image::Qcow2Image) for the duration of a hash
//! operation. This follows the same borrow-based pattern as
//! [`BitmapManager`](super::bitmap_manager::BitmapManager).
//!
//! The hash granularity (`hash_chunk_size`) is independent of the QCOW2
//! cluster size and is stored as `hash_chunk_bits` in the [`Blake3Extension`].

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::{ClusterMapper, ClusterResolution};
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, FormatError, Result};
use crate::format::constants::*;
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::hash::{Blake3Extension, HashTable, HashTableEntry};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::types::*;
use crate::io::{Compressor, IoBackend};

/// Information about a hash mismatch found during verification.
#[derive(Debug, Clone)]
pub struct HashMismatch {
    /// Hash chunk index where the mismatch was found.
    pub hash_chunk_index: u64,
    /// Guest byte offset of the hash chunk.
    pub guest_offset: u64,
    /// Expected hash (from the stored hash data).
    pub expected: Vec<u8>,
    /// Actual computed hash of the hash chunk data.
    pub actual: Vec<u8>,
}

/// A single exported hash entry.
#[derive(Debug, Clone)]
pub struct HashEntry {
    /// Hash chunk index.
    pub hash_chunk_index: u64,
    /// Guest byte offset of the hash chunk.
    pub guest_offset: u64,
    /// The stored hash value.
    pub hash: Vec<u8>,
    /// Whether the hash chunk has any allocated data.
    pub allocated: bool,
}

/// Summary information about the hash extension.
#[derive(Debug, Clone)]
pub struct HashInfo {
    /// Hash size in bytes (16 or 32).
    pub hash_size: u8,
    /// Number of hash table entries.
    pub hash_table_entries: u32,
    /// Whether the autoclear bit is set (hashes consistent).
    pub consistent: bool,
    /// Hash chunk granularity in bits (e.g. 16 = 64KB).
    pub hash_chunk_bits: u8,
}

/// Transient helper for per-hash-chunk hash operations.
///
/// Borrows the mutable state needed from `Qcow2Image` for the duration
/// of a single hash operation.
#[allow(clippy::too_many_arguments)]
pub struct HashManager<'a> {
    backend: &'a dyn IoBackend,
    /// Backend for guest data clusters (external data file or same as backend).
    data_backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    header: &'a mut Header,
    extensions: &'a mut Vec<HeaderExtension>,
    mapper: &'a ClusterMapper,
    cluster_bits: u32,
    virtual_size: u64,
    compression_type: u8,
    crypt_context: Option<&'a crate::engine::encryption::CryptContext>,
    compressor: &'a dyn Compressor,
}

impl<'a> HashManager<'a> {
    /// Create a new hash manager borrowing the image's state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: &'a dyn IoBackend,
        data_backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        header: &'a mut Header,
        extensions: &'a mut Vec<HeaderExtension>,
        mapper: &'a ClusterMapper,
        cluster_bits: u32,
        virtual_size: u64,
        compression_type: u8,
        crypt_context: Option<&'a crate::engine::encryption::CryptContext>,
        compressor: &'a dyn Compressor,
    ) -> Self {
        Self {
            backend,
            data_backend,
            cache,
            refcount_manager,
            header,
            extensions,
            mapper,
            cluster_bits,
            virtual_size,
            compression_type,
            crypt_context,
            compressor,
        }
    }

    // ---- Public operations ----

    /// Whether a hash extension exists.
    pub fn has_hashes(&self) -> bool {
        self.find_extension().is_some()
    }

    /// Get summary info about the hash extension.
    pub fn info(&self) -> Option<HashInfo> {
        self.find_extension().map(|ext| {
            let resolved_bits = if ext.hash_chunk_bits == 0 {
                BLAKE3_DEFAULT_HASH_CHUNK_BITS
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
        })
    }

    /// Initialize the hash extension (creates empty hash table, no hashing yet).
    ///
    /// `hash_chunk_bits` controls the hash granularity: 0 means default (16 = 64KB),
    /// otherwise must be in the range 12–24.
    pub fn init_hashes(&mut self, hash_size: u8, hash_chunk_bits: u8) -> Result<()> {
        if hash_size != BLAKE3_MIN_HASH_SIZE && hash_size != BLAKE3_MAX_HASH_SIZE {
            return Err(FormatError::InvalidHashSize { size: hash_size }.into());
        }

        if hash_chunk_bits != 0
            && !(BLAKE3_MIN_HASH_CHUNK_BITS..=BLAKE3_MAX_HASH_CHUNK_BITS)
                .contains(&hash_chunk_bits)
        {
            return Err(FormatError::InvalidHashChunkBits {
                bits: hash_chunk_bits,
                min: BLAKE3_MIN_HASH_CHUNK_BITS,
                max: BLAKE3_MAX_HASH_CHUNK_BITS,
            }
            .into());
        }

        if self.find_extension().is_some() {
            return Err(FormatError::InvalidHashExtension {
                message: "hash extension already exists".to_string(),
            }
            .into());
        }

        let cluster_size = self.cluster_size();
        let hash_chunk_size = resolve_hash_chunk_size(hash_chunk_bits);
        let hash_table_entries = crate::format::hash::compute_hash_table_entries(
            self.virtual_size,
            cluster_size,
            hash_size,
            hash_chunk_size,
        );

        // Allocate cluster(s) for the hash table (all zeros)
        let table_byte_size = hash_table_entries as u64 * HASH_TABLE_ENTRY_SIZE as u64;
        let table_clusters = ((table_byte_size + cluster_size - 1) / cluster_size).max(1);

        let first_offset = self.refcount_manager.allocate_contiguous_clusters(
            table_clusters,
            self.backend,
            self.cache,
        )?;

        // Write zeros (table is already zeroed by allocator, but be explicit)
        let table_data = vec![0u8; (table_clusters * cluster_size) as usize];
        self.backend.write_all_at(&table_data, first_offset.0)?;

        // Build extension and add to extensions list
        let ext = Blake3Extension {
            hash_table_offset: first_offset.0,
            hash_table_entries,
            hash_size,
            hash_chunk_bits,
        };
        self.extensions
            .push(HeaderExtension::Blake3Hashes(ext));
        self.write_extensions_to_disk()?;

        // Set autoclear bit
        self.header.autoclear_features |= AutoclearFeatures::BLAKE3_HASHES;
        self.write_autoclear_features()?;

        self.backend.flush()?;
        Ok(())
    }

    /// Remove the hash extension and free all hash clusters.
    pub fn remove_hashes(&mut self) -> Result<()> {
        let ext = match self.find_extension() {
            Some(ext) => ext.clone(),
            None => return Ok(()),
        };

        let cluster_size = self.cluster_size();

        // Load hash table and free data clusters
        if ext.hash_table_offset != 0 && ext.hash_table_entries > 0 {
            let table = self.load_hash_table(&ext)?;
            for entry in table.iter() {
                if let Some(offset) = entry.data_offset() {
                    self.refcount_manager
                        .decrement_refcount(offset, self.backend, self.cache)?;
                }
            }

            // Free hash table clusters
            let table_byte_size = ext.hash_table_entries as u64 * HASH_TABLE_ENTRY_SIZE as u64;
            let table_clusters = (table_byte_size + cluster_size - 1) / cluster_size;
            for i in 0..table_clusters {
                let offset = ext.hash_table_offset + i * cluster_size;
                self.refcount_manager
                    .decrement_refcount(offset, self.backend, self.cache)?;
            }
        }

        // Remove extension from list
        self.extensions
            .retain(|e| !matches!(e, HeaderExtension::Blake3Hashes(_)));
        self.write_extensions_to_disk()?;

        // Clear autoclear bit
        self.header.autoclear_features -= AutoclearFeatures::BLAKE3_HASHES;
        self.write_autoclear_features()?;

        self.backend.flush()?;
        Ok(())
    }

    /// Rehash all hash chunks that contain allocated data.
    /// Returns the number of hash chunks hashed.
    pub fn rehash(&mut self) -> Result<u64> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let hash_chunk_size = ext.hash_chunk_size();
        let hash_size = ext.hash_size as usize;
        let total_hash_chunks = (self.virtual_size + hash_chunk_size - 1) / hash_chunk_size;
        let mut table = self.load_hash_table(&ext)?;
        let mut count = 0u64;

        for chunk_idx in 0..total_hash_chunks {
            let chunk_offset = chunk_idx * hash_chunk_size;
            let (data, has_data) = self.read_hash_chunk(chunk_offset, hash_chunk_size)?;

            if !has_data {
                continue;
            }

            let hash_bytes = compute_hash(&data, hash_size);
            self.store_hash(chunk_idx, &hash_bytes, &mut table, &ext)?;
            count += 1;
        }

        // Write updated hash table back
        self.write_hash_table(&table, ext.hash_table_offset)?;
        self.backend.flush()?;
        Ok(count)
    }

    /// Update hashes for all hash chunks touched by a write at [guest_offset, guest_offset+len).
    pub fn update_hashes_for_range(&mut self, guest_offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let ext = match self.find_extension() {
            Some(ext) => ext.clone(),
            None => return Ok(()),
        };

        let hash_chunk_size = ext.hash_chunk_size();
        let hash_size = ext.hash_size as usize;
        let first_chunk = guest_offset / hash_chunk_size;
        let last_chunk = (guest_offset + len - 1) / hash_chunk_size;
        let mut table = self.load_hash_table(&ext)?;

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_offset = chunk_idx * hash_chunk_size;
            let (data, _) = self.read_hash_chunk(chunk_offset, hash_chunk_size)?;
            let hash_bytes = compute_hash(&data, hash_size);
            self.store_hash(chunk_idx, &hash_bytes, &mut table, &ext)?;
        }

        self.write_hash_table(&table, ext.hash_table_offset)?;
        Ok(())
    }

    /// Verify all stored hashes. Returns a list of mismatches (empty = all OK).
    pub fn verify(&mut self) -> Result<Vec<HashMismatch>> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_chunk_size = ext.hash_chunk_size();
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table = self.load_hash_table(&ext)?;
        let total_hash_chunks = (self.virtual_size + hash_chunk_size - 1) / hash_chunk_size;
        let null_hash = vec![0u8; hash_size];
        let mut mismatches = Vec::new();

        for table_idx in 0..table.len() {
            let Some(entry) = table.get(table_idx) else { continue };
            let data_offset = match entry.data_offset() {
                Some(off) => off,
                None => continue,
            };

            // Read hash data cluster
            let mut hash_data = vec![0u8; cluster_size as usize];
            self.backend.read_exact_at(&mut hash_data, data_offset)?;

            for hash_idx in 0..hashes_per_data_cluster {
                let hash_chunk_idx =
                    table_idx as u64 * hashes_per_data_cluster as u64 + hash_idx as u64;
                if hash_chunk_idx >= total_hash_chunks {
                    break;
                }

                let stored_start = hash_idx * hash_size;
                let stored = &hash_data[stored_start..stored_start + hash_size];
                if stored == null_hash.as_slice() {
                    continue; // No hash stored
                }

                let guest_offset = hash_chunk_idx * hash_chunk_size;
                let (data, has_data) = self.read_hash_chunk(guest_offset, hash_chunk_size)?;

                if !has_data {
                    // Hash exists but hash chunk is entirely unallocated → mismatch
                    mismatches.push(HashMismatch {
                        hash_chunk_index: hash_chunk_idx,
                        guest_offset,
                        expected: stored.to_vec(),
                        actual: null_hash.clone(),
                    });
                    continue;
                }

                let actual = compute_hash(&data, hash_size);
                if actual != stored {
                    mismatches.push(HashMismatch {
                        hash_chunk_index: hash_chunk_idx,
                        guest_offset,
                        expected: stored.to_vec(),
                        actual,
                    });
                }
            }
        }

        Ok(mismatches)
    }

    /// Get the stored hash for a specific hash chunk index.
    pub fn get_hash(&mut self, hash_chunk_index: u64) -> Result<Option<Vec<u8>>> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table_idx = (hash_chunk_index / hashes_per_data_cluster as u64) as u32;
        let hash_idx = (hash_chunk_index % hashes_per_data_cluster as u64) as usize;

        let table = self.load_hash_table(&ext)?;
        let entry = match table.get(table_idx) {
            Some(e) => e,
            None => return Ok(None),
        };

        let data_offset = match entry.data_offset() {
            Some(off) => off,
            None => return Ok(None),
        };

        let mut hash_data = vec![0u8; cluster_size as usize];
        self.backend.read_exact_at(&mut hash_data, data_offset)?;

        let start = hash_idx * hash_size;
        let hash = hash_data[start..start + hash_size].to_vec();

        let null_hash = vec![0u8; hash_size];
        if hash == null_hash {
            Ok(None)
        } else {
            Ok(Some(hash))
        }
    }

    /// Export hashes for a range of guest bytes (or all if range is None).
    pub fn export_hashes(
        &mut self,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<HashEntry>> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_chunk_size = ext.hash_chunk_size();
        let hash_size = ext.hash_size as usize;
        let total_hash_chunks = (self.virtual_size + hash_chunk_size - 1) / hash_chunk_size;
        let (start_chunk, end_chunk) = match range {
            Some((start, end)) => (
                start / hash_chunk_size,
                (end + hash_chunk_size - 1) / hash_chunk_size,
            ),
            None => (0, total_hash_chunks),
        };

        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table = self.load_hash_table(&ext)?;
        let null_hash = vec![0u8; hash_size];
        let mut entries = Vec::new();

        // Cache the current hash data cluster to avoid re-reading it for every chunk
        let mut cached_table_idx: Option<u32> = None;
        let mut cached_data = vec![0u8; cluster_size as usize];

        for chunk_idx in start_chunk..end_chunk.min(total_hash_chunks) {
            let table_idx = (chunk_idx / hashes_per_data_cluster as u64) as u32;
            let hash_idx = (chunk_idx % hashes_per_data_cluster as u64) as usize;

            let hash = if let Some(entry) = table.get(table_idx) {
                if let Some(data_offset) = entry.data_offset() {
                    if cached_table_idx != Some(table_idx) {
                        self.backend
                            .read_exact_at(&mut cached_data, data_offset)?;
                        cached_table_idx = Some(table_idx);
                    }
                    let start = hash_idx * hash_size;
                    cached_data[start..start + hash_size].to_vec()
                } else {
                    null_hash.clone()
                }
            } else {
                null_hash.clone()
            };

            let guest_offset = chunk_idx * hash_chunk_size;
            let allocated = !matches!(
                self.mapper
                    .resolve(GuestOffset(guest_offset), self.backend, self.cache)?,
                ClusterResolution::Unallocated
            );

            if hash != null_hash {
                entries.push(HashEntry {
                    hash_chunk_index: chunk_idx,
                    guest_offset,
                    hash,
                    allocated,
                });
            }
        }

        Ok(entries)
    }

    // ---- Internal helpers ----

    fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    fn find_extension(&self) -> Option<&Blake3Extension> {
        self.extensions.iter().find_map(|e| match e {
            HeaderExtension::Blake3Hashes(ext) => Some(ext),
            _ => None,
        })
    }

    /// Read the data for a hash chunk, handling chunks that span multiple
    /// clusters or are sub-cluster regions.
    ///
    /// Returns `(data, has_data)` where `has_data` is true if any portion
    /// of the chunk is non-unallocated (Allocated, Zero, or Compressed).
    fn read_hash_chunk(
        &mut self,
        hash_chunk_offset: u64,
        hash_chunk_size: u64,
    ) -> Result<(Vec<u8>, bool)> {
        let cluster_size = self.cluster_size();
        let mut data = vec![0u8; hash_chunk_size as usize];
        let mut has_data = false;
        let mut pos = 0u64;

        while pos < hash_chunk_size {
            let guest_off = hash_chunk_offset + pos;
            if guest_off >= self.virtual_size {
                break;
            }

            // How much can we process from this cluster position?
            let intra = guest_off & (cluster_size - 1);
            let remaining_in_cluster = cluster_size - intra;
            let remaining_in_chunk = hash_chunk_size - pos;
            let len = remaining_in_cluster.min(remaining_in_chunk) as usize;

            let resolution =
                self.mapper
                    .resolve(GuestOffset(guest_off), self.backend, self.cache)?;

            match resolution {
                ClusterResolution::Allocated {
                    host_offset,
                    intra_cluster_offset,
                    ..
                } => {
                    has_data = true;
                    if let Some(crypt) = self.crypt_context {
                        // Encrypted: read full cluster, decrypt, extract slice
                        let cs = cluster_size as usize;
                        let mut cluster_buf = vec![0u8; cs];
                        self.data_backend.read_exact_at(&mut cluster_buf, host_offset.0)?;
                        crypt.decrypt_cluster(host_offset.0, &mut cluster_buf)?;
                        let intra = intra_cluster_offset.0 as usize;
                        data[pos as usize..pos as usize + len]
                            .copy_from_slice(&cluster_buf[intra..intra + len]);
                    } else {
                        self.data_backend.read_exact_at(
                            &mut data[pos as usize..pos as usize + len],
                            host_offset.0 + intra_cluster_offset.0 as u64,
                        )?;
                    }
                }
                ClusterResolution::Zero { .. } => {
                    has_data = true;
                    // data is already zeroed
                }
                ClusterResolution::Compressed {
                    descriptor,
                    intra_cluster_offset,
                } => {
                    has_data = true;
                    let file_size = self.backend.file_size()?;
                    let available = file_size.saturating_sub(descriptor.host_offset);
                    let rd_size =
                        (descriptor.compressed_size as usize).min(available as usize);
                    let mut comp_buf = vec![0u8; rd_size];
                    self.backend
                        .read_exact_at(&mut comp_buf, descriptor.host_offset)?;
                    let mut decompressed = vec![0u8; cluster_size as usize];
                    self.compressor.decompress(
                        &comp_buf,
                        &mut decompressed,
                        self.compression_type,
                    )?;
                    let intra = intra_cluster_offset.0 as usize;
                    data[pos as usize..pos as usize + len]
                        .copy_from_slice(&decompressed[intra..intra + len]);
                }
                ClusterResolution::Unallocated => {
                    // data stays zeroed
                }
            }

            pos += len as u64;
        }

        Ok((data, has_data))
    }

    fn load_hash_table(&self, ext: &Blake3Extension) -> Result<HashTable> {
        if ext.hash_table_entries == 0 {
            return Ok(HashTable::new_empty(0));
        }
        let byte_size = ext.hash_table_entries as usize * HASH_TABLE_ENTRY_SIZE;
        let mut buf = vec![0u8; byte_size];
        self.backend
            .read_exact_at(&mut buf, ext.hash_table_offset)?;
        Ok(HashTable::read_from(&buf, ext.hash_table_entries)?)
    }

    fn write_hash_table(&self, table: &HashTable, offset: u64) -> Result<()> {
        let data = table.write_to();
        self.backend.write_all_at(&data, offset)?;
        Ok(())
    }

    fn write_extensions_to_disk(&self) -> Result<()> {
        super::metadata_io::write_header_extensions(
            self.backend,
            self.header,
            self.extensions,
            self.cluster_size(),
        )
    }

    fn write_autoclear_features(&self) -> Result<()> {
        super::metadata_io::write_autoclear_features(
            self.backend,
            self.header.autoclear_features,
        )
    }

    /// Store a hash for a given hash chunk, handling COW on hash data clusters.
    fn store_hash(
        &mut self,
        hash_chunk_idx: u64,
        hash_bytes: &[u8],
        table: &mut HashTable,
        ext: &Blake3Extension,
    ) -> Result<()> {
        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table_idx = (hash_chunk_idx / hashes_per_data_cluster as u64) as u32;
        let hash_idx = (hash_chunk_idx % hashes_per_data_cluster as u64) as usize;

        let entry = match table.get(table_idx) {
            Some(e) => *e,
            None => return Ok(()), // Out of range
        };

        let data_offset = match entry.data_offset() {
            None => {
                // Allocate a new hash data cluster
                let new_offset = self
                    .refcount_manager
                    .allocate_cluster(self.backend, self.cache)?;
                let zeros = vec![0u8; cluster_size as usize];
                self.backend.write_all_at(&zeros, new_offset.0)?;
                table.set(table_idx, HashTableEntry::with_offset(new_offset.0));
                new_offset.0
            }
            Some(offset) => {
                // Check refcount for COW
                let rc = self
                    .refcount_manager
                    .get_refcount(offset, self.backend, self.cache)?;
                if rc > 1 {
                    // COW: copy to new cluster
                    let new_offset = self
                        .refcount_manager
                        .allocate_cluster(self.backend, self.cache)?;
                    let mut old_data = vec![0u8; cluster_size as usize];
                    self.backend.read_exact_at(&mut old_data, offset)?;
                    self.backend.write_all_at(&old_data, new_offset.0)?;
                    self.refcount_manager
                        .decrement_refcount(offset, self.backend, self.cache)?;
                    self.cache.evict_hash_data(ClusterOffset(offset));
                    table.set(table_idx, HashTableEntry::with_offset(new_offset.0));
                    new_offset.0
                } else {
                    offset
                }
            }
        };

        // Write the hash into the data cluster
        let write_offset = data_offset + (hash_idx * hash_size) as u64;
        self.backend.write_all_at(hash_bytes, write_offset)?;
        self.cache.evict_hash_data(ClusterOffset(data_offset));

        Ok(())
    }
}

/// Resolve hash_chunk_bits (0 = default) to hash_chunk_size in bytes.
fn resolve_hash_chunk_size(hash_chunk_bits: u8) -> u64 {
    let bits = if hash_chunk_bits == 0 {
        BLAKE3_DEFAULT_HASH_CHUNK_BITS
    } else {
        hash_chunk_bits
    };
    1u64 << bits
}

/// Compute a BLAKE3 hash, truncated to `hash_size` bytes.
fn compute_hash(data: &[u8], hash_size: usize) -> Vec<u8> {
    let hash = blake3::hash(data);
    hash.as_bytes()[..hash_size].to_vec()
}

/// Check if any hash extension exists in the given extensions list.
pub fn detect_hashes(extensions: &[HeaderExtension]) -> bool {
    extensions
        .iter()
        .any(|e| matches!(e, HeaderExtension::Blake3Hashes(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_zero_hash(size: usize, hash_size: u8) -> Vec<u8> {
        let zeros = vec![0u8; size];
        compute_hash(&zeros, hash_size as usize)
    }

    #[test]
    fn compute_hash_32_bytes() {
        let data = vec![0xAA; 65536];
        let hash = compute_hash(&data, 32);
        assert_eq!(hash.len(), 32);
        // Should be deterministic
        let hash2 = compute_hash(&data, 32);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn compute_hash_16_bytes() {
        let data = vec![0xBB; 65536];
        let hash = compute_hash(&data, 16);
        assert_eq!(hash.len(), 16);
        // Should be prefix of 32-byte hash
        let hash32 = compute_hash(&data, 32);
        assert_eq!(hash, hash32[..16]);
    }

    #[test]
    fn compute_hash_different_data() {
        let data1 = vec![0x00; 65536];
        let data2 = vec![0xFF; 65536];
        let hash1 = compute_hash(&data1, 32);
        let hash2 = compute_hash(&data2, 32);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn zero_hash_is_deterministic() {
        let h1 = compute_zero_hash(65536, 32);
        let h2 = compute_zero_hash(65536, 32);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn zero_hash_differs_by_size() {
        let h1 = compute_zero_hash(65536, 32);
        let h2 = compute_zero_hash(4096, 32);
        assert_ne!(h1, h2);
    }

    #[test]
    fn detect_hashes_empty() {
        assert!(!detect_hashes(&[]));
    }

    #[test]
    fn detect_hashes_present() {
        let exts = vec![HeaderExtension::Blake3Hashes(Blake3Extension {
            hash_table_offset: 0x1_0000,
            hash_table_entries: 1,
            hash_size: 32,
            hash_chunk_bits: 0,
        })];
        assert!(detect_hashes(&exts));
    }

    #[test]
    fn detect_hashes_other_extensions() {
        let exts = vec![HeaderExtension::BackingFileFormat("qcow2".to_string())];
        assert!(!detect_hashes(&exts));
    }

    #[test]
    fn resolve_hash_chunk_size_default() {
        assert_eq!(resolve_hash_chunk_size(0), 65536);
    }

    #[test]
    fn resolve_hash_chunk_size_custom() {
        assert_eq!(resolve_hash_chunk_size(12), 4096);
        assert_eq!(resolve_hash_chunk_size(20), 1 << 20);
    }
}
