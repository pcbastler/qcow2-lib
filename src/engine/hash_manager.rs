//! BLAKE3 per-cluster hash management.
//!
//! The [`HashManager`] is a transient helper that borrows components from
//! [`Qcow2Image`](super::image::Qcow2Image) for the duration of a hash
//! operation. This follows the same borrow-based pattern as
//! [`BitmapManager`](super::bitmap_manager::BitmapManager).

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::{ClusterMapper, ClusterResolution};
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::feature_flags::AutoclearFeatures;
use crate::format::hash::{Blake3Extension, HashTable, HashTableEntry};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::types::*;
use crate::io::IoBackend;

/// Offset of the autoclear_features field in the QCOW2 header.
const OFF_AUTOCLEAR_FEATURES: u64 = 88;

/// Information about a hash mismatch found during verification.
#[derive(Debug, Clone)]
pub struct HashMismatch {
    /// Cluster index where the mismatch was found.
    pub cluster_index: u64,
    /// Guest byte offset of the cluster.
    pub guest_offset: u64,
    /// Expected hash (from the stored hash data).
    pub expected: Vec<u8>,
    /// Actual computed hash of the cluster data.
    pub actual: Vec<u8>,
}

/// A single exported hash entry.
#[derive(Debug, Clone)]
pub struct HashEntry {
    /// Cluster index.
    pub cluster_index: u64,
    /// Guest byte offset of the cluster.
    pub guest_offset: u64,
    /// The stored hash value.
    pub hash: Vec<u8>,
    /// Whether the cluster is currently allocated.
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
}

/// Transient helper for per-cluster hash operations.
///
/// Borrows the mutable state needed from `Qcow2Image` for the duration
/// of a single hash operation.
#[allow(clippy::too_many_arguments)]
pub struct HashManager<'a> {
    backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    refcount_manager: &'a mut RefcountManager,
    header: &'a mut Header,
    extensions: &'a mut Vec<HeaderExtension>,
    mapper: &'a ClusterMapper,
    cluster_bits: u32,
    virtual_size: u64,
}

impl<'a> HashManager<'a> {
    /// Create a new hash manager borrowing the image's state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        refcount_manager: &'a mut RefcountManager,
        header: &'a mut Header,
        extensions: &'a mut Vec<HeaderExtension>,
        mapper: &'a ClusterMapper,
        cluster_bits: u32,
        virtual_size: u64,
    ) -> Self {
        Self {
            backend,
            cache,
            refcount_manager,
            header,
            extensions,
            mapper,
            cluster_bits,
            virtual_size,
        }
    }

    // ---- Public operations ----

    /// Whether a hash extension exists.
    pub fn has_hashes(&self) -> bool {
        self.find_extension().is_some()
    }

    /// Get summary info about the hash extension.
    pub fn info(&self) -> Option<HashInfo> {
        self.find_extension().map(|ext| HashInfo {
            hash_size: ext.hash_size,
            hash_table_entries: ext.hash_table_entries,
            consistent: self
                .header
                .autoclear_features
                .contains(AutoclearFeatures::BLAKE3_HASHES),
        })
    }

    /// Initialize the hash extension (creates empty hash table, no hashing yet).
    pub fn init_hashes(&mut self, hash_size: u8) -> Result<()> {
        if hash_size != BLAKE3_MIN_HASH_SIZE && hash_size != BLAKE3_MAX_HASH_SIZE {
            return Err(Error::InvalidHashSize { size: hash_size });
        }

        if self.find_extension().is_some() {
            return Err(Error::InvalidHashExtension {
                message: "hash extension already exists".to_string(),
            });
        }

        let cluster_size = self.cluster_size();
        let hash_table_entries =
            crate::format::hash::compute_hash_table_entries(self.virtual_size, cluster_size, hash_size);

        // Allocate cluster(s) for the hash table (all zeros)
        let table_byte_size = hash_table_entries as u64 * HASH_TABLE_ENTRY_SIZE as u64;
        let table_clusters = ((table_byte_size + cluster_size - 1) / cluster_size).max(1);

        let first_offset = self
            .refcount_manager
            .allocate_cluster(self.backend, self.cache)?;
        for _ in 1..table_clusters {
            self.refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
        }

        // Write zeros (table is already zeroed by allocator, but be explicit)
        let table_data = vec![0u8; (table_clusters * cluster_size) as usize];
        self.backend.write_all_at(&table_data, first_offset.0)?;

        // Build extension and add to extensions list
        let ext = Blake3Extension {
            hash_table_offset: first_offset.0,
            hash_table_entries,
            hash_size,
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

    /// Rehash all allocated clusters. Returns the number of clusters hashed.
    pub fn rehash(&mut self) -> Result<u64> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let total_clusters = (self.virtual_size + cluster_size - 1) / cluster_size;
        let zero_hash = compute_zero_hash(cluster_size as usize, ext.hash_size);
        let mut table = self.load_hash_table(&ext)?;
        let mut count = 0u64;

        for cluster_idx in 0..total_clusters {
            let guest_offset = cluster_idx * cluster_size;
            let resolution =
                self.mapper
                    .resolve(GuestOffset(guest_offset), self.backend, self.cache)?;

            let hash_bytes = match resolution {
                ClusterResolution::Allocated { host_offset, .. } => {
                    let mut data = vec![0u8; cluster_size as usize];
                    self.backend.read_exact_at(&mut data, host_offset.0)?;
                    compute_hash(&data, hash_size)
                }
                ClusterResolution::Zero => zero_hash.clone(),
                ClusterResolution::Compressed {
                    descriptor,
                    ..
                } => {
                    let file_size = self.backend.file_size()?;
                    let available = file_size.saturating_sub(descriptor.host_offset);
                    let read_size =
                        (descriptor.compressed_size as usize).min(available as usize);
                    let mut compressed_data = vec![0u8; read_size];
                    self.backend
                        .read_exact_at(&mut compressed_data, descriptor.host_offset)?;
                    let decompressed = crate::engine::compression::decompress_cluster(
                        &compressed_data,
                        cluster_size as usize,
                        guest_offset,
                    )?;
                    compute_hash(&decompressed, hash_size)
                }
                ClusterResolution::Unallocated => continue,
            };

            self.store_hash(cluster_idx, &hash_bytes, &mut table, &ext)?;
            count += 1;
        }

        // Write updated hash table back
        self.write_hash_table(&table, ext.hash_table_offset)?;
        self.backend.flush()?;
        Ok(count)
    }

    /// Update hashes for all clusters touched by a write at [guest_offset, guest_offset+len).
    pub fn update_hashes_for_range(&mut self, guest_offset: u64, len: u64) -> Result<()> {
        let ext = match self.find_extension() {
            Some(ext) => ext.clone(),
            None => return Ok(()),
        };

        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let first_cluster = guest_offset / cluster_size;
        let last_cluster = (guest_offset + len - 1) / cluster_size;
        let mut table = self.load_hash_table(&ext)?;

        for cluster_idx in first_cluster..=last_cluster {
            let g_off = cluster_idx * cluster_size;
            let resolution =
                self.mapper
                    .resolve(GuestOffset(g_off), self.backend, self.cache)?;

            if let ClusterResolution::Allocated { host_offset, .. } = resolution {
                let mut data = vec![0u8; cluster_size as usize];
                self.backend.read_exact_at(&mut data, host_offset.0)?;
                let hash_bytes = compute_hash(&data, hash_size);
                self.store_hash(cluster_idx, &hash_bytes, &mut table, &ext)?;
            }
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
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table = self.load_hash_table(&ext)?;
        let zero_hash = compute_zero_hash(cluster_size as usize, ext.hash_size);
        let null_hash = vec![0u8; hash_size];
        let mut mismatches = Vec::new();

        for table_idx in 0..table.len() {
            let entry = table.get(table_idx).unwrap();
            let data_offset = match entry.data_offset() {
                Some(off) => off,
                None => continue,
            };

            // Read hash data cluster
            let mut hash_data = vec![0u8; cluster_size as usize];
            self.backend.read_exact_at(&mut hash_data, data_offset)?;

            for hash_idx in 0..hashes_per_data_cluster {
                let cluster_idx =
                    table_idx as u64 * hashes_per_data_cluster as u64 + hash_idx as u64;
                let total_clusters = (self.virtual_size + cluster_size - 1) / cluster_size;
                if cluster_idx >= total_clusters {
                    break;
                }

                let stored_start = hash_idx * hash_size;
                let stored = &hash_data[stored_start..stored_start + hash_size];
                if stored == null_hash.as_slice() {
                    continue; // No hash stored
                }

                let guest_offset = cluster_idx * cluster_size;
                let resolution = self.mapper.resolve(
                    GuestOffset(guest_offset),
                    self.backend,
                    self.cache,
                )?;

                let actual = match resolution {
                    ClusterResolution::Allocated { host_offset, .. } => {
                        let mut data = vec![0u8; cluster_size as usize];
                        self.backend.read_exact_at(&mut data, host_offset.0)?;
                        compute_hash(&data, hash_size)
                    }
                    ClusterResolution::Zero => zero_hash.clone(),
                    ClusterResolution::Compressed { descriptor, .. } => {
                        let file_size = self.backend.file_size()?;
                        let available =
                            file_size.saturating_sub(descriptor.host_offset);
                        let read_size =
                            (descriptor.compressed_size as usize).min(available as usize);
                        let mut comp_buf = vec![0u8; read_size];
                        self.backend
                            .read_exact_at(&mut comp_buf, descriptor.host_offset)?;
                        let decompressed = crate::engine::compression::decompress_cluster(
                            &comp_buf,
                            cluster_size as usize,
                            guest_offset,
                        )?;
                        compute_hash(&decompressed, hash_size)
                    }
                    ClusterResolution::Unallocated => {
                        // Hash exists but cluster is unallocated → mismatch
                        mismatches.push(HashMismatch {
                            cluster_index: cluster_idx,
                            guest_offset,
                            expected: stored.to_vec(),
                            actual: null_hash.clone(),
                        });
                        continue;
                    }
                };

                if actual != stored {
                    mismatches.push(HashMismatch {
                        cluster_index: cluster_idx,
                        guest_offset,
                        expected: stored.to_vec(),
                        actual,
                    });
                }
            }
        }

        Ok(mismatches)
    }

    /// Get the stored hash for a specific cluster index.
    pub fn get_hash(&mut self, cluster_index: u64) -> Result<Option<Vec<u8>>> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table_idx = (cluster_index / hashes_per_data_cluster as u64) as u32;
        let hash_idx = (cluster_index % hashes_per_data_cluster as u64) as usize;

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

    /// Export hashes for a range of clusters (or all if range is None).
    pub fn export_hashes(
        &mut self,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<HashEntry>> {
        let ext = self
            .find_extension()
            .ok_or(Error::HashNotInitialized)?
            .clone();

        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let total_clusters = (self.virtual_size + cluster_size - 1) / cluster_size;
        let (start_cluster, end_cluster) = match range {
            Some((start, end)) => (start / cluster_size, (end + cluster_size - 1) / cluster_size),
            None => (0, total_clusters),
        };

        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table = self.load_hash_table(&ext)?;
        let null_hash = vec![0u8; hash_size];
        let mut entries = Vec::new();

        for cluster_idx in start_cluster..end_cluster.min(total_clusters) {
            let table_idx = (cluster_idx / hashes_per_data_cluster as u64) as u32;
            let hash_idx = (cluster_idx % hashes_per_data_cluster as u64) as usize;

            let hash = if let Some(entry) = table.get(table_idx) {
                if let Some(data_offset) = entry.data_offset() {
                    let mut hash_data = vec![0u8; cluster_size as usize];
                    self.backend.read_exact_at(&mut hash_data, data_offset)?;
                    let start = hash_idx * hash_size;
                    hash_data[start..start + hash_size].to_vec()
                } else {
                    null_hash.clone()
                }
            } else {
                null_hash.clone()
            };

            let guest_offset = cluster_idx * cluster_size;
            let allocated = !matches!(
                self.mapper
                    .resolve(GuestOffset(guest_offset), self.backend, self.cache)?,
                ClusterResolution::Unallocated
            );

            if hash != null_hash {
                entries.push(HashEntry {
                    cluster_index: cluster_idx,
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

    fn load_hash_table(&self, ext: &Blake3Extension) -> Result<HashTable> {
        if ext.hash_table_entries == 0 {
            return Ok(HashTable::new_empty(0));
        }
        let byte_size = ext.hash_table_entries as usize * HASH_TABLE_ENTRY_SIZE;
        let mut buf = vec![0u8; byte_size];
        self.backend
            .read_exact_at(&mut buf, ext.hash_table_offset)?;
        HashTable::read_from(&buf, ext.hash_table_entries)
    }

    fn write_hash_table(&self, table: &HashTable, offset: u64) -> Result<()> {
        let data = table.write_to();
        self.backend.write_all_at(&data, offset)?;
        Ok(())
    }

    fn write_extensions_to_disk(&self) -> Result<()> {
        let ext_data = HeaderExtension::write_all(self.extensions);
        let ext_start = self.header.header_length as u64;
        let cluster_size = self.cluster_size();

        if ext_start + ext_data.len() as u64 > cluster_size {
            return Err(Error::InvalidHashExtension {
                message: format!(
                    "header extensions ({} bytes) exceed cluster 0 ({} bytes)",
                    ext_start as usize + ext_data.len(),
                    cluster_size
                ),
            });
        }

        self.backend.write_all_at(&ext_data, ext_start)?;
        Ok(())
    }

    fn write_autoclear_features(&self) -> Result<()> {
        let mut buf = [0u8; 8];
        BigEndian::write_u64(&mut buf, self.header.autoclear_features.bits());
        self.backend.write_all_at(&buf, OFF_AUTOCLEAR_FEATURES)?;
        Ok(())
    }

    /// Store a hash for a given cluster, handling COW on hash data clusters.
    fn store_hash(
        &mut self,
        cluster_idx: u64,
        hash_bytes: &[u8],
        table: &mut HashTable,
        ext: &Blake3Extension,
    ) -> Result<()> {
        let cluster_size = self.cluster_size();
        let hash_size = ext.hash_size as usize;
        let hashes_per_data_cluster = cluster_size as usize / hash_size;
        let table_idx = (cluster_idx / hashes_per_data_cluster as u64) as u32;
        let hash_idx = (cluster_idx % hashes_per_data_cluster as u64) as usize;

        let entry = match table.get(table_idx) {
            Some(e) => *e,
            None => return Ok(()), // Out of range
        };

        let data_offset = if entry.is_empty() {
            // Allocate a new hash data cluster
            let new_offset = self
                .refcount_manager
                .allocate_cluster(self.backend, self.cache)?;
            let zeros = vec![0u8; cluster_size as usize];
            self.backend.write_all_at(&zeros, new_offset.0)?;
            table.set(table_idx, HashTableEntry::with_offset(new_offset.0));
            new_offset.0
        } else {
            let offset = entry.data_offset().unwrap();
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
        };

        // Write the hash into the data cluster
        let write_offset = data_offset + (hash_idx * hash_size) as u64;
        self.backend.write_all_at(hash_bytes, write_offset)?;
        self.cache.evict_hash_data(ClusterOffset(data_offset));

        Ok(())
    }
}

/// Compute a BLAKE3 hash, truncated to `hash_size` bytes.
fn compute_hash(data: &[u8], hash_size: usize) -> Vec<u8> {
    let hash = blake3::hash(data);
    hash.as_bytes()[..hash_size].to_vec()
}

/// Compute the BLAKE3 hash of an all-zero cluster.
fn compute_zero_hash(cluster_size: usize, hash_size: u8) -> Vec<u8> {
    let zeros = vec![0u8; cluster_size];
    compute_hash(&zeros, hash_size as usize)
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
    use crate::engine::image::{CreateOptions, Qcow2Image};
    use crate::io::MemoryBackend;

    fn create_test_image(virtual_size: u64) -> Qcow2Image {
        Qcow2Image::create_on_backend(
            Box::new(MemoryBackend::zeroed(0)),
            CreateOptions {
                virtual_size,
                cluster_bits: None,
            },
        )
        .unwrap()
    }

    #[allow(dead_code)]
    fn create_hash_manager(_image: &mut Qcow2Image) -> HashManager<'_> {
        // We need to access internal fields — use the image API methods instead
        // This helper is not used; tests call image-level methods
        unreachable!()
    }

    // Tests that exercise through the image API will be in Phase 3.
    // Here we test the standalone helpers.

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
    fn zero_hash_differs_by_cluster_size() {
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
        })];
        assert!(detect_hashes(&exts));
    }

    #[test]
    fn detect_hashes_other_extensions() {
        let exts = vec![HeaderExtension::BackingFileFormat("qcow2".to_string())];
        assert!(!detect_hashes(&exts));
    }
}
