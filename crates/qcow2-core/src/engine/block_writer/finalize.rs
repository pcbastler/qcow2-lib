//! Finalize algorithm: write all metadata to produce a valid QCOW2 image.
//!
//! The finalize phase writes L2 tables, refcount structures, L1 table, and
//! the header. It handles the chicken-and-egg problem where metadata clusters
//! need refcount coverage and refcount clusters need their own coverage.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Result;
use crate::format::constants::{COMPRESSION_DEFLATE, CRYPT_LUKS, HEADER_V3_MIN_LENGTH, VERSION_3};
use crate::format::feature_flags::{
    AutoclearFeatures, CompatibleFeatures, IncompatibleFeatures,
};
use crate::format::hash::{Blake3Extension, HashTable, HashTableEntry, compute_hash_table_entries};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::refcount::RefcountTableEntry;
use crate::format::types::ClusterOffset;
use crate::io::{Compressor, IoBackend};

use super::engine::BlockWriterEngine;

impl BlockWriterEngine {
    /// Finalize the image: write all metadata to the backend.
    ///
    /// This method:
    /// 1. Flushes all remaining buffered clusters
    /// 2. Writes hash structures (if blake3 hashing enabled)
    /// 3. Writes L2 tables to disk
    /// 4. Writes L1 table to disk
    /// 5. Builds and writes refcount structures (with convergence loop)
    /// 6. Writes the header at offset 0
    /// 7. Writes LUKS header data (if encrypted)
    ///
    /// After this call, the image is a valid, self-contained QCOW2 file.
    pub fn finalize(
        &mut self,
        backend: &dyn IoBackend,
        compressor: &dyn Compressor,
        crypt_context: Option<&crate::engine::encryption::CryptContext>,
    ) -> Result<()> {
        if self.finalized {
            return Err(crate::error::Error::BlockWriterFinalized);
        }

        // 1. Flush all remaining buffered clusters
        self.flush_all_remaining(backend, compressor, crypt_context)?;

        // 2. Write hash structures (before other metadata for refcount coverage)
        self.write_hash_structures(backend)?;

        // 3. Write L2 tables, collect their host offsets
        let l2_offsets = self.write_l2_tables(backend)?;

        // 4. Build and write L1 table
        let (l1_offset, _l1_clusters) = self.write_l1_table(backend, &l2_offsets)?;

        // 5. Build and write refcount structures (iterative convergence)
        let (rt_offset, rt_clusters) = self.write_refcount_structures(backend)?;

        // 6. Write header at offset 0
        self.write_header(backend, l1_offset, rt_offset, rt_clusters)?;

        // 7. Write LUKS header data
        if let Some(ref luks_data) = self.luks_header_data {
            let padded_len = self.luks_clusters as usize * self.cluster_size as usize;
            let mut padded = vec![0u8; padded_len];
            let copy_len = luks_data.len().min(padded_len);
            padded[..copy_len].copy_from_slice(&luks_data[..copy_len]);
            backend.write_all_at(&padded, self.cluster_size)?;
        }

        backend.flush()?;
        self.finalized = true;
        Ok(())
    }

    /// Write blake3 hash structures to disk (hash data clusters + hash table).
    ///
    /// Skips if hashing is not enabled. Must be called before L2/L1/refcount
    /// writes so that hash clusters get proper refcount coverage.
    fn write_hash_structures(&mut self, backend: &dyn IoBackend) -> Result<()> {
        let hash_size = match self.config.hash_size {
            Some(s) => s,
            None => return Ok(()),
        };

        let cluster_size = self.cluster_size;
        let hashes_per_data_cluster = cluster_size / hash_size as u64;

        // hash_chunk_bits = cluster_bits (1 hash per cluster for block writer)
        let hash_chunk_size = cluster_size;
        let hash_table_entries = compute_hash_table_entries(
            self.config.virtual_size,
            cluster_size,
            hash_size,
            hash_chunk_size,
        );

        if hash_table_entries == 0 {
            return Ok(());
        }

        let mut hash_table = HashTable::new_empty(hash_table_entries);

        // Write hash data clusters
        for ht_idx in 0..hash_table_entries {
            let start_chunk = ht_idx as u64 * hashes_per_data_cluster;
            let end_chunk = start_chunk + hashes_per_data_cluster;

            // Check if any hashes exist in this range
            let has_any = self
                .hashes
                .range(start_chunk..end_chunk)
                .next()
                .is_some();

            if !has_any {
                continue;
            }

            // Build hash data cluster
            let mut data_buf = vec![0u8; cluster_size as usize];
            for (&chunk_idx, hash_bytes) in self.hashes.range(start_chunk..end_chunk) {
                let slot = (chunk_idx - start_chunk) as usize;
                let offset = slot * hash_size as usize;
                let end = offset + hash_size as usize;
                if end <= data_buf.len() {
                    data_buf[offset..end].copy_from_slice(hash_bytes);
                }
            }

            // Allocate, write, refcount
            let host_offset = self.metadata.allocate_cluster();
            backend.write_all_at(&data_buf, host_offset.0)?;
            self.metadata.increment_refcount(host_offset.0);
            hash_table.set(ht_idx, HashTableEntry::with_offset(host_offset.0));
        }

        // Write hash table
        let ht_bytes = hash_table.write_to();
        let ht_byte_size = ht_bytes.len() as u64;
        let ht_clusters = (ht_byte_size + cluster_size - 1) / cluster_size;
        let ht_clusters = ht_clusters.max(1);

        let ht_offset = self.metadata.allocate_n_clusters(ht_clusters);
        let mut ht_buf = vec![0u8; ht_clusters as usize * cluster_size as usize];
        ht_buf[..ht_bytes.len()].copy_from_slice(&ht_bytes);
        backend.write_all_at(&ht_buf, ht_offset.0)?;

        for i in 0..ht_clusters {
            self.metadata
                .increment_refcount(ht_offset.0 + i * cluster_size);
        }

        // Add blake3 header extension
        let ext = Blake3Extension {
            hash_table_offset: ht_offset.0,
            hash_table_entries,
            hash_size,
            hash_chunk_bits: self.config.cluster_bits as u8,
        };
        self.extensions
            .push(HeaderExtension::Blake3Hashes(ext));

        Ok(())
    }

    /// Write all populated L2 tables to disk. Returns L1 index → host offset mapping.
    fn write_l2_tables(
        &mut self,
        backend: &dyn IoBackend,
    ) -> Result<BTreeMap<u32, ClusterOffset>> {
        let mut l2_offsets = BTreeMap::new();
        let indices = self.metadata.populated_l1_indices();
        let cluster_size = self.cluster_size as usize;

        for l1_index in indices {
            let table = self.metadata.materialize_l2_table(l1_index);
            let host_offset = self.metadata.allocate_cluster();

            let mut buf = vec![0u8; cluster_size];
            table.write_to(&mut buf)?;
            backend.write_all_at(&buf, host_offset.0)?;

            self.metadata.increment_refcount(host_offset.0);
            l2_offsets.insert(l1_index, host_offset);
        }

        Ok(l2_offsets)
    }

    /// Write the L1 table to disk. Returns (host_offset, cluster_count).
    fn write_l1_table(
        &mut self,
        backend: &dyn IoBackend,
        l2_offsets: &BTreeMap<u32, ClusterOffset>,
    ) -> Result<(ClusterOffset, u64)> {
        let l1_table = self.metadata.build_l1_table(l2_offsets);
        let l1_byte_size = self.metadata.l1_entries() as u64 * 8;
        let l1_clusters =
            (l1_byte_size + self.cluster_size - 1) / self.cluster_size;
        let l1_clusters = l1_clusters.max(1);

        let l1_offset = self.metadata.allocate_n_clusters(l1_clusters);

        let mut buf = vec![0u8; l1_clusters as usize * self.cluster_size as usize];
        l1_table.write_to(&mut buf)?;
        backend.write_all_at(&buf, l1_offset.0)?;

        for i in 0..l1_clusters {
            self.metadata
                .increment_refcount(l1_offset.0 + i * self.cluster_size);
        }

        Ok((l1_offset, l1_clusters))
    }

    /// Build and write refcount structures with iterative convergence.
    ///
    /// Returns (refcount_table_offset, refcount_table_clusters).
    fn write_refcount_structures(
        &mut self,
        backend: &dyn IoBackend,
    ) -> Result<(ClusterOffset, u64)> {
        let cluster_size = self.cluster_size;
        let refcount_order = self.metadata.refcount_order();
        let refcount_bits = 1u32 << refcount_order;
        let entries_per_block = (cluster_size as u32 * 8) / refcount_bits;

        // Build metadata refcounts (header, LUKS, L2, L1 clusters)
        let mut meta_refcounts: BTreeMap<u64, u64> = BTreeMap::new();

        // Header cluster (offset 0)
        let header_idx = 0u64;
        *meta_refcounts.entry(header_idx).or_insert(0) += 1;

        // LUKS header clusters
        for i in 0..self.luks_clusters {
            let idx = (cluster_size + i * cluster_size) / cluster_size;
            *meta_refcounts.entry(idx).or_insert(0) += 1;
        }

        // Convergence loop: refcount structures need to cover themselves
        let max_iterations = 5;
        let mut rt_offset = ClusterOffset(0);
        let mut rt_clusters = 0u64;

        for _ in 0..max_iterations {
            // Calculate total clusters that need coverage
            let total_host_end = self.metadata.next_host_offset();
            let total_clusters = total_host_end / cluster_size;

            // How many refcount blocks do we need?
            let num_blocks = if total_clusters == 0 {
                1
            } else {
                (total_clusters + entries_per_block as u64 - 1) / entries_per_block as u64
            };

            // How many clusters for the refcount table?
            let rt_byte_size = num_blocks * 8;
            let new_rt_clusters =
                (rt_byte_size + cluster_size - 1) / cluster_size;
            let new_rt_clusters = new_rt_clusters.max(1);

            // Total metadata clusters: rt + blocks
            let meta_clusters = new_rt_clusters + num_blocks;

            // Allocate space (tentatively)
            let new_rt_offset = ClusterOffset(self.metadata.next_host_offset());

            // Check if we've converged (same count as last iteration)
            if rt_offset.0 != 0 && new_rt_clusters == rt_clusters {
                break;
            }

            // Reserve space for refcount table + blocks
            let _ = self.metadata.allocate_n_clusters(meta_clusters);

            // Add refcounts for these metadata clusters
            for i in 0..meta_clusters {
                let cluster_off = new_rt_offset.0 + i * cluster_size;
                let idx = cluster_off / cluster_size;
                *meta_refcounts.entry(idx).or_insert(0) += 1;
            }

            rt_offset = new_rt_offset;
            rt_clusters = new_rt_clusters;
        }

        // Now build the actual refcount structures
        let (_, blocks) = self.metadata.build_refcount_structures(&meta_refcounts);

        // Write refcount blocks and build refcount table
        let mut rt_entries: Vec<RefcountTableEntry> = Vec::new();
        let total_host_end = self.metadata.next_host_offset();
        let total_clusters_final = total_host_end / cluster_size;
        let num_blocks_final = if total_clusters_final == 0 {
            1
        } else {
            (total_clusters_final + entries_per_block as u64 - 1) / entries_per_block as u64
        };

        // Layout: [refcount_table | refcount_block_0 | refcount_block_1 | ...]
        let rb_start = ClusterOffset(rt_offset.0 + rt_clusters * cluster_size);

        for block_idx in 0..num_blocks_final {
            let block_offset = ClusterOffset(rb_start.0 + block_idx * cluster_size);
            rt_entries.push(RefcountTableEntry::with_block_offset(block_offset));

            // Find or create the block
            let block = blocks
                .iter()
                .find(|(idx, _)| *idx == block_idx)
                .map(|(_, b)| b);

            let mut buf = vec![0u8; cluster_size as usize];
            if let Some(b) = block {
                b.write_to(&mut buf)?;
            }
            // else: zero block (all refcounts = 0)

            backend.write_all_at(&buf, block_offset.0)?;
        }

        // Write refcount table
        {
            let mut rt_buf = vec![0u8; rt_clusters as usize * cluster_size as usize];
            crate::format::refcount::write_refcount_table(&rt_entries, &mut rt_buf)?;
            backend.write_all_at(&rt_buf, rt_offset.0)?;
        }

        Ok((rt_offset, rt_clusters))
    }

    /// Write the QCOW2 header at offset 0.
    fn write_header(
        &self,
        backend: &dyn IoBackend,
        l1_offset: ClusterOffset,
        rt_offset: ClusterOffset,
        rt_clusters: u64,
    ) -> Result<()> {
        // Build feature flags
        let mut incompat = IncompatibleFeatures::empty();
        if self.config.extended_l2 {
            incompat |= IncompatibleFeatures::EXTENDED_L2;
        }
        if self.config.compression_type != COMPRESSION_DEFLATE {
            incompat |= IncompatibleFeatures::COMPRESSION_TYPE;
        }

        let header_length = if self.config.compression_type != COMPRESSION_DEFLATE {
            (HEADER_V3_MIN_LENGTH + 1) as u32
        } else {
            HEADER_V3_MIN_LENGTH as u32
        };

        let header = Header {
            version: VERSION_3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: self.config.cluster_bits,
            virtual_size: self.config.virtual_size,
            crypt_method: if self.config.encrypted { CRYPT_LUKS } else { 0 },
            l1_table_entries: self.metadata.l1_entries(),
            l1_table_offset: l1_offset,
            refcount_table_offset: rt_offset,
            refcount_table_clusters: rt_clusters as u32,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: incompat,
            compatible_features: CompatibleFeatures::empty(),
            autoclear_features: if self.config.hash_size.is_some() {
                AutoclearFeatures::BLAKE3_HASHES
            } else {
                AutoclearFeatures::empty()
            },
            refcount_order: self.config.refcount_order,
            header_length,
            compression_type: self.config.compression_type,
        };

        let cluster_size = self.cluster_size as usize;
        let mut buf = vec![0u8; cluster_size];
        header.write_to(&mut buf)?;

        // Write header extensions after the header
        if !self.extensions.is_empty() {
            let ext_data = HeaderExtension::write_all(&self.extensions);
            let ext_offset = header_length as usize;
            if ext_offset + ext_data.len() <= cluster_size {
                buf[ext_offset..ext_offset + ext_data.len()].copy_from_slice(&ext_data);
            }
        }

        backend.write_all_at(&buf, 0)?;

        Ok(())
    }
}
