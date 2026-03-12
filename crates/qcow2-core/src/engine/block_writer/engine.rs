//! Core block writer engine: write_guest, flush_cluster, eviction.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::engine::encryption::CryptContext;
use crate::error::{Error, Result};
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::constants::COMPRESSED_SECTOR_SIZE;
use crate::format::header_extension::HeaderExtension;
use crate::format::l2::{L2Entry, SubclusterBitmap};
use crate::format::types::{ClusterGeometry, GuestOffset};
use crate::io::{Compressor, IoBackend};

use super::buffer::BlockBuffer;
use super::config::BlockWriterConfig;
use super::metadata::InMemoryMetadata;
use super::zero_detect::is_all_zeros;

/// Append-only QCOW2 image writer engine.
///
/// Buffers guest data in memory, detects zero clusters, optionally compresses
/// and encrypts data clusters, and writes them sequentially to an I/O backend.
/// All metadata is kept in RAM and serialized during [`finalize`](Self::finalize).
pub struct BlockWriterEngine {
    /// Guest data buffer.
    pub(super) buffer: BlockBuffer,
    /// In-memory metadata (L1/L2/refcounts).
    pub(super) metadata: InMemoryMetadata,
    /// Configuration.
    pub(super) config: BlockWriterConfig,
    /// Cluster geometry.
    pub(super) geometry: ClusterGeometry,
    /// Whether finalize() has been called.
    pub(super) finalized: bool,
    /// Cluster size cached.
    pub(super) cluster_size: u64,
    /// Header extensions to write during finalize.
    pub(super) extensions: Vec<HeaderExtension>,
    /// LUKS header data (raw bytes, if encrypted).
    pub(super) luks_header_data: Option<Vec<u8>>,
    /// Number of clusters reserved for the LUKS header.
    pub(super) luks_clusters: u64,
    /// Host offset where data clusters begin.
    pub(super) data_start_offset: u64,
    /// Computed blake3 hashes: hash_chunk_index → hash bytes.
    pub(super) hashes: BTreeMap<u64, Vec<u8>>,
}

impl BlockWriterEngine {
    /// Create a new block writer engine.
    ///
    /// The engine is ready for `write_guest` calls. Call `finalize` when done
    /// to write all metadata and produce a valid QCOW2 image.
    ///
    /// The `luks_header_data` and `extensions` are provided by the std wrapper
    /// which handles LUKS key generation.
    pub fn new(
        config: BlockWriterConfig,
        l1_entries: u32,
        data_start_offset: u64,
        luks_header_data: Option<Vec<u8>>,
        luks_clusters: u64,
        extensions: Vec<HeaderExtension>,
    ) -> Result<Self> {
        if config.virtual_size == 0 {
            return Err(Error::InvalidVirtualSize { size: 0 });
        }

        let geometry = ClusterGeometry {
            cluster_bits: config.cluster_bits,
            extended_l2: config.extended_l2,
        };
        let cluster_size = geometry.cluster_size();

        let buffer = BlockBuffer::new(geometry, config.memory_limit);
        let metadata = InMemoryMetadata::new(
            geometry,
            l1_entries,
            config.refcount_order,
            data_start_offset,
        );

        Ok(Self {
            buffer,
            metadata,
            config,
            geometry,
            finalized: false,
            cluster_size,
            extensions,
            luks_header_data,
            luks_clusters,
            data_start_offset,
            hashes: BTreeMap::new(),
        })
    }

    /// Virtual size of the image.
    pub fn virtual_size(&self) -> u64 {
        self.config.virtual_size
    }

    /// Write data at a guest offset.
    ///
    /// Data is buffered internally. When a cluster becomes full, it is
    /// automatically checked for zeros and flushed to the backend if non-zero.
    pub fn write_guest(
        &mut self,
        guest_offset: u64,
        data: &[u8],
        backend: &dyn IoBackend,
        compressor: &dyn Compressor,
        crypt_context: Option<&CryptContext>,
    ) -> Result<()> {
        if self.finalized {
            return Err(Error::BlockWriterFinalized);
        }

        // Bounds check
        let end = guest_offset
            .checked_add(data.len() as u64)
            .ok_or(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.config.virtual_size,
            })?;
        if end > self.config.virtual_size {
            return Err(Error::OffsetBeyondDiskSize {
                offset: end,
                disk_size: self.config.virtual_size,
            });
        }

        // Write into buffer, collect full clusters
        let flushable = self.buffer.write_guest(guest_offset, data)?;

        // Flush full clusters
        for cluster in flushable {
            self.flush_cluster(
                cluster.guest_offset,
                &cluster.data,
                backend,
                compressor,
                crypt_context,
            )?;
        }

        // Handle memory pressure
        if self.buffer.memory_pressure() {
            self.evict_and_flush(backend, compressor, crypt_context)?;
        }

        Ok(())
    }

    /// Read data from the in-memory buffer.
    ///
    /// Returns an error if any covered cluster has already been flushed to disk.
    pub fn read_from_buffer(
        &self,
        guest_offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        self.buffer.read_from_buffer(guest_offset, buf)
    }

    /// Flush a full cluster to the backend.
    fn flush_cluster(
        &mut self,
        guest_cluster_offset: u64,
        cluster_data: &[u8],
        backend: &dyn IoBackend,
        compressor: &dyn Compressor,
        crypt_context: Option<&CryptContext>,
    ) -> Result<()> {
        let (l1, l2, _) = GuestOffset(guest_cluster_offset).split(self.geometry);

        // 0. Compute blake3 hash on plaintext data (before compression/encryption)
        if let Some(hash_size) = self.config.hash_size {
            let idx = guest_cluster_offset / self.cluster_size;
            let hash = blake3::hash(cluster_data);
            self.hashes
                .insert(idx, hash.as_bytes()[..hash_size as usize].to_vec());
        }

        // 1. Zero detection
        if is_all_zeros(cluster_data) {
            self.metadata.set_l2_entry(
                l1,
                l2,
                L2Entry::Zero {
                    preallocated_offset: None,
                    subclusters: SubclusterBitmap::all_zero(),
                },
            );
            self.buffer.mark_flushed(guest_cluster_offset, 0);
            return Ok(());
        }

        // 2. Try compression (if enabled)
        if self.config.compress {
            let mut compressed_buf = vec![0u8; cluster_data.len()];
            if let Ok(compressed_len) = compressor.compress(
                cluster_data,
                &mut compressed_buf,
                self.config.compression_type,
            ) {
                return self.write_compressed_cluster(
                    guest_cluster_offset,
                    &compressed_buf[..compressed_len],
                    backend,
                );
            }
            // Compression ineffective — fall through to uncompressed
        }

        // 3. Allocate host cluster
        let host_offset = self.metadata.allocate_cluster();

        // 4. Encrypt if needed
        let write_data;
        if let Some(crypt) = crypt_context {
            let mut buf = cluster_data.to_vec();
            crypt.encrypt_cluster(host_offset.0, &mut buf)
                .map_err(|_| Error::EncryptionFailed {
                    guest_offset: guest_cluster_offset,
                    message: alloc::string::String::from("block writer encryption failed"),
                })?;
            write_data = buf;
        } else {
            write_data = cluster_data.to_vec();
        }

        // 5. Write to disk
        backend.write_all_at(&write_data, host_offset.0)?;

        // 6. Update L2 entry
        self.metadata.set_l2_entry(
            l1,
            l2,
            L2Entry::Standard {
                host_offset,
                copied: true,
                subclusters: SubclusterBitmap::all_allocated(),
            },
        );

        // 7. Track refcount
        self.metadata.increment_refcount(host_offset.0);

        // 8. Mark buffer as flushed
        self.buffer.mark_flushed(guest_cluster_offset, host_offset.0);

        Ok(())
    }

    /// Write a compressed cluster with packing.
    fn write_compressed_cluster(
        &mut self,
        guest_cluster_offset: u64,
        compressed_data: &[u8],
        backend: &dyn IoBackend,
    ) -> Result<()> {
        let compressed_size = compressed_data.len() as u64;
        let (write_offset, _new_cluster) =
            self.metadata.allocate_compressed(compressed_size);

        // Sector-align for writing
        let aligned_size =
            ((compressed_size + COMPRESSED_SECTOR_SIZE - 1) / COMPRESSED_SECTOR_SIZE)
                * COMPRESSED_SECTOR_SIZE;
        let mut padded = vec![0u8; aligned_size as usize];
        padded[..compressed_data.len()].copy_from_slice(compressed_data);
        backend.write_all_at(&padded, write_offset)?;

        // Build compressed L2 entry
        let descriptor = CompressedClusterDescriptor {
            host_offset: write_offset,
            compressed_size: aligned_size,
        };
        let (l1, l2, _) = GuestOffset(guest_cluster_offset).split(self.geometry);
        self.metadata.set_l2_entry(l1, l2, L2Entry::Compressed(descriptor));

        // Refcount: increment for every compressed cluster referencing this host cluster.
        // When multiple compressed clusters pack into the same host cluster,
        // the refcount must equal the number of references.
        let host_cluster_offset =
            (write_offset / self.cluster_size) * self.cluster_size;
        self.metadata.increment_refcount(host_cluster_offset);

        // If the compressed data spans into the next host cluster, count that too.
        let end_offset = write_offset + aligned_size;
        let end_cluster_offset = ((end_offset - 1) / self.cluster_size) * self.cluster_size;
        if end_cluster_offset != host_cluster_offset && end_offset > host_cluster_offset + self.cluster_size {
            self.metadata.increment_refcount(end_cluster_offset);
        }

        self.buffer.mark_flushed(guest_cluster_offset, write_offset);

        Ok(())
    }

    /// Evict oldest buffer blocks under memory pressure.
    fn evict_and_flush(
        &mut self,
        backend: &dyn IoBackend,
        compressor: &dyn Compressor,
        crypt_context: Option<&CryptContext>,
    ) -> Result<()> {
        let candidates = self.buffer.evict_candidates();
        if candidates.is_empty() && self.buffer.memory_pressure() {
            return Err(Error::BlockWriterMemoryExceeded {
                current: self.buffer.memory_used(),
                limit: self.config.memory_limit,
            });
        }

        for evictable in candidates {
            self.flush_cluster(
                evictable.guest_offset,
                &evictable.data,
                backend,
                compressor,
                crypt_context,
            )?;
        }

        Ok(())
    }

    /// Flush all remaining buffered clusters.
    ///
    /// Called at the beginning of finalize to ensure all data is written.
    pub(super) fn flush_all_remaining(
        &mut self,
        backend: &dyn IoBackend,
        compressor: &dyn Compressor,
        crypt_context: Option<&CryptContext>,
    ) -> Result<()> {
        let remaining = self.buffer.drain_remaining();
        for cluster in remaining {
            self.flush_cluster(
                cluster.guest_offset,
                &cluster.data,
                backend,
                compressor,
                crypt_context,
            )?;
        }
        Ok(())
    }
}
