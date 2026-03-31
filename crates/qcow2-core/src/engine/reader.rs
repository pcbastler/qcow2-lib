//! QCOW2 read engine: translates guest reads into host data.
//!
//! Composes cluster mapping, decompression, and backing chain fallback
//! to serve arbitrary guest reads that may span multiple clusters.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::{ClusterMapper, ClusterResolution};
use crate::io::Compressor;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::error::{Error, FormatError, Result};
use crate::format::constants::SUBCLUSTERS_PER_CLUSTER;
use crate::format::l2::{SubclusterBitmap, SubclusterState};
use crate::format::types::{ClusterOffset, GuestOffset, IntraClusterOffset};
use crate::engine::encryption::CryptContext;
use crate::io::IoBackend;

/// Reads guest data from a QCOW2 image, handling all cluster types.
///
/// The reader does not own the backend or cache — it borrows them for
/// the duration of a read operation. This allows `Qcow2Image` to
/// maintain ownership and create readers on demand.
///
/// When a backing image is provided, unallocated clusters are read from
/// it instead of returning zeros.
pub struct Qcow2Reader<'a> {
    mapper: &'a ClusterMapper,
    backend: &'a dyn IoBackend,
    /// Backend for guest data clusters (external data file or same as backend).
    data_backend: &'a dyn IoBackend,
    cache: &'a mut MetadataCache,
    cluster_bits: u32,
    virtual_size: u64,
    compression_type: u8,
    read_mode: ReadMode,
    warnings: &'a mut Vec<ReadWarning>,
    backing_image: Option<&'a mut dyn crate::io::BackingImage>,
    crypt_context: Option<&'a CryptContext>,
    compressor: &'a dyn Compressor,
}

impl<'a> Qcow2Reader<'a> {
    /// Create a new reader.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapper: &'a ClusterMapper,
        backend: &'a dyn IoBackend,
        data_backend: &'a dyn IoBackend,
        cache: &'a mut MetadataCache,
        cluster_bits: u32,
        virtual_size: u64,
        compression_type: u8,
        read_mode: ReadMode,
        warnings: &'a mut Vec<ReadWarning>,
        backing_image: Option<&'a mut dyn crate::io::BackingImage>,
        crypt_context: Option<&'a CryptContext>,
        compressor: &'a dyn Compressor,
    ) -> Self {
        Self {
            mapper,
            backend,
            data_backend,
            cache,
            cluster_bits,
            virtual_size,
            compression_type,
            read_mode,
            warnings,
            backing_image,
            crypt_context,
            compressor,
        }
    }

    /// Read `buf.len()` bytes starting at the given guest offset.
    ///
    /// Handles reads that span multiple clusters by splitting them
    /// into per-cluster chunks. Each chunk is resolved independently
    /// through the cluster mapper.
    pub fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        let read_end = guest_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            })?;

        if read_end > self.virtual_size {
            return Err(Error::OffsetBeyondDiskSize {
                offset: guest_offset,
                disk_size: self.virtual_size,
            });
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = buf;
        let mut current_offset = guest_offset;

        while !remaining.is_empty() {
            let intra = (current_offset & (cluster_size - 1)) as usize;
            let bytes_left_in_cluster = cluster_size as usize - intra;
            let chunk_size = remaining.len().min(bytes_left_in_cluster);
            let (chunk, rest) = remaining.split_at_mut(chunk_size);

            self.read_cluster_chunk(chunk, current_offset)?;

            remaining = rest;
            current_offset += chunk_size as u64;
        }

        Ok(())
    }

    /// Read a chunk of data from a single cluster.
    fn read_cluster_chunk(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        let resolution = match self
            .mapper
            .resolve(GuestOffset(guest_offset), self.backend, self.cache)
        {
            Ok(r) => r,
            Err(e) => return self.handle_read_error(buf, guest_offset, e),
        };

        match resolution {
            ClusterResolution::Allocated {
                host_offset,
                intra_cluster_offset,
                subclusters,
            } => {
                if subclusters.is_all_allocated() {
                    self.read_allocated(buf, guest_offset, host_offset, intra_cluster_offset)
                } else {
                    self.read_subclustered(buf, guest_offset, Some(host_offset), intra_cluster_offset, subclusters)
                }
            }
            ClusterResolution::Zero {
                bitmap,
                intra_cluster_offset,
            } => {
                if bitmap.is_all_zero() {
                    // Fast path: all subclusters zero → fill
                    buf.fill(0);
                    Ok(())
                } else {
                    self.read_subclustered(buf, guest_offset, None, intra_cluster_offset, bitmap)
                }
            }
            ClusterResolution::Unallocated => {
                self.read_from_backing_or_zero(buf, guest_offset)
            }
            ClusterResolution::Compressed {
                descriptor,
                intra_cluster_offset,
            } => {
                let cluster_size = 1usize << self.cluster_bits;
                let file_size = self.backend.file_size()?;

                // Validate compressed data offset is within file
                if descriptor.host_offset >= file_size {
                    return self.handle_read_error(
                        buf,
                        guest_offset,
                        FormatError::MetadataOffsetBeyondEof {
                            offset: descriptor.host_offset,
                            size: descriptor.compressed_size,
                            file_size,
                            context: "compressed cluster data",
                        },
                    );
                }

                // The compressed_size from the descriptor is the maximum number
                // of sectors the data can span, but may extend past EOF for the
                // last compressed cluster in the file. Clamp to available data.
                let available = file_size.saturating_sub(descriptor.host_offset);
                let read_size = (descriptor.compressed_size as usize).min(available as usize);
                let mut compressed_data = vec![0u8; read_size];
                if let Err(e) = self
                    .backend
                    .read_exact_at(&mut compressed_data, descriptor.host_offset)
                {
                    return self.handle_read_error(buf, guest_offset, e);
                }
                let mut decompressed = vec![0u8; cluster_size];
                match self.compressor.decompress(
                    &compressed_data,
                    &mut decompressed,
                    self.compression_type,
                ) {
                    Ok(_) => {
                        let intra = intra_cluster_offset.0 as usize;
                        buf.copy_from_slice(&decompressed[intra..intra + buf.len()]);
                        Ok(())
                    }
                    Err(e) => {
                        // The Compressor trait doesn't carry guest_offset context,
                        // so patch it into DecompressionFailed errors before reporting.
                        let e: Error = e.into();
                        let e = match e {
                            Error::DecompressionFailed { kind, message, .. } => {
                                Error::DecompressionFailed { kind, message, guest_offset }
                            }
                            other => other,
                        };
                        self.handle_read_error(buf, guest_offset, e)
                    }
                }
            }
        }
    }

    /// Read from an allocated cluster, decrypting if encrypted.
    ///
    /// For unencrypted images: direct read from host.
    /// For encrypted images: if reading a full cluster, read and decrypt in-place.
    /// For partial reads of encrypted clusters, read the full cluster, decrypt,
    /// then copy the requested slice.
    fn read_allocated(
        &mut self,
        buf: &mut [u8],
        guest_offset: u64,
        host_offset: ClusterOffset,
        intra_cluster_offset: IntraClusterOffset,
    ) -> Result<()> {
        let read_offset = host_offset.0 + intra_cluster_offset.0 as u64;

        let Some(crypt) = self.crypt_context else {
            return match self.data_backend.read_exact_at(buf, read_offset) {
                Ok(()) => Ok(()),
                Err(e) => self.handle_read_error(buf, guest_offset, e),
            };
        };
        let cluster_size = 1usize << self.cluster_bits;
        let intra = intra_cluster_offset.0 as usize;

        if intra == 0 && buf.len() == cluster_size {
            // Full cluster read: decrypt in-place
            match self.data_backend.read_exact_at(buf, host_offset.0) {
                Ok(()) => crypt.decrypt_cluster(host_offset.0, buf),
                Err(e) => self.handle_read_error(buf, guest_offset, e),
            }
        } else {
            // Partial cluster: read full cluster, decrypt, copy slice
            let mut cluster_buf = vec![0u8; cluster_size];
            match self.data_backend.read_exact_at(&mut cluster_buf, host_offset.0) {
                Ok(()) => {
                    crypt.decrypt_cluster(host_offset.0, &mut cluster_buf)?;
                    buf.copy_from_slice(&cluster_buf[intra..intra + buf.len()]);
                    Ok(())
                }
                Err(e) => self.handle_read_error(buf, guest_offset, e),
            }
        }
    }

    /// Read from a cluster with per-subcluster dispatch.
    ///
    /// Each subcluster within the read range is dispatched independently:
    /// - `Allocated`: read from host (if `host_offset` is `Some`)
    /// - `Zero`: fill with zeros
    /// - `Unallocated`: read from backing file or fill with zeros
    /// - `Invalid`: error
    ///
    /// When `host_offset` is `None`, the cluster has no host data (zero entry
    /// without preallocated cluster), so allocated subclusters are treated as zero.
    fn read_subclustered(
        &mut self,
        buf: &mut [u8],
        guest_offset: u64,
        host_offset: Option<ClusterOffset>,
        intra_cluster_offset: IntraClusterOffset,
        bitmap: SubclusterBitmap,
    ) -> Result<()> {
        let cluster_size = 1u64 << self.cluster_bits;
        let sc_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let intra = intra_cluster_offset.0 as u64;

        // For encrypted images with a host cluster, pre-read and decrypt
        // the entire cluster so subcluster slices come from plaintext.
        let decrypted_cluster = if let Some(crypt) = self.crypt_context {
            if let Some(host) = host_offset {
                let mut cluster_buf = vec![0u8; cluster_size as usize];
                self.data_backend.read_exact_at(&mut cluster_buf, host.0)?;
                crypt.decrypt_cluster(host.0, &mut cluster_buf)?;
                Some(cluster_buf)
            } else {
                None
            }
        } else {
            None
        };

        let mut buf_pos = 0usize;
        let mut cluster_pos = intra;

        while buf_pos < buf.len() {
            let sc_index = (cluster_pos / sc_size) as u32;
            debug_assert!(sc_index < SUBCLUSTERS_PER_CLUSTER);

            // How many bytes remain in this subcluster?
            let sc_end = (sc_index as u64 + 1) * sc_size;
            let bytes_in_sc = (sc_end - cluster_pos) as usize;
            let chunk_len = bytes_in_sc.min(buf.len() - buf_pos);

            let state = bitmap.get(sc_index);
            match state {
                SubclusterState::Allocated => {
                    if let Some(ref dc) = decrypted_cluster {
                        // Encrypted: copy from pre-decrypted cluster buffer
                        let cp = cluster_pos as usize;
                        buf[buf_pos..buf_pos + chunk_len]
                            .copy_from_slice(&dc[cp..cp + chunk_len]);
                    } else if let Some(host) = host_offset {
                        let read_offset = host.0 + cluster_pos;
                        match self.data_backend.read_exact_at(
                            &mut buf[buf_pos..buf_pos + chunk_len],
                            read_offset,
                        ) {
                            Ok(()) => {}
                            Err(e) => {
                                return self.handle_read_error(buf, guest_offset, e);
                            }
                        }
                    } else {
                        // No host cluster — treat as zero
                        buf[buf_pos..buf_pos + chunk_len].fill(0);
                    }
                }
                SubclusterState::Zero => {
                    buf[buf_pos..buf_pos + chunk_len].fill(0);
                }
                SubclusterState::Unallocated => {
                    self.read_from_backing_or_zero(
                        &mut buf[buf_pos..buf_pos + chunk_len],
                        guest_offset + buf_pos as u64,
                    )?;
                }
                SubclusterState::Invalid => {
                    return Err(Error::InvalidSubclusterBitmap {
                        l2_index: 0, // we don't have the L2 index here
                        subcluster_index: sc_index,
                    });
                }
            }

            buf_pos += chunk_len;
            cluster_pos += chunk_len as u64;
        }

        Ok(())
    }

    /// Read from the backing image or fill with zeros if no backing.
    fn read_from_backing_or_zero(
        &mut self,
        buf: &mut [u8],
        guest_offset: u64,
    ) -> Result<()> {
        if let Some(ref mut backing) = self.backing_image {
            let backing_vs = backing.virtual_size();
            let read_end = guest_offset + buf.len() as u64;
            if guest_offset >= backing_vs {
                buf.fill(0);
            } else if read_end > backing_vs {
                let available = (backing_vs - guest_offset) as usize;
                backing.read_at(&mut buf[..available], guest_offset)?;
                buf[available..].fill(0);
            } else {
                backing.read_at(buf, guest_offset)?;
            }
        } else {
            buf.fill(0);
        }
        Ok(())
    }

    /// Handle a read error according to the current read mode.
    ///
    /// In strict mode, propagates the error. In lenient mode, fills the
    /// buffer with zeros and records a warning.
    fn handle_read_error<E: Into<Error>>(
        &mut self,
        buf: &mut [u8],
        guest_offset: u64,
        error: E,
    ) -> Result<()> {
        let error = error.into();
        match self.read_mode {
            ReadMode::Strict => Err(error),
            ReadMode::Lenient => {
                self.warnings.push(ReadWarning {
                    guest_offset,
                    message: error.to_string(),
                });
                buf.fill(0);
                Ok(())
            }
        }
    }
}
