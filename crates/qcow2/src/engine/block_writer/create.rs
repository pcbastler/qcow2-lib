//! Construction of [`Qcow2BlockWriter`] instances.

use std::path::Path;

use qcow2_core::engine::block_writer::BlockWriterConfig;
use qcow2_core::io::IoBackend;

use crate::engine::compression::StdCompressor;
use crate::engine::image::create::{
    build_create_extensions, generate_luks_header, validate_create_options,
};
use crate::engine::image::CreateOptions;
use crate::error::Result;
use crate::io::sync_backend::SyncFileBackend;

use super::Qcow2BlockWriter;

/// Options specific to the block writer (beyond [`CreateOptions`]).
#[derive(Debug, Clone)]
pub struct BlockWriterOptions {
    /// Base image creation options.
    pub create: CreateOptions,
    /// Whether to compress data clusters. Default: false.
    pub compress: bool,
    /// Maximum memory for the block buffer in bytes. Default: 4 GiB.
    pub memory_limit: Option<u64>,
    /// Blake3 hash size: None (default, no hashing), Some(16), or Some(32).
    pub hash_size: Option<u8>,
}

impl Qcow2BlockWriter {
    /// Create a new block writer that writes to the given file path.
    pub fn create<P: AsRef<Path>>(
        path: P,
        options: BlockWriterOptions,
    ) -> Result<Self> {
        let backend = SyncFileBackend::create(path.as_ref())?;
        Self::create_on_backend(Box::new(backend), options)
    }

    /// Create a new block writer on an abstract I/O backend.
    pub fn create_on_backend(
        backend: Box<dyn IoBackend>,
        options: BlockWriterOptions,
    ) -> Result<Self> {
        let (cluster_bits, cluster_size, extended_l2, compression_type, _data_file, encryption) =
            validate_create_options(&options.create)?;

        let refcount_order = 4u32;
        let l2_entry_size = if extended_l2 { 16u64 } else { 8u64 };
        let l1_entries = crate::engine::image::create::calculate_l1_entries(
            options.create.virtual_size,
            cluster_size,
            l2_entry_size,
        );

        // Generate LUKS header if encrypted
        let (luks_header_data, crypt_context): (Option<Vec<u8>>, _) =
            generate_luks_header(&encryption)?;
        let luks_clusters = luks_header_data
            .as_ref()
            .map(|d: &Vec<u8>| (d.len() as u64 + cluster_size - 1) / cluster_size)
            .unwrap_or(0);

        // Data starts after header cluster + LUKS clusters
        // Header cluster (0) is written during finalize, so data starts at cluster 1
        // (or after LUKS data if encrypted)
        let data_start_offset = cluster_size + luks_clusters * cluster_size;

        // Build header extensions
        let luks_offset = cluster_size; // LUKS data right after header cluster
        let extensions = build_create_extensions(&luks_header_data, luks_offset, &None);

        let config = BlockWriterConfig {
            virtual_size: options.create.virtual_size,
            cluster_bits,
            extended_l2,
            compression_type,
            compress: options.compress,
            encrypted: encryption.is_some(),
            memory_limit: options.memory_limit.unwrap_or(4 * 1024 * 1024 * 1024),
            refcount_order,
            hash_size: options.hash_size,
        };

        let engine = qcow2_core::engine::block_writer::BlockWriterEngine::new(
            config,
            l1_entries,
            data_start_offset,
            luks_header_data,
            luks_clusters,
            extensions,
        )?;

        Ok(Self {
            engine,
            backend,
            compressor: StdCompressor,
            crypt_context,
            cursor: 0,
        })
    }
}
