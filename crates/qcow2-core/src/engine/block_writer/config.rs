//! Configuration for the block writer engine.

/// Configuration for [`BlockWriterEngine`](super::BlockWriterEngine).
#[derive(Debug, Clone)]
pub struct BlockWriterConfig {
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Log2 of the cluster size (e.g. 16 = 64 KiB). Default: 16.
    pub cluster_bits: u32,
    /// Whether to use extended L2 entries with subclusters.
    pub extended_l2: bool,
    /// Compression type (0 = deflate, 1 = zstd). Default: 0.
    pub compression_type: u8,
    /// Whether to compress data clusters. Default: false.
    pub compress: bool,
    /// Whether the image is encrypted (CryptContext must be provided at write time).
    pub encrypted: bool,
    /// Maximum memory for the block buffer in bytes. Default: 4 GiB.
    pub memory_limit: u64,
    /// Refcount order (log2 of refcount bits). Default: 4 (16-bit).
    pub refcount_order: u32,
}

/// Default memory limit: 4 GiB.
const DEFAULT_MEMORY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

impl Default for BlockWriterConfig {
    fn default() -> Self {
        Self {
            virtual_size: 0,
            cluster_bits: 16,
            extended_l2: false,
            compression_type: 0,
            compress: false,
            encrypted: false,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            refcount_order: 4,
        }
    }
}
