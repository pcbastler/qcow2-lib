//! Stateful read/write engine for QCOW2 images.
//!
//! Core engine modules (reader, writer, cache, cluster mapping, refcount,
//! snapshot, bitmap, hash, encryption) are provided by [`qcow2_core::engine`]
//! and re-exported here.
//!
//! Std-only modules (backing chain, compression, converter, integrity, image)
//! live in this crate directly.

// Re-export core engine modules
pub use qcow2_core::engine::{
    bitmap_manager, cache, cluster_mapping, hash_manager, read_mode, reader,
    refcount_manager, snapshot_manager, writer,
};

// Std-only modules (encryption wraps core + adds LUKS header/create)
pub mod backing;
pub mod compression;
pub mod converter;
pub mod encryption;
pub mod image;
pub mod integrity;

// Re-exports for convenience
pub use qcow2_core::engine::{
    BitmapInfo, CacheConfig, CacheMode, CacheStats, ClusterResolution, HashEntry, HashInfo, HashMismatch,
    ReadMode, ReadWarning, SnapshotInfo,
};
pub use image::Qcow2Image;
pub use integrity::{IntegrityReport, RepairMode, RepairResult};

#[cfg(test)]
mod tests;
