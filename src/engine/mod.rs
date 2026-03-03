//! Stateful read engine for QCOW2 images.
//!
//! This module composes the pure `format` layer with the `io` backend
//! to provide a complete read path. It handles L1/L2 address translation,
//! metadata caching, decompression, and backing file chains.
//!
//! The primary entry point is [`Qcow2Image`], which provides a high-level
//! API for opening and reading QCOW2 disk images.

pub mod backing;
pub mod bitmap_manager;
pub mod cache;
pub mod cluster_mapping;
pub mod compression;
pub mod converter;
pub mod image;
pub mod integrity;
pub mod read_mode;
pub mod reader;
pub mod refcount_manager;
pub mod snapshot_manager;
pub mod writer;

// Re-exports for convenience
pub use bitmap_manager::BitmapInfo;
pub use cache::{CacheConfig, CacheStats};
pub use cluster_mapping::ClusterResolution;
pub use image::Qcow2Image;
pub use read_mode::{ReadMode, ReadWarning};
pub use integrity::{IntegrityReport, RepairMode, RepairResult};
pub use snapshot_manager::SnapshotInfo;
