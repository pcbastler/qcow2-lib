//! Stateful read/write engine for QCOW2 images.
//!
//! This module composes the pure `format` layer with the `io` backend
//! traits to provide a complete read/write path. It handles L1/L2 address
//! translation, metadata caching, refcount management, and COW semantics.
//!
//! The engine is `no_std`-compatible. Concrete I/O backends and compression
//! implementations are injected via the [`IoBackend`](crate::io::IoBackend)
//! and [`Compressor`](crate::io::Compressor) traits.

pub mod bitmap_manager;
pub mod cache;
pub mod cluster_mapping;
pub mod encryption;
pub mod hash_manager;
pub mod metadata_io;
pub mod read_mode;
pub mod reader;
pub mod refcount_manager;
pub mod snapshot_manager;
pub mod writer;

// Re-exports for convenience
pub use bitmap_manager::BitmapInfo;
pub use cache::{CacheConfig, CacheMode, CacheStats};
pub use cluster_mapping::ClusterResolution;
pub use hash_manager::{HashEntry, HashInfo, HashMismatch};
pub use read_mode::{ReadMode, ReadWarning};
pub use snapshot_manager::SnapshotInfo;
