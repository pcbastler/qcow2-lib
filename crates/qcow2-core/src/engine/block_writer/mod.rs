//! Append-only QCOW2 image writer engine.
//!
//! [`BlockWriterEngine`] buffers guest data in memory, detects zero clusters,
//! optionally compresses/encrypts data clusters, and writes them sequentially
//! to an [`IoBackend`](crate::io::IoBackend). All metadata (L1/L2 tables,
//! refcounts) is kept in RAM and serialized during [`BlockWriterEngine::finalize`].
//!
//! This module is `no_std`-compatible (requires `alloc`). The `qcow2` crate
//! provides [`Qcow2BlockWriter`] which wraps this engine with `std::io::Write`
//! and `std::io::Seek` support.

mod buffer;
mod config;
mod engine;
mod finalize;
mod metadata;
mod zero_detect;

pub use config::BlockWriterConfig;
pub use engine::BlockWriterEngine;
pub use zero_detect::is_all_zeros;
