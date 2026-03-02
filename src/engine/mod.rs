//! Stateful read engine for QCOW2 images.
//!
//! This module composes the pure `format` layer with the `io` backend
//! to provide a complete read path. It handles L1/L2 address translation,
//! metadata caching, decompression, and backing file chains.

pub mod backing;
pub mod cache;
pub mod cluster_mapping;
pub mod compression;
