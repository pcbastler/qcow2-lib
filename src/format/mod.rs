//! Pure on-disk data structures for the QCOW2 image format.
//!
//! This module contains no I/O and no mutable state. All types parse from
//! `&[u8]` and serialize to `&mut [u8]`. This makes them trivially testable
//! and reusable across sync and async engines.

pub mod compressed;
pub mod constants;
pub mod feature_flags;
pub mod header;
pub mod header_extension;
pub mod l1;
pub mod l2;
pub mod refcount;
pub mod snapshot;
pub mod types;

// Re-exports for convenience
pub use compressed::CompressedClusterDescriptor;
pub use feature_flags::{AutoclearFeatures, CompatibleFeatures, IncompatibleFeatures};
pub use header::Header;
pub use header_extension::HeaderExtension;
pub use l1::{L1Entry, L1Table};
pub use l2::{L2Entry, L2Table};
pub use refcount::{RefcountBlock, RefcountTableEntry};
pub use snapshot::SnapshotHeader;
pub use types::*;
