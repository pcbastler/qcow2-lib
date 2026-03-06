//! Re-exports QCOW2 on-disk format types from [`qcow2_format`].
//!
//! All format types, constants, and parsing live in the standalone
//! `qcow2-format` crate. This module re-exports everything for
//! backwards compatibility.

pub use qcow2_format::bitmap;
pub use qcow2_format::compressed;
pub use qcow2_format::constants;
pub use qcow2_format::feature_flags;
pub use qcow2_format::hash;
pub use qcow2_format::header;
pub use qcow2_format::header_extension;
pub use qcow2_format::l1;
pub use qcow2_format::l2;
pub use qcow2_format::refcount;
pub use qcow2_format::snapshot;
pub use qcow2_format::types;

// Re-exports for convenience (same as before)
pub use qcow2_format::{
    BitmapDirectoryEntry, BitmapExtension, BitmapTable, BitmapTableEntry, BitmapTableEntryState,
    Blake3Extension, CompressedClusterDescriptor, HashTable, HashTableEntry,
    AutoclearFeatures, CompatibleFeatures, IncompatibleFeatures,
    Header, HeaderExtension,
    L1Entry, L1Table, L2Entry, L2Table,
    RefcountBlock, RefcountTableEntry,
    SnapshotHeader,
};
pub use qcow2_format::types::*;
