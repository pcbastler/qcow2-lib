//! Pure on-disk data structures for the QCOW2 image format.
//!
//! Re-exports all types from [`qcow2_core::format`].

pub use qcow2_core::format::*;
pub use qcow2_core::format::{
    bitmap, compressed, constants, feature_flags, hash, header, header_extension, l1, l2, refcount,
    snapshot, types,
};
