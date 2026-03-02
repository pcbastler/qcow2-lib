//! Pure on-disk data structures for the QCOW2 image format.
//!
//! This module contains no I/O and no mutable state. All types parse from
//! `&[u8]` and serialize to `&mut [u8]`. This makes them trivially testable
//! and reusable across sync and async engines.

pub mod constants;
pub mod types;
pub mod feature_flags;

// Re-exports for convenience
pub use feature_flags::{AutoclearFeatures, CompatibleFeatures, IncompatibleFeatures};
pub use types::*;
