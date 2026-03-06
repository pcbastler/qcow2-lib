//! # qcow2-core
//!
//! `no_std`-compatible QCOW2 image format core library.
//!
//! This crate provides the foundational layers for working with QCOW2 disk
//! images without depending on the standard library. It requires only `alloc`.
//!
//! ## Layers
//!
//! - **format**: Pure data structures for on-disk format parsing (no I/O, no state).
//! - **io**: Trait abstractions for positioned I/O and compression backends.
//! - **engine**: Stateful read/write engine combining format + I/O.
//!
//! Concrete I/O backends and compression implementations are provided by
//! downstream crates:
//! - `qcow2` (userspace): file-backed I/O, flate2/zstd compression.
//! - Kernel modules: VFS-backed I/O, kernel zlib/zstd.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod engine;
pub mod error;
pub mod format;
pub mod io;
pub mod lru;

pub use error::{Error, IoErrorKind, Result};
pub use io::{BackingImage, Compressor, IoBackend};
