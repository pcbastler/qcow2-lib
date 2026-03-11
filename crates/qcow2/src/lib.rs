//! # qcow2
//!
//! A QCOW2 image format library for Rust.
//!
//! Built on [`qcow2_core`] (a `no_std` + `alloc` crate), this library adds:
//! - File-based and in-memory I/O backends
//! - Deflate (flate2) and Zstandard (zstd) compression
//! - Full LUKS1/LUKS2 encryption support (including Argon2id)
//! - Backing chain, converter, and integrity checking
//!
//! # Quick start
//!
//! ```no_run
//! use qcow2::Qcow2Image;
//!
//! let mut image = Qcow2Image::open("disk.qcow2").unwrap();
//! let mut sector = vec![0u8; 512];
//! image.read_at(&mut sector, 0).unwrap();
//! ```

#![warn(missing_docs)]

pub mod engine;
pub mod error;
pub mod format;
pub mod io;

pub use engine::Qcow2Image;
pub use engine::cache::CacheMode;
pub use error::{Error, IoErrorKind, Result};
pub use qcow2_core::io::{BackingImage, Compressor, IoBackend};
