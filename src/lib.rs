//! # qcow2-lib
//!
//! A textbook-quality QCOW2 image format library for Rust.
//!
//! This crate provides three layers:
//! - **format**: Pure data structures for on-disk format parsing (no I/O, no state)
//! - **io**: I/O backend abstraction (trait-based, mockable)
//! - **engine**: Stateful read engine combining format + I/O
//!
//! # Quick start
//!
//! ```no_run
//! use qcow2_lib::Qcow2Image;
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
pub use error::{Error, Result};
