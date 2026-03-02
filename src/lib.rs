//! # qcow2-lib
//!
//! A textbook-quality QCOW2 image format library for Rust.
//!
//! This crate provides three layers:
//! - **format**: Pure data structures for on-disk format parsing (no I/O, no state)
//! - **io**: I/O backend abstraction (trait-based, mockable)
//! - **engine**: Stateful read engine combining format + I/O

#![warn(missing_docs)]

pub mod engine;
pub mod error;
pub mod format;
pub mod io;

pub use error::{Error, Result};
