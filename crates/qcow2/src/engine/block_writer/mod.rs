//! Streaming QCOW2 image writer with `Write` + `Seek` support.
//!
//! [`Qcow2BlockWriter`] wraps the `no_std`-compatible [`BlockWriterEngine`] with
//! file-backed I/O and implements `std::io::Write` + `std::io::Seek`, making it
//! compatible with any code that writes to a `File`.
//!
//! # Example
//!
//! ```no_run
//! use qcow2::Qcow2BlockWriter;
//! use qcow2::engine::block_writer::BlockWriterOptions;
//! use qcow2::engine::image::CreateOptions;
//! use std::io::{Write, Seek, SeekFrom};
//!
//! let mut writer = Qcow2BlockWriter::create("/tmp/output.qcow2", BlockWriterOptions {
//!     create: CreateOptions {
//!         virtual_size: 1024 * 1024 * 1024, // 1 GiB
//!         cluster_bits: Some(16),
//!         extended_l2: false,
//!         compression_type: None,
//!         data_file: None,
//!         encryption: None,
//!     },
//!     compress: false,
//!     memory_limit: None,
//!     hash_size: None,
//! }).unwrap();
//!
//! // Write like a file:
//! writer.write_all(b"Hello QCOW2").unwrap();
//! writer.seek(SeekFrom::Start(1048576)).unwrap();
//! writer.write_all(b"Data at 1 MiB").unwrap();
//!
//! // Finalize to produce a valid QCOW2 image:
//! writer.finalize().unwrap();
//! ```

mod create;
mod finalize;
mod write;

pub use create::BlockWriterOptions;

use qcow2_core::engine::block_writer::BlockWriterEngine;
use qcow2_core::io::IoBackend;

use crate::engine::compression::StdCompressor;
use crate::engine::encryption::CryptContext;

/// A streaming QCOW2 image writer that buffers guest data in memory
/// and writes data clusters to disk on-the-fly.
///
/// Implements [`std::io::Write`] and [`std::io::Seek`] for compatibility
/// with any code that writes to a [`std::fs::File`].
///
/// Metadata (L1/L2 tables, refcount structures, header) is kept entirely
/// in RAM and written during [`finalize`](Self::finalize).
pub struct Qcow2BlockWriter {
    pub(super) engine: BlockWriterEngine,
    pub(super) backend: Box<dyn IoBackend>,
    pub(super) compressor: StdCompressor,
    pub(super) crypt_context: Option<CryptContext>,
    /// Current guest cursor position for Write + Seek.
    pub(super) cursor: u64,
}
