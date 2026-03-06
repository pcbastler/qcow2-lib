//! Unified error types for the qcow2 crate.
//!
//! Re-exports [`qcow2_core::Error`] as the canonical error type and adds
//! `std`-specific conversions (`From<std::io::Error>`, `std::error::Error`).

pub use qcow2_core::error::{Error, IoErrorKind, Result};

/// Convert a `std::io::ErrorKind` to our `no_std`-compatible [`IoErrorKind`].
pub fn io_error_kind(kind: std::io::ErrorKind) -> IoErrorKind {
    match kind {
        std::io::ErrorKind::UnexpectedEof => IoErrorKind::UnexpectedEof,
        std::io::ErrorKind::PermissionDenied => IoErrorKind::PermissionDenied,
        std::io::ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => IoErrorKind::InvalidData,
        std::io::ErrorKind::WriteZero => IoErrorKind::WriteZero,
        std::io::ErrorKind::NotFound => IoErrorKind::NotFound,
        _ => IoErrorKind::Other,
    }
}

/// Convenience: create an [`Error::Io`] from a `std::io::Error`.
pub fn io_error(source: std::io::Error, offset: u64, context: &'static str) -> Error {
    Error::Io {
        kind: io_error_kind(source.kind()),
        message: source.to_string(),
        offset,
        context,
    }
}

/// Create a [`Error::DecompressionFailed`] from a `std::io::Error`.
pub fn decompress_error(source: std::io::Error, guest_offset: u64) -> Error {
    Error::DecompressionFailed {
        kind: io_error_kind(source.kind()),
        message: source.to_string(),
        guest_offset,
    }
}

/// Create an [`Error::CreateFailed`] from a `std::io::Error`.
pub fn create_error(source: std::io::Error, path: String) -> Error {
    Error::CreateFailed {
        message: source.to_string(),
        path,
    }
}

/// Create an [`Error::ExternalDataFileOpen`] from a `std::io::Error`.
pub fn external_data_error(source: std::io::Error, path: String) -> Error {
    Error::ExternalDataFileOpen {
        message: source.to_string(),
        path,
    }
}
