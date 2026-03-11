//! Unified error types for the qcow2 crate.
//!
//! Re-exports [`qcow2_core::Error`] as the canonical error type and adds
//! `std`-specific conversions (`From<std::io::Error>`, `std::error::Error`).

pub use qcow2_core::error::{Error, FormatError, IoErrorKind, Result};

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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- io_error_kind ----

    #[test]
    fn io_error_kind_unexpected_eof() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::UnexpectedEof),
            IoErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn io_error_kind_permission_denied() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::PermissionDenied),
            IoErrorKind::PermissionDenied
        );
    }

    #[test]
    fn io_error_kind_invalid_input() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::InvalidInput),
            IoErrorKind::InvalidInput
        );
    }

    #[test]
    fn io_error_kind_invalid_data() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::InvalidData),
            IoErrorKind::InvalidData
        );
    }

    #[test]
    fn io_error_kind_write_zero() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::WriteZero),
            IoErrorKind::WriteZero
        );
    }

    #[test]
    fn io_error_kind_not_found() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::NotFound),
            IoErrorKind::NotFound
        );
    }

    #[test]
    fn io_error_kind_fallback_maps_to_other() {
        // TimedOut is not listed explicitly — must map to IoErrorKind::Other.
        assert_eq!(
            io_error_kind(std::io::ErrorKind::TimedOut),
            IoErrorKind::Other
        );
    }

    // ---- io_error ----

    #[test]
    fn io_error_maps_all_fields() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let expected_message = source.to_string();
        let err = io_error(source, 0x4000, "reading L1 table");

        match err {
            Error::Io { kind, message, offset, context } => {
                assert_eq!(kind, IoErrorKind::NotFound);
                assert_eq!(message, expected_message);
                assert_eq!(offset, 0x4000);
                assert_eq!(context, "reading L1 table");
            }
            other => panic!("expected Error::Io, got {other:?}"),
        }
    }

    #[test]
    fn io_error_kind_is_converted_from_source() {
        let source = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated");
        let err = io_error(source, 0, "reading header");

        assert!(matches!(err, Error::Io { kind: IoErrorKind::UnexpectedEof, .. }));
    }

    #[test]
    fn io_error_fallback_kind_becomes_other() {
        let source = std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out");
        let err = io_error(source, 0x100, "network read");

        assert!(matches!(err, Error::Io { kind: IoErrorKind::Other, .. }));
    }

    // ---- decompress_error ----

    #[test]
    fn decompress_error_maps_all_fields() {
        let source = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad zlib stream");
        let expected_message = source.to_string();
        let err = decompress_error(source, 0x8000);

        match err {
            Error::DecompressionFailed { kind, message, guest_offset } => {
                assert_eq!(kind, IoErrorKind::InvalidData);
                assert_eq!(message, expected_message);
                assert_eq!(guest_offset, 0x8000);
            }
            other => panic!("expected Error::DecompressionFailed, got {other:?}"),
        }
    }

    #[test]
    fn decompress_error_kind_converted() {
        let source = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof in compressed");
        let err = decompress_error(source, 0x1_0000);

        assert!(matches!(
            err,
            Error::DecompressionFailed { kind: IoErrorKind::UnexpectedEof, guest_offset: 0x1_0000, .. }
        ));
    }

    // ---- create_error ----

    #[test]
    fn create_error_maps_all_fields() {
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let expected_message = source.to_string();
        let err = create_error(source, "/tmp/test.qcow2".to_string());

        match err {
            Error::CreateFailed { message, path } => {
                assert_eq!(message, expected_message);
                assert_eq!(path, "/tmp/test.qcow2");
            }
            other => panic!("expected Error::CreateFailed, got {other:?}"),
        }
    }

    #[test]
    fn create_error_preserves_path() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "dir missing");
        let path = "/nonexistent/dir/image.qcow2".to_string();
        let err = create_error(source, path.clone());

        assert!(matches!(err, Error::CreateFailed { path: ref p, .. } if p == &path));
    }

    // ---- external_data_error ----

    #[test]
    fn external_data_error_maps_all_fields() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "data file missing");
        let expected_message = source.to_string();
        let err = external_data_error(source, "/var/lib/data.raw".to_string());

        match err {
            Error::ExternalDataFileOpen { message, path } => {
                assert_eq!(message, expected_message);
                assert_eq!(path, "/var/lib/data.raw");
            }
            other => panic!("expected Error::ExternalDataFileOpen, got {other:?}"),
        }
    }

    #[test]
    fn external_data_error_preserves_path() {
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no read access");
        let path = "/mnt/external/disk.raw".to_string();
        let err = external_data_error(source, path.clone());

        assert!(matches!(err, Error::ExternalDataFileOpen { path: ref p, .. } if p == &path));
    }
}
