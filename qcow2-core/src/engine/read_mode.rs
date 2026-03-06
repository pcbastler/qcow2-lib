//! Read mode control for corruption tolerance.
//!
//! [`ReadMode`] determines whether the library aborts on the first
//! metadata error (`Strict`) or attempts best-effort recovery (`Lenient`).
//! In lenient mode, unreadable regions are filled with zeros and
//! [`ReadWarning`]s are collected for later inspection.

extern crate alloc;

use alloc::string::String;

/// Controls how the library handles corrupt or inconsistent metadata
/// during read operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadMode {
    /// Abort on any metadata error (default). Safe for normal operation.
    #[default]
    Strict,

    /// Best-effort: recover what we can, fill unreadable regions with
    /// zeros, and collect warnings instead of returning errors.
    Lenient,
}

/// A warning emitted when lenient mode recovers from a read error.
///
/// Warnings are collected by [`Qcow2Image`](super::Qcow2Image) and can
/// be inspected after a read operation to understand which regions
/// could not be read correctly.
#[derive(Debug, Clone)]
pub struct ReadWarning {
    /// Guest byte offset where the problem was detected.
    pub guest_offset: u64,
    /// Human-readable description of the problem.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    #[test]
    fn read_mode_default_is_strict() {
        assert_eq!(ReadMode::default(), ReadMode::Strict);
    }

    #[test]
    fn read_mode_eq_and_copy() {
        let a = ReadMode::Strict;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ReadMode::Strict, ReadMode::Lenient);
    }

    #[test]
    fn read_warning_stores_offset_and_message() {
        let w = ReadWarning {
            guest_offset: 0x1_0000,
            message: "L2 table unreadable".to_string(),
        };
        assert_eq!(w.guest_offset, 0x1_0000);
        assert_eq!(w.message, "L2 table unreadable");
    }

    #[test]
    fn read_warning_debug_format() {
        let w = ReadWarning {
            guest_offset: 42,
            message: "test".to_string(),
        };
        let debug = format!("{w:?}");
        assert!(debug.contains("42"), "should contain offset: {debug}");
        assert!(debug.contains("test"), "should contain message: {debug}");
    }
}
