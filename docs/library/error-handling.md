# Error Handling

<!-- TODO
- Explain the two-level error hierarchy:
    qcow2_format::Error (FormatError) — purely structural, no I/O
    qcow2_core::Error / qcow2::Error  — engine-level, wraps FormatError

- Show the Error::Format(FormatError) variant and the From<FormatError> impl
  that makes `?` work across the boundary

- Explain re-export pattern: FormatError is re-exported at every crate level
  so users don't need to import qcow2-format directly

- Show how to match errors in practice:
    Error::Format(FormatError::InvalidMagic) => ...
    Error::Io(kind) => ...
    Error::Encryption(_) => ...

- List the main error categories with examples:
    Format errors: InvalidMagic, UnsupportedVersion, UnknownIncompatibleFeature
    I/O errors: IoErrorKind enum (UnexpectedEof, InvalidInput, NotFound, ...)
    Table errors: L2TableMisaligned, RefcountInvalid
    Encryption: KeyRecoveryFailed, DecryptionFailed
    Compression: DecompressionFailed, CompressionFailed

- Reference: crates/qcow2-format/src/error.rs
- Reference: crates/qcow2-core/src/error.rs
- Reference: crates/qcow2/src/error.rs
-->
