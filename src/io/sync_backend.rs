//! Synchronous file I/O backend using pread/pwrite.
//!
//! Uses `std::os::unix::fs::FileExt` for positioned I/O without seeking,
//! which avoids the need for locking on the file cursor.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::error::{Error, Result};
use crate::io::IoBackend;

/// Synchronous I/O backend backed by a standard library [`File`].
///
/// Uses `pread(2)` / `pwrite(2)` via the Unix [`FileExt`] trait,
/// allowing concurrent positioned reads without file cursor contention.
pub struct SyncFileBackend {
    file: File,
}

impl SyncFileBackend {
    /// Open a file at the given path for reading.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new().read(true).open(path).map_err(|e| Error::Io {
            source: e,
            offset: 0,
            context: "opening file",
        })?;
        Ok(Self { file })
    }

    /// Open a file at the given path for reading and writing.
    pub fn open_rw(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::Io {
                source: e,
                offset: 0,
                context: "opening file for read-write",
            })?;
        Ok(Self { file })
    }

    /// Create a new file at the given path for reading and writing.
    ///
    /// Fails if the file already exists (uses `create_new`).
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| Error::Io {
                source: e,
                offset: 0,
                context: "creating new file",
            })?;
        Ok(Self { file })
    }

    /// Wrap an existing [`File`] handle.
    pub fn from_file(file: File) -> Self {
        Self { file }
    }
}

impl IoBackend for SyncFileBackend {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        self.file.read_exact_at(buf, offset).map_err(|e| Error::Io {
            source: e,
            offset,
            context: "SyncFileBackend::read_exact_at",
        })
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        self.file.write_all_at(buf, offset).map_err(|e| Error::Io {
            source: e,
            offset,
            context: "SyncFileBackend::write_all_at",
        })
    }

    fn flush(&self) -> Result<()> {
        self.file.sync_data().map_err(|e| Error::Io {
            source: e,
            offset: 0,
            context: "SyncFileBackend::flush",
        })
    }

    fn file_size(&self) -> Result<u64> {
        self.file.metadata().map(|m| m.len()).map_err(|e| Error::Io {
            source: e,
            offset: 0,
            context: "SyncFileBackend::file_size",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn read_write_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let backend = SyncFileBackend::open_rw(tmp.path()).unwrap();

        let data = b"QCOW2 test data";
        backend.write_all_at(data, 0).unwrap();
        backend.flush().unwrap();

        let mut buf = vec![0u8; data.len()];
        backend.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn read_at_offset() {
        let tmp = NamedTempFile::new().unwrap();
        let backend = SyncFileBackend::open_rw(tmp.path()).unwrap();

        backend.write_all_at(b"AAAAhelloBBBB", 0).unwrap();

        let mut buf = [0u8; 5];
        backend.read_exact_at(&mut buf, 4).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn file_size_after_write() {
        let tmp = NamedTempFile::new().unwrap();
        let backend = SyncFileBackend::open_rw(tmp.path()).unwrap();

        assert_eq!(backend.file_size().unwrap(), 0);
        backend.write_all_at(&[0u8; 100], 0).unwrap();
        assert_eq!(backend.file_size().unwrap(), 100);
    }

    #[test]
    fn read_beyond_eof_returns_error() {
        let tmp = NamedTempFile::new().unwrap();
        let backend = SyncFileBackend::open(tmp.path()).unwrap();

        let mut buf = [0u8; 10];
        let result = backend.read_exact_at(&mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn open_nonexistent_returns_error() {
        let result = SyncFileBackend::open(Path::new("/nonexistent/qcow2"));
        assert!(result.is_err());
    }
}
