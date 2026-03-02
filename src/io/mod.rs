//! I/O backend abstraction for positioned reads and writes.
//!
//! The [`IoBackend`] trait decouples the engine from any specific I/O
//! implementation. This enables:
//! - File-based I/O via [`SyncFileBackend`](sync_backend::SyncFileBackend)
//! - In-memory I/O for testing via [`MemoryBackend`]
//! - Future async backends (tokio, io_uring)
//!
//! All operations are offset-based (positioned) and do not maintain a
//! file cursor, making them safe for concurrent use without locking.

pub mod sync_backend;

use crate::error::Result;

/// Abstraction over positioned I/O operations.
///
/// Implementations must be `Send + Sync` to support future concurrent
/// and async engine designs.
pub trait IoBackend: Send + Sync {
    /// Read exactly `buf.len()` bytes starting at the given offset.
    ///
    /// Returns an error if the full read cannot be satisfied (e.g., EOF).
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// Write exactly `buf.len()` bytes starting at the given offset.
    ///
    /// Returns an error if the full write cannot be completed.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()>;

    /// Flush any buffered writes to the underlying storage.
    fn flush(&self) -> Result<()>;

    /// Total size of the backing storage in bytes.
    fn file_size(&self) -> Result<u64>;
}

/// In-memory I/O backend for testing.
///
/// Wraps a `Vec<u8>` behind a `RwLock` so it can satisfy the `Send + Sync`
/// requirement of [`IoBackend`]. Useful for building synthetic QCOW2 images
/// entirely in memory for unit tests.
pub struct MemoryBackend {
    data: std::sync::RwLock<Vec<u8>>,
}

impl MemoryBackend {
    /// Create a new memory backend with the given initial data.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: std::sync::RwLock::new(data),
        }
    }

    /// Create a zero-filled memory backend of the given size.
    pub fn zeroed(size: usize) -> Self {
        Self::new(vec![0u8; size])
    }

    /// Get a copy of the current data (for test assertions).
    pub fn data(&self) -> Vec<u8> {
        self.data.read().unwrap().clone()
    }
}

impl IoBackend for MemoryBackend {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let data = self.data.read().unwrap();
        let start = offset as usize;
        let end = start + buf.len();
        if end > data.len() {
            return Err(crate::error::Error::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "read of {} bytes at offset 0x{:x} exceeds data size {}",
                        buf.len(),
                        offset,
                        data.len()
                    ),
                ),
                offset,
                context: "MemoryBackend::read_exact_at",
            });
        }
        buf.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        let mut data = self.data.write().unwrap();
        let start = offset as usize;
        let end = start + buf.len();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(()) // No-op for memory backend
    }

    fn file_size(&self) -> Result<u64> {
        Ok(self.data.read().unwrap().len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_read_write() {
        let backend = MemoryBackend::zeroed(1024);

        let write_data = b"hello qcow2";
        backend.write_all_at(write_data, 100).unwrap();

        let mut read_buf = vec![0u8; write_data.len()];
        backend.read_exact_at(&mut read_buf, 100).unwrap();
        assert_eq!(&read_buf, write_data);
    }

    #[test]
    fn memory_backend_read_beyond_eof() {
        let backend = MemoryBackend::zeroed(64);
        let mut buf = vec![0u8; 32];
        let result = backend.read_exact_at(&mut buf, 50);
        assert!(result.is_err());
    }

    #[test]
    fn memory_backend_write_extends() {
        let backend = MemoryBackend::zeroed(10);
        backend.write_all_at(&[1, 2, 3], 20).unwrap();
        assert_eq!(backend.file_size().unwrap(), 23);
    }

    #[test]
    fn memory_backend_file_size() {
        let backend = MemoryBackend::new(vec![0u8; 256]);
        assert_eq!(backend.file_size().unwrap(), 256);
    }
}
