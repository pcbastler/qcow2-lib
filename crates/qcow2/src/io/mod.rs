//! I/O backend abstraction for positioned reads and writes.
//!
//! Re-exports the core traits from [`qcow2_core::io`] and provides
//! concrete implementations:
//! - [`SyncFileBackend`](sync_backend::SyncFileBackend) for file-based I/O
//! - [`MemoryBackend`] for in-memory testing

pub mod streaming;
pub mod sync_backend;

pub use qcow2_core::io::{BackingImage, Compressor, IoBackend};
pub use streaming::StreamingBackend;

use crate::error::{io_error, Result};

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
        let end = match start.checked_add(buf.len()) {
            Some(e) => e,
            None => data.len() + 1, // force EOF error below
        };
        if end > data.len() {
            return Err(io_error(
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "read of {} bytes at offset 0x{:x} exceeds data size {}",
                        buf.len(),
                        offset,
                        data.len()
                    ),
                ),
                offset,
                "MemoryBackend::read_exact_at",
            ));
        }
        buf.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        let mut data = self.data.write().unwrap();
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            io_error(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "write offset + length overflows usize",
                ),
                offset,
                "MemoryBackend::write_all_at",
            )
        })?;
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

    fn set_len(&self, size: u64) -> Result<()> {
        let mut data = self.data.write().unwrap();
        data.resize(size as usize, 0);
        Ok(())
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

    #[test]
    fn memory_backend_set_len_grow() {
        let backend = MemoryBackend::zeroed(100);
        backend.set_len(200).unwrap();
        assert_eq!(backend.file_size().unwrap(), 200);
        let mut buf = [0u8; 10];
        backend.read_exact_at(&mut buf, 150).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn memory_backend_set_len_shrink() {
        let backend = MemoryBackend::zeroed(200);
        backend.write_all_at(&[0xAA; 50], 0).unwrap();
        backend.set_len(100).unwrap();
        assert_eq!(backend.file_size().unwrap(), 100);
        let mut buf = [0u8; 50];
        backend.read_exact_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }
}
