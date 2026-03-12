//! Write and Seek implementations for [`Qcow2BlockWriter`].

use std::io::{self, Seek, SeekFrom, Write};

use crate::error::Result;

use super::Qcow2BlockWriter;

impl Qcow2BlockWriter {
    /// Write data at a specific guest offset.
    ///
    /// Data is buffered internally. Full clusters are automatically flushed
    /// to disk after zero detection and optional compression/encryption.
    pub fn write_guest(&mut self, guest_offset: u64, data: &[u8]) -> Result<()> {
        self.engine.write_guest(
            guest_offset,
            data,
            self.backend.as_ref(),
            &self.compressor,
            self.crypt_context.as_ref(),
        )
    }

    /// Read data from the in-memory buffer at a guest offset.
    ///
    /// Returns an error if any covered cluster has already been flushed to disk.
    pub fn read_exact_at(&self, buf: &mut [u8], guest_offset: u64) -> Result<()> {
        self.engine.read_from_buffer(guest_offset, buf)
    }

    /// Virtual size of the image being written.
    pub fn virtual_size(&self) -> u64 {
        self.engine.virtual_size()
    }
}

impl Write for Qcow2BlockWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_guest(self.cursor, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.cursor += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.backend
            .flush()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

impl Seek for Qcow2BlockWriter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.cursor.checked_add(delta as u64)
                } else {
                    self.cursor.checked_sub((-delta) as u64)
                }
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek position overflow")
                })?
            }
            SeekFrom::End(delta) => {
                let size = self.engine.virtual_size();
                if delta >= 0 {
                    size.checked_add(delta as u64)
                } else {
                    size.checked_sub((-delta) as u64)
                }
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek position underflow")
                })?
            }
        };
        self.cursor = new_pos;
        Ok(new_pos)
    }
}
