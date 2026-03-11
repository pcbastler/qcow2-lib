//! Public accessor methods on `Qcow2ImageAsync`.

use crate::error::Result;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;

use super::{poisoned_err, Qcow2ImageAsync};

impl Qcow2ImageAsync {
    /// The parsed image header (cloned, since access requires locking).
    pub fn header(&self) -> Result<Header> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.clone())
    }

    /// The virtual disk size in bytes.
    pub fn virtual_size(&self) -> Result<u64> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.virtual_size)
    }

    /// The cluster size in bytes.
    pub fn cluster_size(&self) -> Result<u64> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.cluster_size())
    }

    /// The parsed extensions list (cloned).
    pub fn extensions(&self) -> Result<Vec<HeaderExtension>> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.extensions.clone())
    }

    /// Whether the image is encrypted.
    pub fn is_encrypted(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.header.crypt_method != 0)
    }

    /// Whether the image is writable.
    pub fn is_writable(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.writable)
    }

    /// Whether the image has the DIRTY flag set.
    pub fn is_dirty(&self) -> Result<bool> {
        let meta = self.meta.lock().map_err(|_| poisoned_err())?;
        Ok(meta.dirty)
    }
}
