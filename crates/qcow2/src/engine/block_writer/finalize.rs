//! Finalize wrapper for [`Qcow2BlockWriter`].

use crate::error::Result;

use super::Qcow2BlockWriter;

impl Qcow2BlockWriter {
    /// Finalize the image: flush all remaining data and write metadata.
    ///
    /// This writes L2 tables, refcount structures, L1 table, and the header
    /// to produce a valid, self-contained QCOW2 file.
    ///
    /// Consumes `self` — no further writes are possible after finalization.
    pub fn finalize(mut self) -> Result<()> {
        self.engine.finalize(
            self.backend.as_ref(),
            &self.compressor,
            self.crypt_context.as_ref(),
        )
    }
}
