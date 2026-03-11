//! Shared helpers for writing QCOW2 header metadata to disk.
//!
//! These free functions eliminate duplication between `BitmapManager`,
//! `HashManager`, `SnapshotManager`, and `Qcow2Image` which all need
//! to rewrite header extensions, feature flags, or flush dirty caches.

extern crate alloc;

use alloc::vec;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::error::{Error, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::io::IoBackend;

/// Byte offset of the `incompatible_features` field in the QCOW2 v3 header.
const OFF_INCOMPATIBLE_FEATURES: u64 = 72;

/// Byte offset of the `autoclear_features` field in the QCOW2 v3 header.
const OFF_AUTOCLEAR_FEATURES: u64 = 88;

/// Rewrite all header extensions into cluster 0 (after the fixed header).
///
/// Returns an error if the serialized extensions exceed the remaining
/// space in the first cluster.
pub fn write_header_extensions(
    backend: &dyn IoBackend,
    header: &Header,
    extensions: &[HeaderExtension],
    cluster_size: u64,
) -> Result<()> {
    let ext_data = HeaderExtension::write_all(extensions);
    let ext_start = header.header_length as u64;

    if ext_start + ext_data.len() as u64 > cluster_size {
        return Err(Error::HeaderExtensionOverflow {
            needed: ext_start as usize + ext_data.len(),
            cluster_size,
        });
    }

    backend.write_all_at(&ext_data, ext_start)?;
    Ok(())
}

/// Write the `autoclear_features` field to the on-disk header (offset 88).
pub fn write_autoclear_features(
    backend: &dyn IoBackend,
    autoclear: AutoclearFeatures,
) -> Result<()> {
    let mut buf = [0u8; 8];
    BigEndian::write_u64(&mut buf, autoclear.bits());
    backend.write_all_at(&buf, OFF_AUTOCLEAR_FEATURES)?;
    Ok(())
}

/// Write the `incompatible_features` field to the on-disk header (offset 72).
pub fn write_incompatible_features(
    backend: &dyn IoBackend,
    incompatible: IncompatibleFeatures,
) -> Result<()> {
    let mut buf = [0u8; 8];
    BigEndian::write_u64(&mut buf, incompatible.bits());
    backend.write_all_at(&buf, OFF_INCOMPATIBLE_FEATURES)?;
    Ok(())
}

/// Write both `incompatible_features` (offset 72) and `autoclear_features`
/// (offset 88) in a single I/O covering bytes 72..96 of the header.
///
/// This batches what would otherwise be 2-3 separate pwrite calls into one,
/// reducing syscall overhead in mark_dirty/clear_dirty.
pub fn write_dirty_header_fields(
    backend: &dyn IoBackend,
    incompatible: IncompatibleFeatures,
    autoclear: AutoclearFeatures,
) -> Result<()> {
    // Header layout bytes 72..96:
    //   72..80: incompatible_features (u64 BE)
    //   80..88: compatible_features   (u64 BE) — preserved from disk
    //   88..96: autoclear_features    (u64 BE)
    let mut buf = [0u8; 24];
    // Read existing compatible_features (offset 80) to preserve it
    backend.read_exact_at(&mut buf[8..16], OFF_INCOMPATIBLE_FEATURES + 8)?;
    BigEndian::write_u64(&mut buf[0..8], incompatible.bits());
    // buf[8..16] already has compatible_features
    BigEndian::write_u64(&mut buf[16..24], autoclear.bits());
    backend.write_all_at(&buf, OFF_INCOMPATIBLE_FEATURES)?;
    Ok(())
}

/// Flush all dirty metadata from cache to disk.
///
/// Order: pending evictions first, then refcount blocks, then L2 tables.
/// Refcount blocks are written before L2 tables for crash consistency:
/// a crash after refcount writes but before L2 writes leaves the image
/// with leaked (but not lost) clusters.
pub fn flush_dirty_metadata(
    backend: &dyn IoBackend,
    cache: &mut MetadataCache,
    cluster_bits: u32,
) -> Result<()> {
    let cluster_size = 1usize << cluster_bits;

    // Pending evictions first (already evicted from LRU but not yet written)
    let pending_l2 = cache.take_pending_l2_evictions();
    for (offset, table) in &pending_l2 {
        let mut buf = vec![0u8; cluster_size];
        table.write_to(&mut buf)?;
        backend.write_all_at(&buf, *offset)?;
    }
    let pending_rc = cache.take_pending_refcount_evictions();
    for (offset, block) in &pending_rc {
        let mut buf = vec![0u8; cluster_size];
        block.write_to(&mut buf)?;
        backend.write_all_at(&buf, *offset)?;
    }

    // In-cache dirty entries: refcount blocks first (crash consistency)
    cache.flush_refcount_blocks(
        &mut |offset: u64,
              block: &crate::format::refcount::RefcountBlock|
              -> Result<()> {
            let mut buf = vec![0u8; cluster_size];
            block.write_to(&mut buf)?;
            backend.write_all_at(&buf, offset)?;
            Ok(())
        },
    )?;

    // L2 tables second
    cache.flush_l2_tables(
        &mut |offset: u64, table: &crate::format::l2::L2Table| -> Result<()> {
            let mut buf = vec![0u8; cluster_size];
            table.write_to(&mut buf)?;
            backend.write_all_at(&buf, offset)?;
            Ok(())
        },
    )?;

    Ok(())
}
