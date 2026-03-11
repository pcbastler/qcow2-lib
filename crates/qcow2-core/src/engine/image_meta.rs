//! Shared metadata state for QCOW2 images.
//!
//! [`ImageMeta`] bundles all mutable metadata that both `Qcow2Image`
//! (single-threaded, `&mut self`) and `Qcow2ImageAsync` (thread-safe,
//! `Mutex`-protected) share. It lives in `qcow2-core` (no_std) and
//! contains no locks or OS primitives.

extern crate alloc;

use alloc::vec::Vec;

use crate::engine::cache::MetadataCache;
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::refcount_manager::RefcountManager;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;

/// Mutable metadata state for a QCOW2 image.
///
/// Contains all fields that need `&mut` access during read/write operations:
/// header, L1/L2 mapping, metadata cache, refcount tracking, and flags.
///
/// I/O backends, backing images, encryption contexts, and compressors
/// live outside this struct (they are either `&self`-safe or std-only).
pub struct ImageMeta {
    /// On-disk QCOW2 header (version, cluster size, virtual size, features, etc.).
    pub header: Header,
    /// Parsed header extensions (backing file format, feature name table, etc.).
    pub extensions: Vec<HeaderExtension>,
    /// L1/L2 cluster mapping tables.
    pub mapper: ClusterMapper,
    /// In-memory LRU cache for L2 and refcount tables.
    pub cache: MetadataCache,
    /// Refcount manager for cluster allocation/deallocation (None if read-only).
    pub refcount_manager: Option<RefcountManager>,
    /// Whether the image is opened for writing.
    pub writable: bool,
    /// Whether the DIRTY incompatible feature flag is set.
    pub dirty: bool,
    /// Byte offset for packing compressed clusters into shared host clusters.
    pub compressed_cursor: u64,
    /// Cached flag: true if any bitmap has the AUTO flag set.
    pub has_auto_bitmaps: bool,
    /// Cached flag: true if a BLAKE3 hash extension exists.
    pub has_hashes: bool,
    /// How unallocated/zero clusters are handled during reads.
    pub read_mode: ReadMode,
    /// Warnings collected during image open (e.g., dirty flag, unknown features).
    pub warnings: Vec<ReadWarning>,
    /// When true, `mark_dirty()` sets `dirty = true` in memory but skips
    /// writing the DIRTY flag to the on-disk header. Used by streaming
    /// backends where the header must remain clean (no patching).
    pub skip_dirty_marking: bool,
}

/// Describes how a write should be executed after metadata resolution.
///
/// Returned by [`ImageMeta::resolve_for_write`] to separate metadata
/// operations (inside lock) from data I/O (outside lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritePlan {
    /// Cluster is already allocated with refcount=1 (COPIED flag).
    /// Write data in-place at the given host offset.
    InPlace {
        /// Host file offset where data should be written.
        host_offset: u64,
        /// Byte offset within the cluster where the write starts.
        intra_cluster_offset: u64,
    },
    /// A new cluster was allocated. Write data to it, then call
    /// `commit_l2_entry` to update the L2 table.
    NewAlloc {
        /// Host file offset of the newly allocated cluster.
        host_offset: u64,
        /// Byte offset within the cluster where the write starts.
        intra_cluster_offset: u64,
    },
}
