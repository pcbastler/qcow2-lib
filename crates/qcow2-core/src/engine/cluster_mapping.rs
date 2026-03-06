//! Two-level cluster address translation.
//!
//! The heart of QCOW2: translates a guest virtual offset into a
//! [`ClusterResolution`] that tells the caller where to find (or not find)
//! the actual data.

extern crate alloc;

use alloc::vec;

use crate::engine::cache::MetadataCache;
use crate::error::{FormatError, Result};
use crate::format::compressed::CompressedClusterDescriptor;
use crate::format::l1::L1Table;
use crate::format::l2::{L2Entry, L2Table, SubclusterBitmap};
use crate::format::types::*;
use crate::io::IoBackend;

/// The result of resolving a guest offset to its physical location.
///
/// This enum drives the reader's main dispatch: each variant requires
/// a different strategy to produce guest data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterResolution {
    /// Data is stored at a specific host offset.
    Allocated {
        /// Host file offset of the start of the cluster.
        host_offset: ClusterOffset,
        /// Byte offset within the cluster where the requested data starts.
        intra_cluster_offset: IntraClusterOffset,
        /// Subcluster bitmap. In standard mode: `all_allocated()`.
        subclusters: SubclusterBitmap,
    },

    /// The cluster reads as all zeros (possibly with mixed zero/unallocated subclusters).
    Zero {
        /// Subcluster bitmap. In standard mode: `all_zero()`.
        bitmap: SubclusterBitmap,
        /// Byte offset within the cluster where the requested data starts.
        intra_cluster_offset: IntraClusterOffset,
    },

    /// The cluster is not allocated in this image; check the backing file.
    Unallocated,

    /// The cluster data is compressed.
    Compressed {
        /// Decoded compressed cluster descriptor.
        descriptor: CompressedClusterDescriptor,
        /// Byte offset within the decompressed cluster.
        intra_cluster_offset: IntraClusterOffset,
    },
}

/// Resolves guest offsets to physical cluster locations.
///
/// Encapsulates the QCOW2 two-level lookup algorithm:
/// `guest_offset -> L1[i] -> L2_table -> L2[j] -> ClusterResolution`
pub struct ClusterMapper {
    l1_table: L1Table,
    geometry: ClusterGeometry,
    file_size: u64,
}

impl ClusterMapper {
    /// Create a new cluster mapper.
    pub fn new(l1_table: L1Table, geometry: ClusterGeometry, file_size: u64) -> Self {
        Self {
            l1_table,
            geometry,
            file_size,
        }
    }

    /// Resolve a guest offset to a [`ClusterResolution`].
    ///
    /// May perform I/O to load L2 tables that are not in the cache.
    pub fn resolve(
        &self,
        guest_offset: GuestOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<ClusterResolution> {
        let (l1_index, l2_index, intra) = guest_offset.split(self.geometry);

        // Step 1: L1 lookup
        let l1_entry = self.l1_table.get(l1_index)?;
        let l2_offset = match l1_entry.l2_table_offset() {
            Some(offset) => offset,
            None => return Ok(ClusterResolution::Unallocated),
        };

        // Step 2: Load L2 table (cache-first)
        let l2_table = self.load_l2_table(l2_offset, backend, cache)?;

        // Step 3: L2 lookup
        let l2_entry = l2_table.get(l2_index)?;

        // Step 4: Map L2Entry to ClusterResolution
        match l2_entry {
            L2Entry::Unallocated => Ok(ClusterResolution::Unallocated),
            L2Entry::Zero { preallocated_offset: Some(host_offset), subclusters } => {
                // Zero entry with preallocated host cluster:
                // treat as Allocated so the reader can dispatch per-subcluster.
                Ok(ClusterResolution::Allocated {
                    host_offset,
                    intra_cluster_offset: intra,
                    subclusters,
                })
            }
            L2Entry::Zero { preallocated_offset: None, subclusters } => {
                if subclusters.is_all_unallocated() {
                    Ok(ClusterResolution::Unallocated)
                } else {
                    Ok(ClusterResolution::Zero {
                        bitmap: subclusters,
                        intra_cluster_offset: intra,
                    })
                }
            }
            L2Entry::Standard { host_offset, subclusters, .. } => {
                Ok(ClusterResolution::Allocated {
                    host_offset,
                    intra_cluster_offset: intra,
                    subclusters,
                })
            }
            L2Entry::Compressed(descriptor) => Ok(ClusterResolution::Compressed {
                descriptor,
                intra_cluster_offset: intra,
            }),
        }
    }

    /// Load an L2 table, checking the cache first.
    fn load_l2_table(
        &self,
        offset: ClusterOffset,
        backend: &dyn IoBackend,
        cache: &mut MetadataCache,
    ) -> Result<L2Table> {
        // Check cache first
        if let Some(table) = cache.get_l2_table(offset) {
            return Ok(table.clone());
        }

        // Validate L2 table offset against file size.
        // Note: overflow is impossible here because L1_OFFSET_MASK caps the
        // offset at ~1 EB (0x00FF_FFFF_FFFF_FE00) and max cluster_size is
        // 2 MB — their sum never exceeds u64.
        let cluster_size = self.geometry.cluster_size();
        let l2_end = offset.0 + cluster_size;
        if l2_end > self.file_size {
            return Err(FormatError::MetadataOffsetBeyondEof {
                offset: offset.0,
                size: cluster_size,
                file_size: self.file_size,
                context: "L2 table",
            }
            .into());
        }

        // Cache miss: read from backend
        let mut buf = vec![0u8; cluster_size as usize];
        backend.read_exact_at(&mut buf, offset.0)?;
        let table = L2Table::read_from(&buf, self.geometry)?;

        // Insert into cache
        cache.insert_l2_table(offset, table.clone());
        Ok(table)
    }

    /// Access the L1 table (for inspection/diagnostics).
    pub fn l1_table(&self) -> &L1Table {
        &self.l1_table
    }

    /// The cluster geometry used for address decomposition.
    pub fn geometry(&self) -> ClusterGeometry {
        self.geometry
    }

    /// The cluster_bits value used for address decomposition.
    pub fn cluster_bits(&self) -> u32 {
        self.geometry.cluster_bits
    }

    /// Whether this mapper uses extended L2 entries.
    pub fn extended_l2(&self) -> bool {
        self.geometry.extended_l2
    }

    /// Read an L1 entry by index.
    pub fn l1_entry(&self, index: L1Index) -> Result<crate::format::l1::L1Entry> {
        Ok(self.l1_table.get(index)?)
    }

    /// Update an L1 entry at the given index.
    pub fn set_l1_entry(
        &mut self,
        index: L1Index,
        entry: crate::format::l1::L1Entry,
    ) -> Result<()> {
        Ok(self.l1_table.set(index, entry)?)
    }

    /// Update the known file size (after extending the image file).
    pub fn set_file_size(&mut self, file_size: u64) {
        self.file_size = file_size;
    }

    /// Replace the L1 table (used during resize when the table relocates).
    pub fn replace_l1_table(&mut self, new_table: L1Table) {
        self.l1_table = new_table;
    }

    /// Mutable access to the L1 table (for in-place grow).
    pub fn l1_table_mut(&mut self) -> &mut L1Table {
        &mut self.l1_table
    }
}
