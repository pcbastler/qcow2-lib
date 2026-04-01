//! In-memory metadata tracking for the block writer engine.
//!
//! All L2 entries and refcounts are stored in RAM. L2 entries are sparse
//! (only populated entries are stored) and materialized to full [`L2Table`]
//! structures during finalize.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::format::constants::COMPRESSED_SECTOR_SIZE;
use crate::format::l1::{L1Entry, L1Table};
use crate::format::l2::{L2Entry, L2Table};
use crate::format::refcount::{RefcountBlock, RefcountTableEntry};
use crate::format::types::{ClusterGeometry, ClusterOffset, L1Index, L2Index};

/// In-memory metadata for the block writer.
///
/// L2 entries are stored sparsely in a `BTreeMap` keyed by `(l1_index, l2_index)`.
/// This is memory-efficient for sparse images. Entries are materialized to full
/// `L2Table` instances during finalize.
pub struct InMemoryMetadata {
    /// Sparse L2 entries: (l1_index, l2_index) → entry.
    l2_entries: BTreeMap<(u32, u32), L2Entry>,
    /// Refcount tracking: cluster_index → refcount value.
    refcounts: BTreeMap<u64, u64>,
    /// Next host offset for data cluster allocation (append-only).
    next_host_offset: u64,
    /// Total number of L1 entries needed.
    l1_entries: u32,
    /// Refcount order (log2 of refcount bits, e.g. 4 = 16-bit).
    refcount_order: u32,
    /// Cluster geometry.
    geometry: ClusterGeometry,
    /// Current offset for compressed cluster packing.
    compressed_cursor: u64,
    /// End offset of the host cluster currently used for compressed packing.
    /// When `compressed_cursor >= compressed_cluster_end`, a new host cluster
    /// must be allocated. This prevents the cursor from advancing into host
    /// clusters allocated by `allocate_cluster()` for uncompressed data.
    compressed_cluster_end: u64,
    /// Cluster size cached for convenience.
    cluster_size: u64,
}

impl InMemoryMetadata {
    /// Create new in-memory metadata.
    pub fn new(
        geometry: ClusterGeometry,
        l1_entries: u32,
        refcount_order: u32,
        initial_host_offset: u64,
    ) -> Self {
        let cluster_size = geometry.cluster_size();
        Self {
            l2_entries: BTreeMap::new(),
            refcounts: BTreeMap::new(),
            next_host_offset: initial_host_offset,
            l1_entries,
            refcount_order,
            geometry,
            compressed_cursor: 0,
            compressed_cluster_end: 0,
            cluster_size,
        }
    }

    /// Allocate a single data cluster. Returns the host offset.
    pub fn allocate_cluster(&mut self) -> ClusterOffset {
        let offset = ClusterOffset(self.next_host_offset);
        self.next_host_offset += self.cluster_size;
        // If the compressed cursor overlaps with the newly allocated cluster,
        // invalidate it so the next compressed allocation starts fresh.
        if self.compressed_cursor >= offset.0
            && self.compressed_cursor < self.next_host_offset
        {
            self.compressed_cursor = 0;
            self.compressed_cluster_end = 0;
        }
        offset
    }

    /// Allocate `n` contiguous clusters. Returns the offset of the first.
    pub fn allocate_n_clusters(&mut self, n: u64) -> ClusterOffset {
        let offset = ClusterOffset(self.next_host_offset);
        self.next_host_offset += n * self.cluster_size;
        if self.compressed_cursor >= offset.0
            && self.compressed_cursor < self.next_host_offset
        {
            self.compressed_cursor = 0;
            self.compressed_cluster_end = 0;
        }
        offset
    }

    /// Set an L2 entry in the sparse map.
    pub fn set_l2_entry(&mut self, l1_index: L1Index, l2_index: L2Index, entry: L2Entry) {
        self.l2_entries.insert((l1_index.0, l2_index.0), entry);
    }

    /// Get an L2 entry from the sparse map.
    /// Reserved for future use (e.g. deduplication, pre-write validation).
    #[allow(dead_code)]
    pub fn get_l2_entry(&self, l1_index: L1Index, l2_index: L2Index) -> Option<&L2Entry> {
        self.l2_entries.get(&(l1_index.0, l2_index.0))
    }

    /// Increment the refcount for a cluster.
    pub fn increment_refcount(&mut self, cluster_offset: u64) {
        let cluster_index = cluster_offset / self.cluster_size;
        *self.refcounts.entry(cluster_index).or_insert(0) += 1;
    }

    /// Allocate space for a compressed cluster with packing.
    ///
    /// Returns `(write_offset, new_host_cluster_allocated)`.
    /// Compressed clusters are packed sequentially within host clusters.
    pub fn allocate_compressed(
        &mut self,
        compressed_size: u64,
    ) -> (u64, bool) {
        // Sector-align the compressed size
        let aligned_size =
            ((compressed_size + COMPRESSED_SECTOR_SIZE - 1) / COMPRESSED_SECTOR_SIZE)
                * COMPRESSED_SECTOR_SIZE;

        // Allocate a new host cluster when:
        // - cursor is 0 (initial state or invalidated by allocate_cluster)
        // - cursor has reached or passed the end of the current packing cluster
        //   (catches both exact-fill boundary and cursor advancing into
        //   independently allocated clusters)
        // - the entry would not fit in the remaining space of the current cluster
        let new_cluster = if self.compressed_cursor == 0
            || self.compressed_cursor >= self.compressed_cluster_end
            || (self.compressed_cursor % self.cluster_size) + aligned_size > self.cluster_size
        {
            let host = self.allocate_cluster();
            self.compressed_cursor = host.0;
            self.compressed_cluster_end = host.0 + self.cluster_size;
            true
        } else {
            false
        };

        let write_offset = self.compressed_cursor;
        self.compressed_cursor += aligned_size;
        (write_offset, new_cluster)
    }

    /// Current next host offset (end of allocated space).
    pub fn next_host_offset(&self) -> u64 {
        self.next_host_offset
    }

    /// Number of L1 entries.
    pub fn l1_entries(&self) -> u32 {
        self.l1_entries
    }

    /// Refcount order.
    pub fn refcount_order(&self) -> u32 {
        self.refcount_order
    }

    /// Collect all unique L1 indices that have at least one L2 entry.
    pub fn populated_l1_indices(&self) -> Vec<u32> {
        let mut indices: Vec<u32> = self.l2_entries.keys().map(|&(l1, _)| l1).collect();
        indices.dedup();
        indices
    }

    /// Materialize the sparse L2 entries for a given L1 index into a full L2Table.
    #[allow(clippy::clone_on_copy)]
    pub fn materialize_l2_table(&self, l1_index: u32) -> L2Table {
        let mut table = L2Table::new_empty(self.geometry);
        for (&(l1, l2), entry) in &self.l2_entries {
            if l1 == l1_index {
                // Intentional .clone() instead of *entry for robustness:
                // if L2Entry ever loses Copy, this still compiles.
                let _ = table.set(L2Index(l2), entry.clone());
            }
        }
        table
    }

    /// Build the L1 table from the L2 table host offsets.
    pub fn build_l1_table(
        &self,
        l2_offsets: &BTreeMap<u32, ClusterOffset>,
    ) -> L1Table {
        let mut l1 = L1Table::new_empty(self.l1_entries);
        for (&l1_index, &host_offset) in l2_offsets {
            let _ = l1.set(L1Index(l1_index), L1Entry::with_l2_offset(host_offset, true));
        }
        l1
    }

    /// Build refcount structures for all tracked clusters plus additional metadata clusters.
    ///
    /// Returns `(refcount_table_entries, refcount_blocks, block_offsets)`.
    pub fn build_refcount_structures(
        &self,
        additional_refcounts: &BTreeMap<u64, u64>,
    ) -> (Vec<RefcountTableEntry>, Vec<(u64, RefcountBlock)>) {
        let refcount_bits = 1u32 << self.refcount_order;
        let entries_per_block =
            (self.cluster_size as u32 * 8) / refcount_bits;

        // Merge data refcounts and additional (metadata) refcounts
        let mut all_refcounts: BTreeMap<u64, u64> = self.refcounts.clone();
        for (&idx, &val) in additional_refcounts {
            *all_refcounts.entry(idx).or_insert(0) += val;
        }

        // Determine how many refcount blocks we need
        let max_cluster_index = all_refcounts
            .keys()
            .last()
            .copied()
            .unwrap_or(0);
        let num_blocks =
            (max_cluster_index + entries_per_block as u64) / entries_per_block as u64;

        // Build refcount blocks
        let mut blocks = Vec::new();
        let mut rt_entries = Vec::new();

        for block_idx in 0..num_blocks {
            let mut block = RefcountBlock::new_empty(self.cluster_size as usize, self.refcount_order);
            let base = block_idx * entries_per_block as u64;
            let mut has_entries = false;

            for (&cluster_index, &refcount) in &all_refcounts {
                if cluster_index >= base && cluster_index < base + entries_per_block as u64 {
                    let local = (cluster_index - base) as u32;
                    let _ = block.set(local, refcount);
                    has_entries = true;
                }
            }

            if has_entries {
                blocks.push((block_idx, block));
            }
        }

        // Build refcount table entries (we'll fill in offsets during finalize)
        for _ in 0..num_blocks {
            rt_entries.push(RefcountTableEntry::unallocated());
        }

        (rt_entries, blocks)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use super::*;
    use crate::format::l2::SubclusterBitmap;

    fn test_geometry() -> ClusterGeometry {
        ClusterGeometry {
            cluster_bits: 16,
            extended_l2: false,
        }
    }

    #[test]
    fn allocate_cluster_sequential() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        let a = meta.allocate_cluster();
        let b = meta.allocate_cluster();
        assert_eq!(a, ClusterOffset(0x10000));
        assert_eq!(b, ClusterOffset(0x20000));
    }

    #[test]
    fn allocate_n_clusters() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        let offset = meta.allocate_n_clusters(3);
        assert_eq!(offset, ClusterOffset(0x10000));
        assert_eq!(meta.next_host_offset(), 0x10000 + 3 * 65536);
    }

    #[test]
    fn sparse_l2_entries() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);

        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x30000),
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        meta.set_l2_entry(L1Index(0), L2Index(5), entry.clone());

        assert!(meta.get_l2_entry(L1Index(0), L2Index(5)).is_some());
        assert!(meta.get_l2_entry(L1Index(0), L2Index(0)).is_none());
    }

    #[test]
    fn materialize_l2_table() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        let entry = L2Entry::Standard {
            host_offset: ClusterOffset(0x30000),
            copied: true,
            subclusters: SubclusterBitmap::all_allocated(),
        };
        meta.set_l2_entry(L1Index(0), L2Index(5), entry.clone());

        let table = meta.materialize_l2_table(0);
        let read_entry = table.get(L2Index(5)).unwrap();
        assert!(matches!(read_entry, L2Entry::Standard { .. }));
    }

    #[test]
    fn refcount_tracking() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        meta.increment_refcount(0x10000);
        meta.increment_refcount(0x10000);
        meta.increment_refcount(0x20000);

        // cluster_index 1 (0x10000/65536) has refcount 2
        assert_eq!(meta.refcounts.get(&1), Some(&2));
        // cluster_index 2 has refcount 1
        assert_eq!(meta.refcounts.get(&2), Some(&1));
    }

    #[test]
    fn populated_l1_indices() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        meta.set_l2_entry(
            L1Index(0),
            L2Index(0),
            L2Entry::Zero {
                preallocated_offset: None,
                subclusters: SubclusterBitmap::all_zero(),
            },
        );
        meta.set_l2_entry(
            L1Index(3),
            L2Index(0),
            L2Entry::Zero {
                preallocated_offset: None,
                subclusters: SubclusterBitmap::all_zero(),
            },
        );

        let indices = meta.populated_l1_indices();
        assert_eq!(indices, vec![0, 3]);
    }

    #[test]
    fn allocate_compressed_packing() {
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        // First compressed: allocates a new host cluster
        let (offset1, new1) = meta.allocate_compressed(400);
        assert!(new1);
        assert_eq!(offset1, 0x10000);

        // Second compressed: packs into same host cluster (400→512 aligned)
        let (offset2, new2) = meta.allocate_compressed(400);
        assert!(!new2);
        assert_eq!(offset2, 0x10000 + 512);
    }

    #[test]
    fn allocate_compressed_exact_cluster_boundary() {
        // Regression test for Bug 2: when compressed entries exactly fill a
        // host cluster (128 × 512 = 65536), the 129th entry must allocate
        // a new cluster instead of writing into unallocated space.
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        let cluster_size = 65536u64;

        // Fill exactly one host cluster: 128 entries × 512 bytes each
        let entries_per_cluster = cluster_size / 512;
        for i in 0..entries_per_cluster {
            let (offset, new) = meta.allocate_compressed(512);
            if i == 0 {
                assert!(new, "first entry should allocate a new cluster");
                assert_eq!(offset, 0x10000);
            } else {
                assert!(!new, "entry {i} should pack into existing cluster");
                assert_eq!(offset, 0x10000 + i * 512);
            }
        }

        // next_host_offset should be right after the first host cluster
        assert_eq!(meta.next_host_offset(), 0x10000 + cluster_size);

        // Entry 129: MUST allocate a new cluster, not reuse the exhausted one
        let (offset129, new129) = meta.allocate_compressed(512);
        assert!(
            new129,
            "entry after exact cluster fill must allocate new cluster"
        );
        assert_eq!(
            offset129,
            0x10000 + cluster_size,
            "new cluster should start at next_host_offset"
        );
        // next_host_offset advanced by one more cluster
        assert_eq!(meta.next_host_offset(), 0x10000 + 2 * cluster_size);
    }

    #[test]
    fn allocate_compressed_overflow_into_new_cluster() {
        // When a compressed entry doesn't fit in the remaining space,
        // a new cluster must be allocated.
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);

        // First entry: 512 bytes
        let (_, new1) = meta.allocate_compressed(512);
        assert!(new1);

        // Fill up most of the cluster: write 126 more entries (127 total = 65024)
        for _ in 1..127 {
            let (_, new) = meta.allocate_compressed(512);
            assert!(!new);
        }

        // 512 bytes left. Entry of 1024 bytes (aligned) doesn't fit.
        let (offset, new) = meta.allocate_compressed(1024);
        assert!(new, "should allocate new cluster when entry doesn't fit");
        assert_eq!(offset, 0x10000 + 65536);
    }

    #[test]
    fn allocate_compressed_interleaved_with_uncompressed() {
        // Compressed allocation followed by uncompressed allocation must
        // not produce overlapping ranges.
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);

        // Allocate 128 compressed entries (exactly fills one host cluster)
        for _ in 0..128 {
            meta.allocate_compressed(512);
        }

        // Allocate an uncompressed cluster — must not overlap
        let uncompressed = meta.allocate_cluster();
        assert!(
            uncompressed.0 >= 0x10000 + 65536,
            "uncompressed cluster must be beyond compressed data, got {:#x}",
            uncompressed.0
        );

        // Allocate another compressed entry — must allocate a fresh cluster
        let (offset, new) = meta.allocate_compressed(512);
        assert!(new);
        assert!(
            offset >= uncompressed.0 + 65536,
            "new compressed entry must be beyond uncompressed cluster"
        );
    }

    #[test]
    fn allocate_compressed_cursor_survives_non_overlapping_alloc() {
        // Positive test: when compressed cursor is in the MIDDLE of a host
        // cluster and allocate_cluster() is called, the cursor must NOT be
        // invalidated because it doesn't overlap with the new allocation.
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);

        // Pack 10 compressed entries (5120 bytes used, 60416 remaining)
        for _ in 0..10 {
            meta.allocate_compressed(512);
        }

        // Allocate an uncompressed cluster — at a different address
        let uncompressed = meta.allocate_cluster();
        assert_eq!(uncompressed.0, 0x10000 + 65536); // next cluster

        // Next compressed entry should STILL pack into the original cluster
        // because cursor (0x10000 + 5120) is NOT in the uncompressed range
        let (offset, new) = meta.allocate_compressed(512);
        assert!(
            !new,
            "cursor in middle of earlier cluster should still be valid"
        );
        assert_eq!(offset, 0x10000 + 10 * 512);
    }

    #[test]
    fn allocate_compressed_no_overlap_between_ranges() {
        // Exhaustive: allocate many compressed+uncompressed in alternation,
        // verify no two allocated ranges overlap.
        let mut meta = InMemoryMetadata::new(test_geometry(), 16, 4, 0x10000);
        let mut ranges: Vec<(u64, u64)> = Vec::new(); // (start, end)

        for round in 0..5 {
            // 130 compressed entries — crosses one cluster boundary
            for _ in 0..130 {
                let (offset, _) = meta.allocate_compressed(512);
                ranges.push((offset, offset + 512));
            }
            // 1 uncompressed cluster
            let uc = meta.allocate_cluster();
            ranges.push((uc.0, uc.0 + 65536));

            // Verify no overlaps so far
            let mut sorted = ranges.clone();
            sorted.sort_by_key(|&(start, _)| start);
            for w in sorted.windows(2) {
                let (_, end_a) = w[0];
                let (start_b, _) = w[1];
                assert!(
                    end_a <= start_b,
                    "round {round}: overlap detected: ..{end_a:#x} vs {start_b:#x}.."
                );
            }
        }
    }
}
