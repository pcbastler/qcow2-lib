//! Multi-block write buffer for the block writer engine.
//!
//! The buffer organizes guest data into blocks of 2 × cluster_size. Each block
//! contains two cluster slots. When a cluster slot becomes full, it is reported
//! to the engine for zero detection and potential flushing.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::types::ClusterGeometry;

/// State of a single cluster slot within a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterSlotState {
    /// No bytes written to this cluster yet.
    Empty,
    /// Some bytes written, not yet a full cluster.
    Partial,
    /// All bytes have been written (cluster is full).
    Full,
    /// Already flushed to disk at the given host offset.
    /// A host_offset of 0 indicates a zero cluster (no disk write).
    Flushed {
        /// Host offset where the cluster was written (0 for zero clusters).
        host_offset: u64,
    },
}

/// A single cluster slot within a block.
#[derive(Debug, Clone)]
pub struct ClusterSlot {
    /// Cluster data buffer (cluster_size bytes).
    pub data: Vec<u8>,
    /// Byte-level write tracking: a bit per byte would be expensive,
    /// so we track total bytes written. When == cluster_size, it's full.
    pub bytes_written: u64,
    /// Current state.
    pub state: ClusterSlotState,
}

impl ClusterSlot {
    fn new(cluster_size: usize) -> Self {
        Self {
            data: vec![0u8; cluster_size],
            bytes_written: 0,
            state: ClusterSlotState::Empty,
        }
    }
}

/// A block covering 2 adjacent clusters in guest space.
#[derive(Debug, Clone)]
pub struct BlockEntry {
    /// The two cluster slots (lower and upper cluster).
    pub slots: [ClusterSlot; 2],
    /// Monotonically increasing counter for LRU eviction.
    pub order: u64,
}

/// Descriptor for a cluster that became full and is ready for flushing.
#[derive(Debug)]
pub struct FlushableCluster {
    /// Guest offset of the cluster (cluster-aligned).
    pub guest_offset: u64,
    /// Copy of the full cluster data.
    pub data: Vec<u8>,
}

/// Descriptor for a cluster selected for eviction.
#[derive(Debug)]
pub struct EvictableCluster {
    /// Guest offset of the cluster (cluster-aligned).
    pub guest_offset: u64,
    /// The cluster data (zero-padded if partial).
    pub data: Vec<u8>,
}

/// Multi-block write buffer backed by a `BTreeMap`.
///
/// Blocks are indexed by guest block index (`guest_offset / block_size`).
/// Each block contains two cluster slots.
pub struct BlockBuffer {
    /// Blocks keyed by guest block index.
    blocks: BTreeMap<u64, BlockEntry>,
    /// Cluster size in bytes.
    cluster_size: u64,
    /// Block size = 2 × cluster_size.
    block_size: u64,
    /// Cluster geometry.
    geometry: ClusterGeometry,
    /// Current memory usage in bytes (number of allocated cluster buffers × cluster_size).
    memory_used: u64,
    /// Maximum allowed memory usage.
    memory_limit: u64,
    /// Monotonic counter for insertion order (used for eviction priority).
    order_counter: u64,
}

impl BlockBuffer {
    /// Create a new buffer.
    pub fn new(geometry: ClusterGeometry, memory_limit: u64) -> Self {
        let cluster_size = geometry.cluster_size();
        Self {
            blocks: BTreeMap::new(),
            cluster_size,
            block_size: 2 * cluster_size,
            geometry,
            memory_used: 0,
            memory_limit,
            order_counter: 0,
        }
    }

    /// Write guest data into the buffer.
    ///
    /// Returns a list of clusters that became full and should be flushed.
    /// Returns an error if any target cluster was already flushed.
    pub fn write_guest(
        &mut self,
        guest_offset: u64,
        data: &[u8],
    ) -> Result<Vec<FlushableCluster>> {
        let mut flushable = Vec::new();
        let mut remaining = data;
        let mut offset = guest_offset;
        let cluster_size = self.cluster_size;
        let block_size = self.block_size;

        while !remaining.is_empty() {
            let block_index = offset / block_size;
            let offset_in_block = offset % block_size;
            let slot_index = if offset_in_block < cluster_size {
                0
            } else {
                1
            };
            let offset_in_cluster = (offset % cluster_size) as usize;
            let space_in_cluster = cluster_size as usize - offset_in_cluster;
            let write_len = remaining.len().min(space_in_cluster);

            // Get or create the block
            let entry = self.get_or_create_block(block_index);
            let slot = &mut entry.slots[slot_index];

            // Check if already flushed
            if let ClusterSlotState::Flushed { host_offset } = slot.state {
                let guest_cluster_offset =
                    block_index * block_size + slot_index as u64 * cluster_size;
                return Err(Error::ClusterAlreadyFlushed {
                    guest_offset: guest_cluster_offset,
                    host_offset,
                });
            }

            // Write data into the slot
            slot.data[offset_in_cluster..offset_in_cluster + write_len]
                .copy_from_slice(&remaining[..write_len]);
            slot.bytes_written += write_len as u64;

            // Update state
            if slot.bytes_written >= cluster_size {
                slot.state = ClusterSlotState::Full;
                let guest_cluster_offset =
                    block_index * block_size + slot_index as u64 * cluster_size;
                flushable.push(FlushableCluster {
                    guest_offset: guest_cluster_offset,
                    data: slot.data[..cluster_size as usize].to_vec(),
                });
            } else if slot.state == ClusterSlotState::Empty {
                slot.state = ClusterSlotState::Partial;
            }

            remaining = &remaining[write_len..];
            offset += write_len as u64;
        }

        Ok(flushable)
    }

    /// Read data from the buffer at a guest offset.
    ///
    /// Returns an error if any covered cluster has already been flushed.
    pub fn read_from_buffer(
        &self,
        guest_offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let mut remaining = buf.len();
        let mut buf_offset = 0usize;
        let mut offset = guest_offset;

        while remaining > 0 {
            let block_index = offset / self.block_size;
            let slot_index = if (offset % self.block_size) < self.cluster_size {
                0
            } else {
                1
            };
            let offset_in_cluster = (offset % self.cluster_size) as usize;
            let readable = (self.cluster_size as usize - offset_in_cluster).min(remaining);

            match self.blocks.get(&block_index) {
                Some(entry) => {
                    let slot = &entry.slots[slot_index];
                    if let ClusterSlotState::Flushed { .. } = slot.state {
                        let guest_cluster_offset = block_index * self.block_size
                            + slot_index as u64 * self.cluster_size;
                        return Err(Error::ClusterNotInBuffer {
                            guest_offset: guest_cluster_offset,
                        });
                    }
                    buf[buf_offset..buf_offset + readable]
                        .copy_from_slice(&slot.data[offset_in_cluster..offset_in_cluster + readable]);
                }
                None => {
                    // Block not in buffer — return zeros (unwritten area)
                    buf[buf_offset..buf_offset + readable].fill(0);
                }
            }

            buf_offset += readable;
            remaining -= readable;
            offset += readable as u64;
        }

        Ok(())
    }

    /// Mark a cluster slot as flushed.
    pub fn mark_flushed(&mut self, guest_cluster_offset: u64, host_offset: u64) {
        let block_index = guest_cluster_offset / self.block_size;
        let slot_index = if (guest_cluster_offset % self.block_size) < self.cluster_size {
            0
        } else {
            1
        };

        if let Some(entry) = self.blocks.get_mut(&block_index) {
            entry.slots[slot_index].state = ClusterSlotState::Flushed { host_offset };
            // Clear data to free memory
            entry.slots[slot_index].data = Vec::new();
            self.memory_used = self.memory_used.saturating_sub(self.cluster_size);

            // If both slots are flushed, remove the entire block
            let both_flushed = entry.slots.iter().all(|s| {
                matches!(s.state, ClusterSlotState::Flushed { .. })
            });
            if both_flushed {
                self.blocks.remove(&block_index);
            }
        }
    }

    /// Returns `true` if memory usage exceeds the configured limit.
    pub fn memory_pressure(&self) -> bool {
        self.memory_used > self.memory_limit
    }

    /// Current memory usage in bytes.
    pub fn memory_used(&self) -> u64 {
        self.memory_used
    }

    /// Find clusters suitable for eviction (oldest blocks first, skip block 0).
    ///
    /// Returns clusters that are `Full` or `Partial` (partial ones are zero-padded).
    /// Never evicts block 0 (header area).
    pub fn evict_candidates(&mut self) -> Vec<EvictableCluster> {
        let mut candidates: Vec<(u64, u64, usize)> = Vec::new(); // (order, block_index, slot_index)

        for (&block_index, entry) in &self.blocks {
            // Never evict block 0
            if block_index == 0 {
                continue;
            }
            for (slot_index, slot) in entry.slots.iter().enumerate() {
                match slot.state {
                    ClusterSlotState::Full | ClusterSlotState::Partial => {
                        candidates.push((entry.order, block_index, slot_index));
                    }
                    _ => {}
                }
            }
        }

        // Sort by insertion order (oldest first)
        candidates.sort_by_key(|&(order, _, _)| order);

        let mut result = Vec::new();
        for (_, block_index, slot_index) in candidates {
            if !self.memory_pressure() {
                break;
            }

            let guest_cluster_offset =
                block_index * self.block_size + slot_index as u64 * self.cluster_size;

            if let Some(entry) = self.blocks.get(&block_index) {
                let slot = &entry.slots[slot_index];
                // Data is already zero-initialized, so partial writes are zero-padded
                result.push(EvictableCluster {
                    guest_offset: guest_cluster_offset,
                    data: slot.data.clone(),
                });
            }
        }

        result
    }

    /// Drain all remaining non-flushed clusters from the buffer.
    ///
    /// Used during finalize to flush everything. Returns clusters in guest offset order.
    pub fn drain_remaining(&mut self) -> Vec<FlushableCluster> {
        let mut result = Vec::new();

        let block_indices: Vec<u64> = self.blocks.keys().copied().collect();
        for block_index in block_indices {
            if let Some(entry) = self.blocks.get(&block_index) {
                for (slot_index, slot) in entry.slots.iter().enumerate() {
                    match slot.state {
                        ClusterSlotState::Full
                        | ClusterSlotState::Partial
                        | ClusterSlotState::Empty => {
                            // Skip truly empty slots (never written to)
                            if slot.state == ClusterSlotState::Empty {
                                continue;
                            }
                            let guest_cluster_offset = block_index * self.block_size
                                + slot_index as u64 * self.cluster_size;
                            result.push(FlushableCluster {
                                guest_offset: guest_cluster_offset,
                                data: slot.data.clone(),
                            });
                        }
                        ClusterSlotState::Flushed { .. } => {}
                    }
                }
            }
        }

        result
    }

    /// Get or create a block for the given block index.
    fn get_or_create_block(&mut self, block_index: u64) -> &mut BlockEntry {
        let cluster_size = self.cluster_size as usize;
        let order_counter = &mut self.order_counter;
        let memory_used = &mut self.memory_used;

        self.blocks.entry(block_index).or_insert_with(|| {
            let order = *order_counter;
            *order_counter += 1;
            *memory_used += 2 * cluster_size as u64;
            BlockEntry {
                slots: [
                    ClusterSlot::new(cluster_size),
                    ClusterSlot::new(cluster_size),
                ],
                order,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use super::*;

    fn test_geometry() -> ClusterGeometry {
        ClusterGeometry {
            cluster_bits: 16,
            extended_l2: false,
        }
    }

    #[test]
    fn write_single_cluster() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let data = vec![0xAA; 65536];
        let flushable = buf.write_guest(0, &data).unwrap();
        assert_eq!(flushable.len(), 1);
        assert_eq!(flushable[0].guest_offset, 0);
        assert_eq!(flushable[0].data, data);
    }

    #[test]
    fn write_partial_then_complete() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let half = vec![0xBB; 32768];

        // First half — no flushable yet
        let f = buf.write_guest(0, &half).unwrap();
        assert!(f.is_empty());

        // Second half — now it's full
        let f = buf.write_guest(32768, &half).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].guest_offset, 0);
    }

    #[test]
    fn write_spanning_two_clusters() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        // Write 128 KiB starting at offset 0 — covers two clusters
        let data = vec![0xCC; 131072];
        let f = buf.write_guest(0, &data).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].guest_offset, 0);
        assert_eq!(f[1].guest_offset, 65536);
    }

    #[test]
    fn read_from_buffer() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let data = vec![0xDD; 1024];
        buf.write_guest(4096, &data).unwrap();

        // Read back
        let mut read_buf = vec![0u8; 1024];
        buf.read_from_buffer(4096, &mut read_buf).unwrap();
        assert_eq!(read_buf, data);

        // Read unwritten area — should be zeros
        let mut zero_buf = vec![0xFFu8; 1024];
        buf.read_from_buffer(0, &mut zero_buf).unwrap();
        assert_eq!(zero_buf, vec![0u8; 1024]);
    }

    #[test]
    fn read_flushed_cluster_errors() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let data = vec![0xEE; 65536];
        buf.write_guest(0, &data).unwrap();
        buf.mark_flushed(0, 0x30000);

        let mut read_buf = vec![0u8; 1024];
        let err = buf.read_from_buffer(0, &mut read_buf).unwrap_err();
        assert!(matches!(err, Error::ClusterNotInBuffer { guest_offset: 0 }));
    }

    #[test]
    fn rewrite_flushed_cluster_errors() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let data = vec![0xFF; 65536];
        buf.write_guest(0, &data).unwrap();
        buf.mark_flushed(0, 0x30000);

        let err = buf.write_guest(0, &[1]).unwrap_err();
        assert!(matches!(
            err,
            Error::ClusterAlreadyFlushed {
                guest_offset: 0,
                host_offset: 0x30000,
            }
        ));
    }

    #[test]
    fn mark_flushed_removes_block_when_both_done() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        let data = vec![0xAA; 131072]; // 2 clusters
        buf.write_guest(0, &data).unwrap();

        buf.mark_flushed(0, 0x10000);
        // Block still exists (second slot not flushed yet)
        assert!(buf.memory_used > 0);

        buf.mark_flushed(65536, 0x20000);
        // Both flushed — block removed
        assert_eq!(buf.blocks.len(), 0);
    }

    #[test]
    fn drain_remaining() {
        let mut buf = BlockBuffer::new(test_geometry(), u64::MAX);
        // Write partial to cluster 0 and full to cluster 1
        buf.write_guest(0, &vec![0x11; 1024]).unwrap();
        let full = vec![0x22; 65536];
        buf.write_guest(65536, &full).unwrap();
        // Flush cluster 1
        buf.mark_flushed(65536, 0x10000);

        let remaining = buf.drain_remaining();
        // Only cluster 0 (partial) should remain
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].guest_offset, 0);
    }

    #[test]
    fn memory_pressure() {
        // Limit to 1 block (2 clusters = 128 KiB)
        let mut buf = BlockBuffer::new(test_geometry(), 128 * 1024);
        assert!(!buf.memory_pressure());

        // Write one block — at limit
        buf.write_guest(0, &vec![0xAA; 65536]).unwrap();
        assert!(!buf.memory_pressure());

        // Write to second block — over limit
        buf.write_guest(131072, &vec![0xBB; 65536]).unwrap();
        assert!(buf.memory_pressure());
    }
}
