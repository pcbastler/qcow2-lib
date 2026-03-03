//! Image integrity checking and refcount repair.
//!
//! Provides library-level integrity verification by walking all L1/L2 tables
//! (active **and** snapshot) to build a reference count map, then comparing
//! it against the stored refcounts. Optionally repairs mismatches in-place.

use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cache::MetadataCache;
use crate::engine::refcount_manager::RefcountManager;
use crate::error::Result;
use crate::format::bitmap::{BitmapDirectoryEntry, BitmapTableEntryState};
use crate::format::constants::*;
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::L1Entry;
use crate::format::l2::{L2Entry, L2Table};
use crate::format::refcount::{RefcountBlock, RefcountTableEntry};
use crate::format::snapshot::SnapshotHeader;
use crate::io::IoBackend;

/// Statistics about cluster types found during the walk.
#[derive(Debug, Clone, Default)]
pub struct ClusterStats {
    /// Number of standard (allocated, uncompressed) data clusters.
    pub data_clusters: u64,
    /// Number of compressed data clusters.
    pub compressed_clusters: u64,
    /// Number of zero clusters.
    pub zero_clusters: u64,
    /// Number of unallocated L2 entries.
    pub unallocated_entries: u64,
}

/// A mismatch between stored and expected refcount.
#[derive(Debug, Clone)]
pub struct RefcountMismatch {
    /// Cluster index (host_offset / cluster_size).
    pub cluster_index: u64,
    /// Refcount computed by walking metadata.
    pub expected: u64,
    /// Refcount stored on disk.
    pub stored: u64,
}

/// A cluster with a stored refcount > 0 but no references.
#[derive(Debug, Clone)]
pub struct LeakedCluster {
    /// Cluster index (host_offset / cluster_size).
    pub cluster_index: u64,
    /// The stored refcount value.
    pub stored_refcount: u64,
}

/// Complete report from an integrity check.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    /// Cluster type statistics from the walk.
    pub stats: ClusterStats,
    /// Clusters where stored != expected refcount.
    pub mismatches: Vec<RefcountMismatch>,
    /// Clusters with stored refcount > 0 but no references.
    pub leaks: Vec<LeakedCluster>,
    /// The full reference map (cluster_index → expected_refcount).
    pub reference_map: HashMap<u64, u64>,
}

impl IntegrityReport {
    /// Returns `true` if no mismatches or leaks were found.
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty() && self.leaks.is_empty()
    }

    /// Total number of issues found.
    pub fn total_errors(&self) -> usize {
        self.mismatches.len() + self.leaks.len()
    }
}

/// How to repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    /// Only fix leaked clusters (set their refcount to 0).
    LeaksOnly,
    /// Fix all mismatches and leaks.
    Full,
}

/// Summary of what was repaired.
#[derive(Debug, Clone)]
pub struct RepairResult {
    /// Number of leaked clusters freed (refcount set to 0).
    pub leaks_fixed: u64,
    /// Number of refcount mismatches corrected.
    pub mismatches_fixed: u64,
}

// ---------------------------------------------------------------------------
// Build reference map
// ---------------------------------------------------------------------------

/// Walk all metadata structures to build the expected refcount for every
/// referenced host cluster.
///
/// This walks:
/// 1. Header cluster (cluster 0)
/// 2. Active L1 table clusters
/// 3. Refcount table clusters
/// 4. Active L1 → L2 tables → data/compressed/zero clusters
/// 5. Snapshot table clusters (if any)
/// 6. Each snapshot's L1 → L2 tables
/// 7. Refcount block clusters
pub fn build_reference_map(
    backend: &dyn IoBackend,
    header: &Header,
) -> Result<(HashMap<u64, u64>, ClusterStats)> {
    let cluster_size = header.cluster_size();
    let mut refs: HashMap<u64, u64> = HashMap::new();
    let mut stats = ClusterStats::default();

    // 1. Header cluster
    add_ref(&mut refs, 0, cluster_size);

    // 2. Active L1 table clusters
    let l1_byte_size = header.l1_table_entries as u64 * L1_ENTRY_SIZE as u64;
    let l1_cluster_count = (l1_byte_size + cluster_size - 1) / cluster_size;
    for c in 0..l1_cluster_count {
        add_ref(&mut refs, header.l1_table_offset.0 + c * cluster_size, cluster_size);
    }

    // 3. Refcount table clusters
    for c in 0..header.refcount_table_clusters as u64 {
        add_ref(&mut refs, header.refcount_table_offset.0 + c * cluster_size, cluster_size);
    }

    // 4. Walk active L1/L2
    walk_l1_l2(
        backend,
        header.l1_table_offset.0,
        header.l1_table_entries,
        header.cluster_bits,
        cluster_size,
        &mut refs,
        &mut stats,
    )?;

    // 5+6. Snapshot table + snapshot L1/L2s
    if header.snapshot_count > 0 {
        let snap_table_buf = read_snapshot_table_raw(backend, header, cluster_size)?;
        let snapshots = SnapshotHeader::read_table(
            &snap_table_buf,
            header.snapshot_count,
            header.snapshots_offset.0,
        )?;

        // Count snapshot table clusters (compute actual serialized size, not
        // the over-read buffer size from read_snapshot_table_raw)
        let mut snap_table_size = 0u64;
        for snap in &snapshots {
            let mut tmp = Vec::new();
            snap.write_to(&mut tmp);
            snap_table_size += tmp.len() as u64;
        }
        let snap_cluster_count = (snap_table_size + cluster_size - 1) / cluster_size;
        for c in 0..snap_cluster_count {
            add_ref(&mut refs, header.snapshots_offset.0 + c * cluster_size, cluster_size);
        }

        // Walk each snapshot's L1/L2
        for snap in &snapshots {
            // Count snapshot L1 table clusters
            let snap_l1_bytes = snap.l1_table_entries as u64 * L1_ENTRY_SIZE as u64;
            let snap_l1_clusters = (snap_l1_bytes + cluster_size - 1) / cluster_size;
            for c in 0..snap_l1_clusters {
                add_ref(&mut refs, snap.l1_table_offset.0 + c * cluster_size, cluster_size);
            }

            walk_l1_l2(
                backend,
                snap.l1_table_offset.0,
                snap.l1_table_entries,
                header.cluster_bits,
                cluster_size,
                &mut refs,
                &mut stats,
            )?;
        }
    }

    // 7. Refcount block clusters
    let rt_byte_size = header.refcount_table_clusters as u64 * cluster_size;
    if rt_byte_size > 0 {
        let mut rt_buf = vec![0u8; rt_byte_size as usize];
        backend.read_exact_at(&mut rt_buf, header.refcount_table_offset.0)?;

        let entry_count = rt_byte_size as usize / REFCOUNT_TABLE_ENTRY_SIZE;
        for i in 0..entry_count {
            let raw = BigEndian::read_u64(&rt_buf[i * REFCOUNT_TABLE_ENTRY_SIZE..]);
            let entry = RefcountTableEntry::from_raw(raw);
            if let Some(block_offset) = entry.block_offset() {
                add_ref(&mut refs, block_offset.0, cluster_size);
            }
        }
    }

    // 8. Bitmap clusters (directory, tables, data)
    walk_bitmaps(backend, header, cluster_size, &mut refs)?;

    Ok((refs, stats))
}

/// Check integrity: build reference map and compare with stored refcounts.
pub fn check_integrity(
    backend: &dyn IoBackend,
    header: &Header,
) -> Result<IntegrityReport> {
    let cluster_size = header.cluster_size();
    let (reference_map, stats) = build_reference_map(backend, header)?;

    let mut mismatches = Vec::new();
    let mut leaks = Vec::new();

    // Read refcount table
    let rt_byte_size = header.refcount_table_clusters as u64 * cluster_size;
    if rt_byte_size > 0 {
        let mut rt_buf = vec![0u8; rt_byte_size as usize];
        backend.read_exact_at(&mut rt_buf, header.refcount_table_offset.0)?;

        let entry_count = rt_byte_size as usize / REFCOUNT_TABLE_ENTRY_SIZE;
        let entries_per_block = header.refcounts_per_block() as usize;

        for rt_idx in 0..entry_count {
            let raw = BigEndian::read_u64(&rt_buf[rt_idx * REFCOUNT_TABLE_ENTRY_SIZE..]);
            let rt_entry = RefcountTableEntry::from_raw(raw);

            let block_offset = match rt_entry.block_offset() {
                Some(o) => o,
                None => continue,
            };

            let mut block_buf = vec![0u8; cluster_size as usize];
            backend.read_exact_at(&mut block_buf, block_offset.0)?;
            let block = RefcountBlock::read_from(&block_buf, header.refcount_order)?;

            let base_cluster = rt_idx * entries_per_block;

            for bi in 0..entries_per_block {
                let cluster_idx = (base_cluster + bi) as u64;
                let stored = block.get(bi as u32)?;
                let expected = reference_map.get(&cluster_idx).copied().unwrap_or(0);

                if stored != expected {
                    if expected == 0 && stored > 0 {
                        leaks.push(LeakedCluster {
                            cluster_index: cluster_idx,
                            stored_refcount: stored,
                        });
                    } else {
                        mismatches.push(RefcountMismatch {
                            cluster_index: cluster_idx,
                            expected,
                            stored,
                        });
                    }
                }
            }
        }
    }

    Ok(IntegrityReport {
        stats,
        mismatches,
        leaks,
        reference_map,
    })
}

// ---------------------------------------------------------------------------
// Repair
// ---------------------------------------------------------------------------

/// Repair refcounts in-place.
///
/// After fixing refcounts, updates COPIED flags on the active L1/L2 tables:
/// entries with refcount == 1 get COPIED=true (safe for in-place writes),
/// entries with refcount > 1 get COPIED=false (require COW).
pub fn repair_refcounts(
    backend: &dyn IoBackend,
    header: &Header,
    refcount_manager: &mut RefcountManager,
    cache: &mut MetadataCache,
    mode: RepairMode,
) -> Result<RepairResult> {
    let report = check_integrity(backend, header)?;

    let mut result = RepairResult {
        leaks_fixed: 0,
        mismatches_fixed: 0,
    };

    // Fix leaks (both modes)
    for leak in &report.leaks {
        let cluster_size = header.cluster_size();
        let host_offset = leak.cluster_index * cluster_size;
        refcount_manager.set_refcount(host_offset, 0, backend, cache)?;
        result.leaks_fixed += 1;
    }

    // Fix mismatches (Full mode only)
    if mode == RepairMode::Full {
        for mismatch in &report.mismatches {
            let cluster_size = header.cluster_size();
            let host_offset = mismatch.cluster_index * cluster_size;
            refcount_manager.set_refcount(
                host_offset,
                mismatch.expected,
                backend,
                cache,
            )?;
            result.mismatches_fixed += 1;
        }
    }

    // Fix COPIED flags on active L1/L2 entries
    if result.leaks_fixed > 0 || result.mismatches_fixed > 0 {
        fix_copied_flags(backend, header, refcount_manager, cache)?;
    }

    Ok(result)
}

/// Walk the active L1/L2 tables and fix COPIED flags based on current refcounts.
///
/// An L1 or L2 entry should have COPIED=true if and only if the referenced
/// cluster has refcount == 1.
fn fix_copied_flags(
    backend: &dyn IoBackend,
    header: &Header,
    refcount_manager: &mut RefcountManager,
    cache: &mut MetadataCache,
) -> Result<()> {
    let cluster_size = header.cluster_size();
    let l1_byte_size = header.l1_table_entries as usize * L1_ENTRY_SIZE;
    if l1_byte_size == 0 {
        return Ok(());
    }

    let mut l1_buf = vec![0u8; l1_byte_size];
    backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;

    for l1_idx in 0..header.l1_table_entries as usize {
        let raw = BigEndian::read_u64(&l1_buf[l1_idx * L1_ENTRY_SIZE..]);
        let l1_entry = L1Entry::from_raw(raw);

        let l2_offset = match l1_entry.l2_table_offset() {
            Some(o) => o,
            None => continue,
        };

        // Fix L1 COPIED flag
        let l2_rc = refcount_manager.get_refcount(l2_offset.0, backend, cache)?;
        let l1_should_be_copied = l2_rc == 1;
        if l1_entry.is_copied() != l1_should_be_copied {
            let fixed = L1Entry::with_l2_offset(l2_offset, l1_should_be_copied);
            let disk_offset =
                header.l1_table_offset.0 + (l1_idx as u64 * L1_ENTRY_SIZE as u64);
            let mut entry_buf = [0u8; 8];
            BigEndian::write_u64(&mut entry_buf, fixed.raw());
            backend.write_all_at(&entry_buf, disk_offset)?;
        }

        // Fix L2 COPIED flags
        let mut l2_buf = vec![0u8; cluster_size as usize];
        backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
        let l2_table = L2Table::read_from(&l2_buf, header.cluster_bits)?;
        let entries_per_l2 = cluster_size as usize / L2_ENTRY_SIZE;
        let mut l2_modified = false;

        for l2_idx in 0..entries_per_l2 {
            let entry = l2_table.get(crate::format::types::L2Index(l2_idx as u32))?;
            if let L2Entry::Standard {
                host_offset,
                copied,
            } = entry
            {
                let data_rc =
                    refcount_manager.get_refcount(host_offset.0, backend, cache)?;
                let should_be_copied = data_rc == 1;
                if copied != should_be_copied {
                    let fixed = L2Entry::Standard {
                        host_offset,
                        copied: should_be_copied,
                    };
                    let entry_offset =
                        l2_offset.0 + (l2_idx as u64 * L2_ENTRY_SIZE as u64);
                    let mut entry_buf = [0u8; 8];
                    BigEndian::write_u64(
                        &mut entry_buf,
                        fixed.encode(header.cluster_bits),
                    );
                    backend.write_all_at(&entry_buf, entry_offset)?;
                    l2_modified = true;
                }
            }
        }

        if l2_modified {
            cache.evict_l2_table(l2_offset);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Increment the reference count for a host cluster.
fn add_ref(refs: &mut HashMap<u64, u64>, host_offset: u64, cluster_size: u64) {
    let cluster_idx = host_offset / cluster_size;
    *refs.entry(cluster_idx).or_insert(0) += 1;
}

/// Walk an L1 table and all its L2 tables, counting references.
fn walk_l1_l2(
    backend: &dyn IoBackend,
    l1_offset: u64,
    l1_entries: u32,
    cluster_bits: u32,
    cluster_size: u64,
    refs: &mut HashMap<u64, u64>,
    stats: &mut ClusterStats,
) -> Result<()> {
    if l1_entries == 0 {
        return Ok(());
    }

    let l1_byte_size = l1_entries as usize * L1_ENTRY_SIZE;
    let mut l1_buf = vec![0u8; l1_byte_size];
    backend.read_exact_at(&mut l1_buf, l1_offset)?;

    let entries_per_l2 = cluster_size as usize / L2_ENTRY_SIZE;

    for l1_idx in 0..l1_entries as usize {
        let raw = BigEndian::read_u64(&l1_buf[l1_idx * L1_ENTRY_SIZE..]);
        let l1_entry = L1Entry::from_raw(raw);

        let l2_offset = match l1_entry.l2_table_offset() {
            Some(offset) => offset,
            None => continue,
        };

        // Count L2 table cluster
        let l2_cluster = l2_offset.0 / cluster_size;
        *refs.entry(l2_cluster).or_insert(0) += 1;

        // Read and walk L2 table
        let mut l2_buf = vec![0u8; cluster_size as usize];
        backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
        let l2_table = L2Table::read_from(&l2_buf, cluster_bits)?;

        for l2_idx in 0..entries_per_l2 {
            let entry = l2_table
                .get(crate::format::types::L2Index(l2_idx as u32))?;

            match entry {
                L2Entry::Unallocated => {
                    stats.unallocated_entries += 1;
                }
                L2Entry::Zero {
                    preallocated_offset,
                } => {
                    stats.zero_clusters += 1;
                    if let Some(offset) = preallocated_offset {
                        let cluster = offset.0 / cluster_size;
                        *refs.entry(cluster).or_insert(0) += 1;
                    }
                }
                L2Entry::Standard { host_offset, .. } => {
                    stats.data_clusters += 1;
                    let cluster = host_offset.0 / cluster_size;
                    *refs.entry(cluster).or_insert(0) += 1;
                }
                L2Entry::Compressed(desc) => {
                    stats.compressed_clusters += 1;
                    let start_cluster = desc.host_offset / cluster_size;
                    let end_byte = desc.host_offset + desc.compressed_size;
                    let end_cluster =
                        (end_byte + cluster_size - 1) / cluster_size;
                    for c in start_cluster..end_cluster {
                        *refs.entry(c).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Walk bitmap structures and count all referenced clusters.
///
/// Counts:
/// - Bitmap directory clusters
/// - Bitmap table clusters (per bitmap)
/// - Bitmap data clusters (from table entries with data offsets)
fn walk_bitmaps(
    backend: &dyn IoBackend,
    header: &Header,
    cluster_size: u64,
    refs: &mut HashMap<u64, u64>,
) -> Result<()> {
    // Read header extensions to find bitmap extension
    let ext_start = header.header_length as u64;
    let ext_end = cluster_size.min(backend.file_size()?);
    if ext_start >= ext_end {
        return Ok(());
    }

    let mut ext_buf = vec![0u8; (ext_end - ext_start) as usize];
    backend.read_exact_at(&mut ext_buf, ext_start)?;
    let extensions = HeaderExtension::read_all(&ext_buf).unwrap_or_default();

    let bitmap_ext = match extensions.iter().find_map(|e| match e {
        HeaderExtension::Bitmaps(b) => Some(b),
        _ => None,
    }) {
        Some(ext) if ext.nb_bitmaps > 0 => ext,
        _ => return Ok(()),
    };

    // Count directory clusters
    let dir_cluster_count =
        (bitmap_ext.bitmap_directory_size + cluster_size - 1) / cluster_size;
    for c in 0..dir_cluster_count {
        add_ref(
            refs,
            bitmap_ext.bitmap_directory_offset + c * cluster_size,
            cluster_size,
        );
    }

    // Read directory entries
    let mut dir_buf = vec![0u8; bitmap_ext.bitmap_directory_size as usize];
    backend.read_exact_at(&mut dir_buf, bitmap_ext.bitmap_directory_offset)?;
    let entries =
        BitmapDirectoryEntry::read_directory(&dir_buf, bitmap_ext.nb_bitmaps)?;

    for entry in &entries {
        // Count bitmap table clusters
        let table_byte_size =
            entry.bitmap_table_size as u64 * BITMAP_TABLE_ENTRY_SIZE as u64;
        let table_cluster_count =
            (table_byte_size + cluster_size - 1) / cluster_size;
        for c in 0..table_cluster_count {
            add_ref(
                refs,
                entry.bitmap_table_offset.0 + c * cluster_size,
                cluster_size,
            );
        }

        // Read bitmap table and count data clusters
        let mut table_buf =
            vec![0u8; entry.bitmap_table_size as usize * BITMAP_TABLE_ENTRY_SIZE];
        backend.read_exact_at(&mut table_buf, entry.bitmap_table_offset.0)?;
        let table = crate::format::bitmap::BitmapTable::read_from(
            &table_buf,
            entry.bitmap_table_size,
        )?;

        for i in 0..table.len() {
            let te = table
                .get(crate::format::types::BitmapIndex(i as u32))
                .unwrap();
            if let BitmapTableEntryState::Data(data_offset) = te.state() {
                add_ref(refs, data_offset.0, cluster_size);
            }
        }
    }

    Ok(())
}

/// Read the raw bytes of the snapshot table from the image.
fn read_snapshot_table_raw(
    backend: &dyn IoBackend,
    header: &Header,
    cluster_size: u64,
) -> Result<Vec<u8>> {
    // Over-read: snapshot table can span multiple clusters, but we don't know
    // the exact size until we parse it. Read a generous amount.
    let file_size = backend.file_size()?;
    let max_read = (file_size - header.snapshots_offset.0).min(
        // Safety limit: at most 64 clusters of snapshot data
        64 * cluster_size,
    );
    let mut buf = vec![0u8; max_read as usize];
    backend.read_exact_at(&mut buf, header.snapshots_offset.0)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::image::{CreateOptions, Qcow2Image};

    #[test]
    fn empty_image_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "empty image should be clean: {} mismatches, {} leaks",
            report.mismatches.len(),
            report.leaks.len()
        );
    }

    #[test]
    fn image_with_data_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.write_at(&[0xBB; 512], 65536).unwrap();
        image.flush().unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "image with data should be clean: {} mismatches, {} leaks",
            report.mismatches.len(),
            report.leaks.len()
        );
        assert!(report.stats.data_clusters >= 2);
    }

    #[test]
    fn image_with_snapshot_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.flush().unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "image with snapshot should be clean: mismatches={:?}, leaks={:?}",
            report.mismatches,
            report.leaks
        );
    }

    #[test]
    fn snapshot_cow_write_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        // COW write
        image.write_at(&[0xBB; 4096], 0).unwrap();
        image.flush().unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "COW write should be clean: mismatches={:?}, leaks={:?}",
            report.mismatches,
            report.leaks
        );
    }

    #[test]
    fn multiple_snapshots_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.write_at(&[0xBB; 4096], 0).unwrap();
        image.snapshot_create("snap2").unwrap();
        image.write_at(&[0xCC; 4096], 0).unwrap();
        image.flush().unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "multiple snapshots should be clean: mismatches={:?}, leaks={:?}",
            report.mismatches,
            report.leaks
        );
    }

    #[test]
    fn snapshot_delete_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.snapshot_delete("snap1").unwrap();
        image.flush().unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "after snapshot delete should be clean: mismatches={:?}, leaks={:?}",
            report.mismatches,
            report.leaks
        );
    }

    #[test]
    fn is_clean_and_total_errors() {
        let report = IntegrityReport {
            stats: ClusterStats::default(),
            mismatches: vec![],
            leaks: vec![],
            reference_map: HashMap::new(),
        };
        assert!(report.is_clean());
        assert_eq!(report.total_errors(), 0);

        let report2 = IntegrityReport {
            stats: ClusterStats::default(),
            mismatches: vec![RefcountMismatch {
                cluster_index: 5,
                expected: 2,
                stored: 1,
            }],
            leaks: vec![LeakedCluster {
                cluster_index: 10,
                stored_refcount: 1,
            }],
            reference_map: HashMap::new(),
        };
        assert!(!report2.is_clean());
        assert_eq!(report2.total_errors(), 2);
    }

    #[test]
    fn reference_map_counts_metadata_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        drop(image);

        let image = Qcow2Image::open(&path).unwrap();
        let (refs, _) = build_reference_map(image.backend(), image.header()).unwrap();

        // Cluster 0 (header) should have refcount 1
        assert_eq!(refs.get(&0).copied().unwrap_or(0), 1, "header cluster");
        // L1 table cluster should be counted
        let l1_cluster = image.header().l1_table_offset.0 / image.cluster_size();
        assert!(refs.get(&l1_cluster).copied().unwrap_or(0) >= 1, "L1 cluster");
        // Refcount table cluster should be counted
        let rt_cluster = image.header().refcount_table_offset.0 / image.cluster_size();
        assert!(refs.get(&rt_cluster).copied().unwrap_or(0) >= 1, "RT cluster");
    }

    #[test]
    fn compressed_image_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let raw_path = dir.path().join("input.raw");
        let qcow2_path = dir.path().join("output.qcow2");

        // Create a small raw file with compressible data
        let mut raw_data = vec![0u8; 2 * 1024 * 1024];
        for (i, byte) in raw_data.iter_mut().enumerate() {
            *byte = (i % 4) as u8;
        }
        std::fs::write(&raw_path, &raw_data).unwrap();

        crate::engine::converter::convert_from_raw(&raw_path, &qcow2_path, true).unwrap();

        let image = Qcow2Image::open(&qcow2_path).unwrap();
        let report = check_integrity(image.backend(), image.header()).unwrap();
        assert!(
            report.is_clean(),
            "compressed image should be clean: mismatches={:?}, leaks={:?}",
            report.mismatches,
            report.leaks
        );
        assert!(report.stats.compressed_clusters > 0, "should have compressed clusters");
    }

    // ---- Repair tests ----

    /// Helper: corrupt a refcount by writing directly to the refcount block on disk.
    fn corrupt_refcount(path: &std::path::Path, cluster_index: u64, new_value: u16) {
        use crate::io::sync_backend::SyncFileBackend;
        let image = Qcow2Image::open(path).unwrap();
        let header = image.header().clone();
        drop(image);
        let backend = SyncFileBackend::open_rw(path).unwrap();

        // Read refcount table to find the refcount block
        let entries_per_block = header.refcounts_per_block();
        let rt_idx = cluster_index / entries_per_block;
        let block_idx = cluster_index % entries_per_block;

        let mut rt_entry_buf = [0u8; 8];
        let rt_entry_offset =
            header.refcount_table_offset.0 + rt_idx * 8;
        backend.read_exact_at(&mut rt_entry_buf, rt_entry_offset).unwrap();
        let block_offset = u64::from_be_bytes(rt_entry_buf);

        // Write the new refcount value at the right position in the block
        // refcount_order=4 means 16-bit refcounts, 2 bytes each
        let byte_offset = block_offset + block_idx * 2;
        let mut val_buf = [0u8; 2];
        BigEndian::write_u16(&mut val_buf, new_value);
        backend.write_all_at(&val_buf, byte_offset).unwrap();
        backend.flush().unwrap();
    }

    #[test]
    fn repair_fixes_leaked_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.flush().unwrap();

        // Find a cluster that's beyond the used area and set its refcount to 1
        let cluster_size = image.cluster_size();
        let file_size = image.backend().file_size().unwrap();
        let leak_cluster = file_size / cluster_size; // one past the last used
        drop(image);

        // Grow the file to make room for the "leaked" cluster
        {
            use crate::io::sync_backend::SyncFileBackend;
            let backend = SyncFileBackend::open_rw(&path).unwrap();
            backend.set_len(file_size + cluster_size).unwrap();
        }
        corrupt_refcount(&path, leak_cluster, 1);

        // Verify the corruption is detected
        let mut image =
            Qcow2Image::open_rw(&path).unwrap();
        let report_before = image.check_integrity().unwrap();
        assert!(
            !report_before.is_clean(),
            "should detect leak"
        );
        assert_eq!(report_before.leaks.len(), 1);

        // Repair
        let _ = image
            .check_and_repair(Some(RepairMode::LeaksOnly))
            .unwrap();

        // Verify clean after repair
        let report_after = image.check_integrity().unwrap();
        assert!(
            report_after.is_clean(),
            "should be clean after repair: mismatches={:?}, leaks={:?}",
            report_after.mismatches,
            report_after.leaks
        );
    }

    #[test]
    fn repair_full_fixes_mismatches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.flush().unwrap();
        drop(image);

        // Find the data cluster and corrupt its refcount
        let image = Qcow2Image::open(&path).unwrap();
        let (ref_map, _) = build_reference_map(image.backend(), image.header()).unwrap();
        // Find a data cluster (refcount should be 1, we'll set to 3)
        let data_cluster = ref_map
            .iter()
            .filter(|(_, &rc)| rc == 1)
            .map(|(&idx, _)| idx)
            .max() // pick the highest = most likely data cluster
            .unwrap();
        drop(image);

        corrupt_refcount(&path, data_cluster, 3);

        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let report_before = image.check_integrity().unwrap();
        assert!(!report_before.is_clean(), "should detect mismatch");
        assert!(!report_before.mismatches.is_empty());

        // LeaksOnly should NOT fix mismatches
        let report = image.check_and_repair(Some(RepairMode::LeaksOnly)).unwrap();
        assert!(!report.mismatches.is_empty());
        let still_bad = image.check_integrity().unwrap();
        assert!(!still_bad.is_clean(), "LeaksOnly should not fix mismatches");

        // Full repair SHOULD fix mismatches
        let _ = image.check_and_repair(Some(RepairMode::Full)).unwrap();
        let report_after = image.check_integrity().unwrap();
        assert!(
            report_after.is_clean(),
            "should be clean after full repair: mismatches={:?}, leaks={:?}",
            report_after.mismatches,
            report_after.leaks
        );
    }

    #[test]
    fn repair_preserves_snapshot_refcounts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        image.flush().unwrap();
        drop(image);

        // The image with snapshot is already clean; corrupt one refcount
        // Find a shared cluster (expected rc=2 from snapshot)
        let image = Qcow2Image::open(&path).unwrap();
        let (ref_map, _) = build_reference_map(image.backend(), image.header()).unwrap();
        let shared_cluster = ref_map
            .iter()
            .filter(|(_, &rc)| rc == 2)
            .map(|(&idx, _)| idx)
            .next()
            .unwrap();
        drop(image);

        // Set refcount to 1 (wrong, should be 2)
        corrupt_refcount(&path, shared_cluster, 1);

        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let report = image.check_integrity().unwrap();
        assert!(!report.is_clean());

        let _ = image.check_and_repair(Some(RepairMode::Full)).unwrap();

        let report_after = image.check_integrity().unwrap();
        assert!(
            report_after.is_clean(),
            "should be clean after repairing snapshot: mismatches={:?}, leaks={:?}",
            report_after.mismatches,
            report_after.leaks
        );
    }

    #[test]
    fn repair_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.flush().unwrap();
        drop(image);

        // Corrupt a refcount
        let image = Qcow2Image::open(&path).unwrap();
        let (ref_map, _) = build_reference_map(image.backend(), image.header()).unwrap();
        let cluster = ref_map.iter().map(|(&idx, _)| idx).max().unwrap();
        drop(image);
        corrupt_refcount(&path, cluster, 5);

        // First repair
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let _ = image.check_and_repair(Some(RepairMode::Full)).unwrap();
        let report1 = image.check_integrity().unwrap();
        assert!(report1.is_clean());

        // Second repair should be a no-op
        let report2 = image.check_and_repair(Some(RepairMode::Full)).unwrap();
        assert!(report2.is_clean(), "second repair should find clean image");
    }

    #[test]
    fn repair_fixes_copied_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 2 * 1024 * 1024,
                cluster_bits: None,
            },
        )
        .unwrap();
        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.snapshot_create("snap1").unwrap();
        // COW write — now cluster refcount=1, COPIED=true
        image.write_at(&[0xBB; 4096], 0).unwrap();
        image.flush().unwrap();
        drop(image);

        // Corrupt: set the new data cluster's refcount to 2 (wrong, should be 1)
        let image = Qcow2Image::open(&path).unwrap();
        let header = image.header().clone();
        // Read active L1 → L2 → find the data cluster
        let mut l1_buf = [0u8; 8];
        image.backend().read_exact_at(&mut l1_buf, header.l1_table_offset.0).unwrap();
        let l1_raw = u64::from_be_bytes(l1_buf);
        let l1_entry = L1Entry::from_raw(l1_raw);
        let l2_offset = l1_entry.l2_table_offset().unwrap();
        let mut l2_buf = vec![0u8; header.cluster_size() as usize];
        image.backend().read_exact_at(&mut l2_buf, l2_offset.0).unwrap();
        let l2_table = L2Table::read_from(&l2_buf, header.cluster_bits).unwrap();
        let entry = l2_table.get(crate::format::types::L2Index(0)).unwrap();
        let data_offset = match entry {
            L2Entry::Standard { host_offset, .. } => host_offset.0,
            _ => panic!("expected Standard entry"),
        };
        let data_cluster = data_offset / header.cluster_size();
        drop(image);

        corrupt_refcount(&path, data_cluster, 2);

        // Repair
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let _ = image.check_and_repair(Some(RepairMode::Full)).unwrap();

        // Verify: the data cluster should now have refcount=1 and COPIED=true
        let report = image.check_integrity().unwrap();
        assert!(report.is_clean());

        // Read the L2 entry and check COPIED flag
        let mut l2_buf2 = vec![0u8; image.cluster_size() as usize];
        image.backend().read_exact_at(&mut l2_buf2, l2_offset.0).unwrap();
        let l2_table2 = L2Table::read_from(&l2_buf2, image.header().cluster_bits).unwrap();
        let entry2 = l2_table2.get(crate::format::types::L2Index(0)).unwrap();
        match entry2 {
            L2Entry::Standard { copied, .. } => {
                assert!(copied, "COPIED should be true after repair (refcount=1)");
            }
            _ => panic!("expected Standard entry after repair"),
        }
    }
}
