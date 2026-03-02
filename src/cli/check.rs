//! `check` subcommand: verify image consistency.
//!
//! Walks the L1/L2 tables and refcount structures to identify potential
//! issues such as leaked clusters (non-zero refcount but unreferenced)
//! or clusters referenced more times than their refcount indicates.

use std::collections::HashMap;
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;
use qcow2_lib::format::constants::*;
use qcow2_lib::format::l1::L1Entry;
use qcow2_lib::format::l2::L2Entry;
use qcow2_lib::format::refcount::{RefcountBlock, RefcountTableEntry};

/// Run the check subcommand.
pub fn run(path: &Path) -> Result<()> {
    let image = Qcow2Image::open(path)?;
    let header = image.header();
    let backend = image.backend();
    let cluster_size = image.cluster_size() as usize;

    println!("Checking: {}", path.display());

    // Step 1: Build a reference count map by walking L1/L2 tables
    let mut reference_counts: HashMap<u64, u64> = HashMap::new();
    let mut total_data_clusters = 0u64;
    let mut total_compressed_clusters = 0u64;
    let mut total_zero_clusters = 0u64;
    let mut total_unallocated_clusters = 0u64;

    // Count the header cluster
    let header_cluster = 0u64;
    *reference_counts.entry(header_cluster).or_insert(0) += 1;

    // Count L1 table clusters
    let l1_cluster = header.l1_table_offset.0 / cluster_size as u64;
    let l1_size = header.l1_table_entries as usize * L1_ENTRY_SIZE;
    let l1_clusters = (l1_size + cluster_size - 1) / cluster_size;
    for c in 0..l1_clusters as u64 {
        *reference_counts.entry(l1_cluster + c).or_insert(0) += 1;
    }

    // Count refcount table clusters
    let rt_cluster = header.refcount_table_offset.0 / cluster_size as u64;
    for c in 0..header.refcount_table_clusters as u64 {
        *reference_counts.entry(rt_cluster + c).or_insert(0) += 1;
    }

    // Read L1 table
    let mut l1_buf = vec![0u8; l1_size];
    backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;

    // Walk L1 entries
    for l1_idx in 0..header.l1_table_entries {
        let offset = l1_idx as usize * L1_ENTRY_SIZE;
        let raw = BigEndian::read_u64(&l1_buf[offset..]);
        let l1_entry = L1Entry::from_raw(raw);

        let l2_offset = match l1_entry.l2_table_offset() {
            Some(offset) => offset,
            None => continue,
        };

        // Count L2 table cluster
        let l2_cluster = l2_offset.0 / cluster_size as u64;
        *reference_counts.entry(l2_cluster).or_insert(0) += 1;

        // Read and walk L2 table
        let mut l2_buf = vec![0u8; cluster_size];
        backend.read_exact_at(&mut l2_buf, l2_offset.0)?;
        let l2_table =
            qcow2_lib::format::l2::L2Table::read_from(&l2_buf, header.cluster_bits)?;

        let entries_per_table = cluster_size / L2_ENTRY_SIZE;
        for l2_idx in 0..entries_per_table {
            let entry = l2_table.get(qcow2_lib::format::types::L2Index(l2_idx as u32))?;

            match entry {
                L2Entry::Unallocated => {
                    total_unallocated_clusters += 1;
                }
                L2Entry::Zero { preallocated_offset } => {
                    total_zero_clusters += 1;
                    if let Some(offset) = preallocated_offset {
                        let cluster = offset.0 / cluster_size as u64;
                        *reference_counts.entry(cluster).or_insert(0) += 1;
                    }
                }
                L2Entry::Standard { host_offset, .. } => {
                    total_data_clusters += 1;
                    let cluster = host_offset.0 / cluster_size as u64;
                    *reference_counts.entry(cluster).or_insert(0) += 1;
                }
                L2Entry::Compressed(desc) => {
                    total_compressed_clusters += 1;
                    // Compressed clusters can span partial clusters
                    let start_cluster = desc.host_offset / cluster_size as u64;
                    let end_byte = desc.host_offset + desc.compressed_size;
                    let end_cluster = (end_byte + cluster_size as u64 - 1) / cluster_size as u64;
                    for c in start_cluster..end_cluster {
                        *reference_counts.entry(c).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // Step 2: Read actual refcounts and compare
    let rt_size = header.refcount_table_clusters as usize * cluster_size;
    let mut errors = 0u64;
    let mut leaked = 0u64;

    if rt_size > 0 {
        let mut rt_buf = vec![0u8; rt_size];
        backend.read_exact_at(&mut rt_buf, header.refcount_table_offset.0)?;

        let entry_count = rt_size / REFCOUNT_TABLE_ENTRY_SIZE;
        for rt_idx in 0..entry_count {
            let rt_offset = rt_idx * REFCOUNT_TABLE_ENTRY_SIZE;
            let raw = BigEndian::read_u64(&rt_buf[rt_offset..]);
            let rt_entry = RefcountTableEntry::from_raw(raw);

            let block_offset = match rt_entry.block_offset() {
                Some(o) => o,
                None => continue,
            };

            // Count refcount block cluster itself
            let block_cluster = block_offset.0 / cluster_size as u64;
            *reference_counts.entry(block_cluster).or_insert(0) += 1;

            // Read the refcount block
            let mut block_buf = vec![0u8; cluster_size];
            backend.read_exact_at(&mut block_buf, block_offset.0)?;
            let block = RefcountBlock::read_from(&block_buf, header.refcount_order)?;

            let entries_per_block = header.refcounts_per_block() as usize;
            let base_cluster = rt_idx * entries_per_block;

            for bi in 0..entries_per_block {
                let cluster_idx = (base_cluster + bi) as u64;
                let stored_refcount = block.get(bi as u32)?;
                let expected_refs = reference_counts.get(&cluster_idx).copied().unwrap_or(0);

                if stored_refcount == 0 && expected_refs > 0 {
                    errors += 1;
                    if errors <= 10 {
                        eprintln!("  ERROR: cluster {} has refcount 0 but {} references",
                            cluster_idx, expected_refs);
                    }
                } else if stored_refcount > 0 && expected_refs == 0 {
                    leaked += 1;
                }
            }
        }
    }

    // Summary
    println!();
    println!("Cluster statistics:");
    println!("  Allocated (standard):   {total_data_clusters}");
    println!("  Allocated (compressed): {total_compressed_clusters}");
    println!("  Zero:                   {total_zero_clusters}");
    println!("  Unallocated:            {total_unallocated_clusters}");
    println!();

    if errors == 0 && leaked == 0 {
        println!("No errors found.");
    } else {
        if errors > 0 {
            println!("Errors: {errors} clusters with refcount mismatches");
        }
        if leaked > 0 {
            println!("Leaked: {leaked} clusters (non-zero refcount, no references)");
        }
    }

    Ok(())
}
