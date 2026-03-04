//! `dump` subcommand: display metadata tables in human-readable format.

use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;
use qcow2_lib::format::constants::*;
use qcow2_lib::format::l1::L1Entry;
use qcow2_lib::format::l2::L2Entry;
use qcow2_lib::format::refcount::RefcountTableEntry;

/// Run the dump subcommand.
pub fn run(path: &Path, target: &super::DumpTarget) -> Result<()> {
    let image = Qcow2Image::open(path)?;

    match target {
        super::DumpTarget::L1 => dump_l1(&image),
        super::DumpTarget::L2 => dump_l2(&image),
        super::DumpTarget::Refcount => dump_refcount(&image),
    }
}

fn dump_l1(image: &Qcow2Image) -> Result<()> {
    let header = image.header();
    let backend = image.backend();

    let l1_size = header.l1_table_entries as usize * L1_ENTRY_SIZE;
    let mut l1_buf = vec![0u8; l1_size];
    backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;

    println!("L1 Table ({} entries at offset 0x{:x}):",
        header.l1_table_entries, header.l1_table_offset.0);
    println!("{:>6}  {:>18}  {:>8}  {:>8}", "Index", "Raw", "L2 Offset", "Copied");
    println!("{:-<6}  {:-<18}  {:-<8}  {:-<8}", "", "", "", "");

    for i in 0..header.l1_table_entries {
        let offset = i as usize * L1_ENTRY_SIZE;
        let raw = BigEndian::read_u64(&l1_buf[offset..]);
        let entry = L1Entry::from_raw(raw);

        if entry.is_unallocated() {
            continue; // Skip empty entries for readability
        }

        let l2_offset = entry
            .l2_table_offset()
            .map(|o| format!("0x{:x}", o.0))
            .unwrap_or_else(|| "-".to_string());
        let copied = if entry.is_copied() { "yes" } else { "no" };

        println!("{:>6}  0x{:016x}  {:>8}  {:>8}", i, raw, l2_offset, copied);
    }

    Ok(())
}

fn dump_l2(image: &Qcow2Image) -> Result<()> {
    let header = image.header();
    let backend = image.backend();

    // Read first L1 entry to find the L2 table
    let mut l1_buf = vec![0u8; L1_ENTRY_SIZE];
    backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
    let l1_raw = BigEndian::read_u64(&l1_buf);
    let l1_entry = L1Entry::from_raw(l1_raw);

    let l2_offset = match l1_entry.l2_table_offset() {
        Some(offset) => offset,
        None => {
            println!("L1[0] is unallocated — no L2 table to dump.");
            return Ok(());
        }
    };

    let cluster_size = image.cluster_size() as usize;
    let mut l2_buf = vec![0u8; cluster_size];
    backend.read_exact_at(&mut l2_buf, l2_offset.0)?;

    let extended_l2 = header.has_extended_l2();
    let l2_table = qcow2_lib::format::l2::L2Table::read_from(&l2_buf, header.cluster_bits, extended_l2)?;
    let entries_per_table = cluster_size / header.l2_entry_size();

    println!("L2 Table (L1[0] -> offset 0x{:x}, {} entries):",
        l2_offset.0, entries_per_table);
    println!("{:>6}  {:>18}  {:>12}", "Index", "Type", "Details");
    println!("{:-<6}  {:-<18}  {:-<12}", "", "", "");

    for i in 0..entries_per_table {
        let entry = l2_table.get(qcow2_lib::format::types::L2Index(i as u32))?;

        match entry {
            L2Entry::Unallocated => continue,
            L2Entry::Zero { preallocated_offset, subclusters } => {
                let detail = preallocated_offset
                    .map(|o| format!("prealloc: 0x{:x}", o.0))
                    .unwrap_or_else(|| "-".to_string());
                let sc = subclusters.map(|b| format!(" sc=0x{:016x}", b.0)).unwrap_or_default();
                println!("{:>6}  {:>18}  {}{}", i, "zero", detail, sc);
            }
            L2Entry::Standard { host_offset, copied, subclusters } => {
                let flag = if copied { " (copied)" } else { "" };
                let sc = subclusters.map(|b| format!(" sc=0x{:016x}", b.0)).unwrap_or_default();
                println!("{:>6}  {:>18}  0x{:x}{}{}", i, "standard", host_offset.0, flag, sc);
            }
            L2Entry::Compressed(desc) => {
                println!("{:>6}  {:>18}  host=0x{:x} size={}", i, "compressed",
                    desc.host_offset, desc.compressed_size);
            }
        }
    }

    Ok(())
}

fn dump_refcount(image: &Qcow2Image) -> Result<()> {
    let header = image.header();
    let backend = image.backend();

    let rt_size = header.refcount_table_clusters as usize * image.cluster_size() as usize;
    if rt_size == 0 {
        println!("No refcount table present.");
        return Ok(());
    }

    let mut rt_buf = vec![0u8; rt_size];
    backend.read_exact_at(&mut rt_buf, header.refcount_table_offset.0)?;

    let entry_count = rt_size / REFCOUNT_TABLE_ENTRY_SIZE;
    println!("Refcount Table ({} entries at offset 0x{:x}):",
        entry_count, header.refcount_table_offset.0);
    println!("{:>6}  {:>18}", "Index", "Block Offset");
    println!("{:-<6}  {:-<18}", "", "");

    for i in 0..entry_count {
        let offset = i * REFCOUNT_TABLE_ENTRY_SIZE;
        let raw = BigEndian::read_u64(&rt_buf[offset..]);
        let entry = RefcountTableEntry::from_raw(raw);

        if let Some(block_offset) = entry.block_offset() {
            println!("{:>6}  0x{:016x}", i, block_offset.0);
        }
    }

    Ok(())
}
