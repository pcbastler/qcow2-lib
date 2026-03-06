use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::config::CorruptionType;

/// Apply targeted corruption to a QCOW2 image file.
/// Returns a description of what was corrupted.
pub fn corrupt(qcow2_path: &Path, corruption: CorruptionType) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(qcow2_path)
        .map_err(|e| format!("open {}: {e}", qcow2_path.display()))?;

    let file_size = file
        .metadata()
        .map_err(|e| format!("metadata: {e}"))?
        .len();

    // Read header to determine layout
    let header = read_header(&mut file)?;

    match corruption {
        CorruptionType::HeaderZeroed => {
            zero_range(&mut file, 0, header.cluster_size.min(512))?;
            Ok(format!("zeroed header (first {} bytes)", header.cluster_size.min(512)))
        }
        CorruptionType::L1Corrupted => {
            let l1_offset = header.l1_table_offset;
            let l1_size = header.l1_size as u64 * 8;
            garbage_range(&mut file, l1_offset, l1_size)?;
            Ok(format!("filled L1 table at offset {l1_offset} ({l1_size} bytes) with garbage"))
        }
        CorruptionType::L2Corrupted => {
            // Read first L1 entry to find an L2 table
            file.seek(SeekFrom::Start(header.l1_table_offset))
                .map_err(|e| format!("seek: {e}"))?;
            let mut buf = [0u8; 8];
            file.read_exact(&mut buf).map_err(|e| format!("read L1: {e}"))?;
            let l2_offset = u64::from_be_bytes(buf) & 0x00ff_ffff_ffff_fe00;
            if l2_offset == 0 || l2_offset >= file_size {
                return Err("no valid L2 table found in first L1 entry".into());
            }
            garbage_range(&mut file, l2_offset, header.cluster_size)?;
            Ok(format!("filled L2 table at offset {l2_offset} with garbage"))
        }
        CorruptionType::RefcountCorrupted => {
            let rct_offset = header.refcount_table_offset;
            let rct_size = header.refcount_table_clusters as u64 * header.cluster_size;
            garbage_range(&mut file, rct_offset, rct_size)?;
            Ok(format!("filled refcount table at offset {rct_offset} ({rct_size} bytes) with garbage"))
        }
        CorruptionType::HeaderAndL1 => {
            zero_range(&mut file, 0, header.cluster_size.min(512))?;
            let l1_offset = header.l1_table_offset;
            let l1_size = header.l1_size as u64 * 8;
            garbage_range(&mut file, l1_offset, l1_size)?;
            Ok(format!("zeroed header + corrupted L1 at offset {l1_offset}"))
        }
        CorruptionType::AllMetadata => {
            // Zero header
            zero_range(&mut file, 0, header.cluster_size.min(512))?;
            // Garbage L1
            let l1_size = header.l1_size as u64 * 8;
            garbage_range(&mut file, header.l1_table_offset, l1_size)?;
            // Garbage refcount table
            let rct_size = header.refcount_table_clusters as u64 * header.cluster_size;
            garbage_range(&mut file, header.refcount_table_offset, rct_size)?;
            Ok("corrupted all metadata (header + L1 + refcount)".into())
        }
    }
}

struct QcowHeader {
    cluster_size: u64,
    l1_table_offset: u64,
    l1_size: u32,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
}

fn read_header(file: &mut std::fs::File) -> Result<QcowHeader, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| format!("seek: {e}"))?;
    let mut buf = [0u8; 104];
    file.read_exact(&mut buf).map_err(|e| format!("read header: {e}"))?;

    // Verify magic
    if &buf[0..4] != b"QFI\xfb" {
        return Err("not a QCOW2 file (bad magic)".into());
    }

    let cluster_bits = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let cluster_size = 1u64 << cluster_bits;
    let l1_size = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
    let l1_table_offset = u64::from_be_bytes([buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47]]);
    let refcount_table_offset = u64::from_be_bytes([buf[48], buf[49], buf[50], buf[51], buf[52], buf[53], buf[54], buf[55]]);
    let refcount_table_clusters = u32::from_be_bytes([buf[56], buf[57], buf[58], buf[59]]);

    Ok(QcowHeader {
        cluster_size,
        l1_table_offset,
        l1_size,
        refcount_table_offset,
        refcount_table_clusters,
    })
}

fn zero_range(file: &mut std::fs::File, offset: u64, size: u64) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek: {e}"))?;
    let zeros = vec![0u8; size as usize];
    file.write_all(&zeros).map_err(|e| format!("write: {e}"))?;
    file.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

fn garbage_range(file: &mut std::fs::File, offset: u64, size: u64) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek: {e}"))?;
    let mut garbage = vec![0u8; size as usize];
    // Deterministic garbage (not zero, not valid metadata)
    let mut state: u32 = (offset as u32).wrapping_mul(2654435761);
    for byte in garbage.iter_mut() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = ((state >> 16) as u8) | 0x80; // ensure high bit set
    }
    file.write_all(&garbage).map_err(|e| format!("write: {e}"))?;
    file.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}
