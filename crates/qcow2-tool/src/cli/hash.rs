//! `hash` subcommand: manage BLAKE3 per-hash-chunk hashes.

use std::path::Path;

use qcow2::engine::image::Qcow2Image;
use qcow2::error::Result;

/// Initialize the BLAKE3 hash extension.
pub fn run_init(path: &Path, hash_size: Option<u8>, chunk_size: Option<u64>) -> Result<()> {
    // Convert chunk_size (bytes, power-of-2) to hash_chunk_bits
    let hash_chunk_bits = match chunk_size {
        Some(cs) => {
            if !cs.is_power_of_two() || !(4096..=(1 << 24)).contains(&cs) {
                return Err(qcow2::error::FormatError::InvalidHashChunkBits {
                    bits: 0,
                    min: 12,
                    max: 24,
                }
                .into());
            }
            Some(cs.trailing_zeros() as u8)
        }
        None => None,
    };

    let mut image = Qcow2Image::open_rw(path)?;
    image.hash_init(hash_size, hash_chunk_bits)?;
    image.flush()?;
    let hs = hash_size.unwrap_or(32);
    let chunk_sz = chunk_size.unwrap_or(65536);
    println!(
        "BLAKE3 hash extension initialized (hash_size: {} bytes, hash_chunk_size: {}).",
        hs,
        format_size(chunk_sz),
    );
    Ok(())
}

/// Rehash all allocated hash chunks.
pub fn run_rehash(path: &Path) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    let count = image.hash_rehash()?;
    image.flush()?;
    println!("Rehashed {} hash chunk(s).", count);
    Ok(())
}

/// Verify all stored hashes.
pub fn run_verify(path: &Path) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;

    let info = image.hash_info().ok_or(
        qcow2::error::Error::HashNotInitialized
    )?;

    if !info.consistent {
        println!("Warning: autoclear bit not set — hashes may be stale.");
        println!("Run 'hash rehash' to recompute hashes.\n");
    }

    println!("Verifying hash chunk hashes...");
    let mismatches = image.hash_verify()?;

    if mismatches.is_empty() {
        println!("All hashes verified OK.");
    } else {
        for m in &mismatches {
            println!(
                "  Hash chunk {} (0x{:012x}): MISMATCH",
                m.hash_chunk_index, m.guest_offset,
            );
            println!("    Expected: {}", hex_string(&m.expected));
            println!("    Actual:   {}", hex_string(&m.actual));
        }
        let hash_chunk_size = 1u64 << info.hash_chunk_bits;
        let total_chunks = (image.virtual_size() + hash_chunk_size - 1) / hash_chunk_size;
        println!(
            "\n{} of {} hash chunk(s) have hash mismatches.",
            mismatches.len(),
            total_chunks,
        );
    }

    Ok(())
}

/// Show hash extension info.
pub fn run_info(path: &Path) -> Result<()> {
    let image = Qcow2Image::open(path)?;

    match image.hash_info() {
        Some(info) => {
            println!("BLAKE3 hash extension:");
            println!("  Hash size:       {} bytes", info.hash_size);
            println!("  Hash chunk size: {}", format_size(1u64 << info.hash_chunk_bits));
            println!("  Table entries:   {}", info.hash_table_entries);
            println!(
                "  Consistent:      {}",
                if info.consistent { "yes" } else { "no (rehash needed)" },
            );
        }
        None => {
            println!("No BLAKE3 hash extension found.");
        }
    }

    Ok(())
}

/// Export hashes in raw or JSON format.
pub fn run_export(path: &Path, range: Option<(u64, u64)>, json: bool) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;

    let info = image.hash_info().ok_or(
        qcow2::error::Error::HashNotInitialized
    )?;

    let entries = image.hash_export(range)?;

    if json {
        let hash_chunk_size = 1u64 << info.hash_chunk_bits;
        println!("{{");
        println!("  \"hash_size\": {},", info.hash_size);
        println!("  \"hash_chunk_size\": {},", hash_chunk_size);
        println!("  \"algorithm\": \"blake3\",");
        println!("  \"entries\": [");
        for (i, e) in entries.iter().enumerate() {
            let comma = if i + 1 < entries.len() { "," } else { "" };
            println!(
                "    {{\"offset\": {}, \"hash\": \"{}\"}}{comma}",
                e.guest_offset,
                hex_string(&e.hash),
            );
        }
        println!("  ]");
        println!("}}");
    } else {
        for e in &entries {
            println!("0x{:012x}: {}", e.guest_offset, hex_string(&e.hash));
        }
        if entries.is_empty() {
            println!("(no hashes stored)");
        }
    }

    Ok(())
}

/// Remove the hash extension.
pub fn run_remove(path: &Path) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.hash_remove()?;
    image.flush()?;
    println!("BLAKE3 hash extension removed.");
    Ok(())
}

/// Format bytes as a hex string.
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Format a byte size as human-readable (e.g. "64 KiB", "4 MiB").
fn format_size(bytes: u64) -> String {
    if bytes >= (1 << 20) && bytes % (1 << 20) == 0 {
        format!("{} MiB", bytes >> 20)
    } else if bytes >= 1024 && bytes % 1024 == 0 {
        format!("{} KiB", bytes >> 10)
    } else {
        format!("{} bytes", bytes)
    }
}
