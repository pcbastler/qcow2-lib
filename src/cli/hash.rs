//! `hash` subcommand: manage BLAKE3 per-cluster hashes.

use std::path::Path;

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;

/// Initialize the BLAKE3 hash extension.
pub fn run_init(path: &Path, hash_size: Option<u8>) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.hash_init(hash_size)?;
    image.flush()?;
    let hs = hash_size.unwrap_or(32);
    println!("BLAKE3 hash extension initialized (hash_size: {} bytes).", hs);
    Ok(())
}

/// Rehash all allocated clusters.
pub fn run_rehash(path: &Path) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    let count = image.hash_rehash()?;
    image.flush()?;
    println!("Rehashed {} cluster(s).", count);
    Ok(())
}

/// Verify all stored hashes.
pub fn run_verify(path: &Path) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;

    let info = image.hash_info().ok_or_else(|| {
        qcow2_lib::error::Error::HashNotInitialized
    })?;

    if !info.consistent {
        println!("Warning: autoclear bit not set — hashes may be stale.");
        println!("Run 'hash rehash' to recompute hashes.\n");
    }

    println!("Verifying cluster hashes...");
    let mismatches = image.hash_verify()?;

    if mismatches.is_empty() {
        println!("All hashes verified OK.");
    } else {
        for m in &mismatches {
            println!(
                "  Cluster {} (0x{:012x}): MISMATCH",
                m.cluster_index, m.guest_offset,
            );
            println!("    Expected: {}", hex_string(&m.expected));
            println!("    Actual:   {}", hex_string(&m.actual));
        }
        let cluster_size = image.cluster_size();
        let total_clusters = (image.virtual_size() + cluster_size - 1) / cluster_size;
        println!(
            "\n{} of {} cluster(s) have hash mismatches.",
            mismatches.len(),
            total_clusters,
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
            println!("  Hash size:     {} bytes", info.hash_size);
            println!("  Table entries: {}", info.hash_table_entries);
            println!(
                "  Consistent:    {}",
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

    let info = image.hash_info().ok_or_else(|| {
        qcow2_lib::error::Error::HashNotInitialized
    })?;

    let entries = image.hash_export(range)?;

    if json {
        println!("{{");
        println!("  \"hash_size\": {},", info.hash_size);
        println!("  \"cluster_size\": {},", image.cluster_size());
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
