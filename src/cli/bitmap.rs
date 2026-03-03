//! `bitmap` subcommand: manage QCOW2 persistent dirty bitmaps.

use std::path::Path;

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;

/// List all bitmaps in the image.
pub fn run_list(path: &Path) -> Result<()> {
    let image = Qcow2Image::open(path)?;
    let bitmaps = image.bitmap_list()?;

    if bitmaps.is_empty() {
        println!("No bitmaps.");
        return Ok(());
    }

    println!(
        "{:<24} {:>12} {:>6} {:>7} {:>8}  {}",
        "Name", "Granularity", "Type", "In-Use", "Auto", "Table Entries"
    );
    println!("{}", "-".repeat(75));
    for b in &bitmaps {
        let type_str = if b.bitmap_type == 1 { "dirty" } else { "unknown" };
        println!(
            "{:<24} {:>12} {:>6} {:>7} {:>8}  {}",
            b.name,
            format_size(b.granularity),
            type_str,
            if b.in_use { "yes" } else { "no" },
            if b.auto { "yes" } else { "no" },
            b.table_size,
        );
    }
    println!("\n{} bitmap(s) total.", bitmaps.len());

    Ok(())
}

/// Create a new bitmap.
pub fn run_create(path: &Path, name: &str, granularity_bits: Option<u8>, auto: bool) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.bitmap_create(name, granularity_bits, auto)?;
    image.flush()?;
    let gran = 1u64 << granularity_bits.unwrap_or(16);
    println!(
        "Bitmap '{}' created (granularity: {}{}).",
        name,
        format_size(gran),
        if auto { ", auto-tracking" } else { "" },
    );
    Ok(())
}

/// Delete an existing bitmap.
pub fn run_delete(path: &Path, name: &str) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.bitmap_delete(name)?;
    image.flush()?;
    println!("Bitmap '{}' deleted.", name);
    Ok(())
}

/// Dump dirty regions of a bitmap.
pub fn run_dump(path: &Path, name: &str) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    let bitmaps = image.bitmap_list()?;

    let info = bitmaps
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| qcow2_lib::error::Error::BitmapNotFound {
            name: name.to_string(),
        })?;

    let granularity = info.granularity;
    let virtual_size = image.virtual_size();

    println!(
        "Dirty regions in bitmap '{}' (granularity: {}):",
        name,
        format_size(granularity),
    );

    let mut region_start: Option<u64> = None;
    let mut region_count = 0u64;
    let mut dirty_bytes = 0u64;

    let mut offset = 0u64;
    while offset < virtual_size {
        let is_dirty = image.bitmap_get_dirty(name, offset)?;

        match (is_dirty, region_start) {
            (true, None) => {
                region_start = Some(offset);
            }
            (false, Some(start)) => {
                let end = offset;
                let size = end - start;
                println!(
                    "  0x{:012x} - 0x{:012x}  ({})",
                    start,
                    end - 1,
                    format_size(size),
                );
                dirty_bytes += size;
                region_count += 1;
                region_start = None;
            }
            _ => {}
        }

        offset += granularity;
    }

    // Close last region
    if let Some(start) = region_start {
        let end = virtual_size;
        let size = end - start;
        println!(
            "  0x{:012x} - 0x{:012x}  ({})",
            start,
            end - 1,
            format_size(size),
        );
        dirty_bytes += size;
        region_count += 1;
    }

    if region_count == 0 {
        println!("  (clean — no dirty regions)");
    } else {
        println!(
            "Total: {} dirty region(s), {} dirty",
            region_count,
            format_size(dirty_bytes),
        );
    }

    Ok(())
}

/// Format a byte size as a human-readable string.
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}
