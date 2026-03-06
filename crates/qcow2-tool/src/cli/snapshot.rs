//! `snapshot` subcommand: manage QCOW2 image snapshots.

use std::path::Path;

use qcow2::engine::image::Qcow2Image;
use qcow2::error::Result;

/// List all snapshots in the image.
pub fn run_list(path: &Path) -> Result<()> {
    let image = Qcow2Image::open(path)?;
    let snaps = image.snapshot_list()?;

    if snaps.is_empty() {
        println!("No snapshots.");
        return Ok(());
    }

    println!("{:<6} {:<24} {:>14}  {}", "ID", "Name", "Virtual Size", "L1 Entries");
    println!("{}", "-".repeat(60));
    for s in &snaps {
        let vsize = match s.virtual_size {
            Some(v) => format_size(v),
            None => "—".to_string(),
        };
        println!("{:<6} {:<24} {:>14}  {}", s.id, s.name, vsize, s.l1_table_entries);
    }
    println!("\n{} snapshot(s) total.", snaps.len());

    Ok(())
}

/// Create a new snapshot.
pub fn run_create(path: &Path, name: &str) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.snapshot_create(name)?;
    image.flush()?;
    println!("Snapshot '{}' created.", name);
    Ok(())
}

/// Delete an existing snapshot.
pub fn run_delete(path: &Path, name: &str) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.snapshot_delete(name)?;
    image.flush()?;
    println!("Snapshot '{}' deleted.", name);
    Ok(())
}

/// Apply (revert to) a snapshot.
pub fn run_apply(path: &Path, name: &str) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;
    image.snapshot_apply(name)?;
    image.flush()?;
    println!("Snapshot '{}' applied.", name);
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
