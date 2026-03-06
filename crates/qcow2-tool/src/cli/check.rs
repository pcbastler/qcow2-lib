//! `check` subcommand: verify image consistency and optionally repair.
//!
//! Delegates to the library's [`integrity`] module for the actual check
//! and repair logic. This CLI layer only handles argument parsing and output.

use std::path::Path;

use qcow2::engine::image::Qcow2Image;
use qcow2::engine::integrity::RepairMode;
use qcow2::error::Result;

/// Run the check subcommand.
pub fn run(path: &Path, repair: bool) -> Result<()> {
    println!("Checking: {}", path.display());

    let report = if repair {
        let mut image = Qcow2Image::open_rw(path)?;
        let report = image.check_and_repair(Some(RepairMode::Full))?;

        // Re-check after repair to confirm clean state
        let post_report = image.check_integrity()?;

        if !report.is_clean() {
            println!();
            println!("Repair summary:");
            println!(
                "  Mismatches fixed: {}",
                report.mismatches.len()
            );
            println!("  Leaks fixed:      {}", report.leaks.len());

            if post_report.is_clean() {
                println!("  Status:           all issues repaired");
            } else {
                println!(
                    "  Status:           {} issues remain after repair",
                    post_report.total_errors()
                );
            }
        }

        report
    } else {
        let image = Qcow2Image::open(path)?;
        image.check_integrity()?
    };

    let stats = &report.stats;
    println!();
    println!("Cluster statistics:");
    println!("  Allocated (standard):   {}", stats.data_clusters);
    println!("  Allocated (compressed): {}", stats.compressed_clusters);
    println!("  Zero:                   {}", stats.zero_clusters);
    println!("  Unallocated:            {}", stats.unallocated_entries);
    println!();

    if report.is_clean() {
        println!("No errors found.");
    } else {
        if !report.mismatches.is_empty() {
            println!(
                "Errors: {} clusters with refcount mismatches",
                report.mismatches.len()
            );
            for m in report.mismatches.iter().take(10) {
                eprintln!(
                    "  cluster {}: expected refcount {}, stored {}",
                    m.cluster_index, m.expected, m.stored
                );
            }
            if report.mismatches.len() > 10 {
                eprintln!("  ... and {} more", report.mismatches.len() - 10);
            }
        }
        if !report.leaks.is_empty() {
            println!(
                "Leaked: {} clusters (non-zero refcount, no references)",
                report.leaks.len()
            );
            for l in report.leaks.iter().take(10) {
                eprintln!(
                    "  cluster {}: stored refcount {}",
                    l.cluster_index, l.stored_refcount
                );
            }
            if report.leaks.len() > 10 {
                eprintln!("  ... and {} more", report.leaks.len() - 10);
            }
        }

        if !repair {
            println!();
            println!("Hint: use --repair to fix these issues.");
        }
    }

    Ok(())
}
