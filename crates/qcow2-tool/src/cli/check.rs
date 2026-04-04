//! `check` subcommand: verify image consistency and optionally repair.
//!
//! Delegates to the library's [`integrity`] module for the actual check
//! and repair logic. This CLI layer only handles argument parsing and output.

use std::path::Path;

use qcow2::engine::image::Qcow2Image;
use qcow2::engine::integrity::{IntegrityReport, RepairMode};
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
            print_repair_summary(&report, &post_report);
        }

        report
    } else {
        let mut image = Qcow2Image::open(path)?;
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
        print_issues(
            "Errors: clusters with refcount mismatches",
            &report.mismatches,
            |m| format!("cluster {}: expected refcount {}, stored {}", m.cluster_index, m.expected, m.stored),
        );
        print_issues(
            "Leaked: clusters (non-zero refcount, no references)",
            &report.leaks,
            |l| format!("cluster {}: stored refcount {}", l.cluster_index, l.stored_refcount),
        );
        print_issues(
            "Overlaps: metadata regions overlap",
            &report.overlaps,
            |o| format!("cluster {}: {} overlaps {}", o.cluster_index, o.region_a, o.region_b),
        );

        if !repair {
            println!();
            println!("Hint: use --repair to fix these issues.");
        }
    }

    Ok(())
}

fn print_repair_summary(report: &IntegrityReport, post_report: &IntegrityReport) {
    println!();
    println!("Repair summary:");
    println!("  Mismatches fixed: {}", report.mismatches.len());
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

fn print_issues<T>(title: &str, items: &[T], fmt: impl Fn(&T) -> String) {
    if items.is_empty() {
        return;
    }
    println!("{}: {}", title, items.len());
    for item in items.iter().take(10) {
        eprintln!("  {}", fmt(item));
    }
    if items.len() > 10 {
        eprintln!("  ... and {} more", items.len() - 10);
    }
}
