//! qcow2-rescue: Recovery tool for corrupted QCOW2 images.
//!
//! Scans, analyzes, and reconstructs data from damaged QCOW2 files
//! that `qemu-img check -r all` cannot repair.

mod config;
mod error;
mod reconstruct;
mod report;
mod scan;
mod tree;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use config::{ConflictStrategy, OutputFormat, RescueConfig};
use error::{RescueError, Result};

#[derive(Parser)]
#[command(name = "qcow2-rescue", about = "Recovery tool for corrupted QCOW2 images")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a QCOW2 image without writing any output.
    ///
    /// Scans all clusters, classifies them, reconstructs metadata,
    /// and writes JSON reports to the output directory.
    Analyze {
        /// Path to the QCOW2 image file or directory containing a backing chain.
        path: PathBuf,

        /// Output directory for analysis reports.
        #[arg(short, long, default_value = "recovery")]
        output: PathBuf,

        /// Override cluster size in bytes (power of 2, e.g. 65536).
        /// Use when the header is corrupt and auto-detection fails.
        #[arg(long)]
        cluster_size: Option<u64>,
    },

    /// Recover data from a QCOW2 image.
    ///
    /// Runs the full pipeline: scan, reconstruct, extract, decrypt,
    /// decompress, and merge into a clean output image.
    Recover {
        /// Path to the QCOW2 image file or directory containing a backing chain.
        path: PathBuf,

        /// Output directory for recovered data.
        #[arg(short, long, default_value = "recovery")]
        output: PathBuf,

        /// Output format.
        #[arg(short, long, default_value = "raw")]
        format: OutputFormat,

        /// Which path/snapshot in the backing tree to recover.
        #[arg(long)]
        snapshot: Option<String>,

        /// File containing the password (for encrypted images).
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// How to resolve ambiguities.
        #[arg(long, default_value = "ask")]
        on_conflict: ConflictStrategy,

        /// Override cluster size in bytes.
        #[arg(long)]
        cluster_size: Option<u64>,

        /// Resume from a previous interrupted run.
        #[arg(long)]
        resume: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Analyze {
            path,
            output,
            cluster_size,
        } => run_analyze(path, output, cluster_size),
        Command::Recover {
            path,
            output,
            format,
            snapshot,
            password_file,
            on_conflict,
            cluster_size,
            resume,
        } => {
            let password = password_file.map(|p| {
                std::fs::read(&p)
                    .unwrap_or_else(|e| {
                        eprintln!("error: cannot read password file {}: {e}", p.display());
                        std::process::exit(1);
                    })
            });

            let config = RescueConfig {
                input: path,
                output,
                format: Some(format),
                path: snapshot,
                password,
                on_conflict,
                cluster_size_override: cluster_size,
                resume,
            };
            run_recover(config)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run_analyze(path: PathBuf, output: PathBuf, cluster_size: Option<u64>) -> Result<()> {
    if !path.exists() {
        return Err(RescueError::InputNotFound { path });
    }

    std::fs::create_dir_all(&output).map_err(|e| RescueError::OutputDirFailed {
        path: output.clone(),
        reason: e.to_string(),
    })?;

    // Phase 1: Cluster scan
    let file_size = std::fs::metadata(&path)?.len();
    let cluster_size = match cluster_size {
        Some(cs) => {
            println!("using user-specified cluster size: {} bytes", cs);
            cs
        }
        None => {
            println!("detecting cluster size from header...");
            scan::detect_cluster_size(&path)?
        }
    };

    println!(
        "scanning {} ({} bytes, {} clusters of {} bytes)",
        path.display(),
        file_size,
        file_size / cluster_size,
        cluster_size,
    );

    let cluster_map = scan::scan_file(&path, cluster_size)?;

    println!(
        "scan complete: {} headers, {} L1, {} L2, {} refcount, {} compressed, {} data, {} empty, {} unknown",
        cluster_map.summary.headers,
        cluster_map.summary.l1_tables,
        cluster_map.summary.l2_tables,
        cluster_map.summary.refcount_blocks,
        cluster_map.summary.compressed,
        cluster_map.summary.data,
        cluster_map.summary.empty,
        cluster_map.summary.unknown,
    );

    // Write cluster map report
    let report_path = output.join("cluster_map.json");
    let json = serde_json::to_string_pretty(&cluster_map)?;
    std::fs::write(&report_path, json)?;
    println!("wrote {}", report_path.display());

    // Phase 2: Metadata reconstruction
    println!("reconstructing metadata...");
    let tables_report = reconstruct::reconstruct(&path, &cluster_map)?;

    println!(
        "reconstruction complete: {} L1 entries, {} L2 verified, {} L2 suspicious, {} mappings ({} from L2), {} orphan data clusters",
        tables_report.l1_entries,
        tables_report.l2_tables_verified,
        tables_report.l2_tables_suspicious,
        tables_report.mappings_total,
        tables_report.mappings_from_l2,
        tables_report.orphan_data_clusters,
    );

    let tables_path = output.join("reconstructed_tables.json");
    let json = serde_json::to_string_pretty(&tables_report)?;
    std::fs::write(&tables_path, json)?;
    println!("wrote {}", tables_path.display());

    // Phase 3: Backing tree detection
    println!("detecting backing file tree...");
    let tree_report = tree::build_tree(&path)?;

    let num_files: usize = count_tree_nodes(&tree_report.roots);
    println!(
        "tree: {} files, {} roots, {} recoverable paths",
        num_files,
        tree_report.roots.len(),
        tree_report.paths.len(),
    );

    let tree_path = output.join("backing_tree.json");
    let json = serde_json::to_string_pretty(&tree_report)?;
    std::fs::write(&tree_path, json)?;
    println!("wrote {}", tree_path.display());

    Ok(())
}

fn count_tree_nodes(nodes: &[report::TreeNode]) -> usize {
    nodes
        .iter()
        .map(|n| 1 + count_tree_nodes(&n.children))
        .sum()
}

fn run_recover(_config: RescueConfig) -> Result<()> {
    println!("recover: not yet implemented (analyze works)");
    Ok(())
}
