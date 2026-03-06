//! CLI entry point for qcow2-rescue.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use qcow2_rescue::config::{ConflictStrategy, OutputFormat, RescueConfig};

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
        } => qcow2_rescue::run_analyze(path, output, cluster_size),
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
            qcow2_rescue::run_recover(config)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
