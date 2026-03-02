//! CLI tool for inspecting and managing QCOW2 images.
//!
//! Provides subcommands for viewing header information, dumping metadata
//! tables, checking image consistency, and managing snapshots.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

mod check;
mod convert;
mod dump;
mod info;
mod resize;
mod snapshot;

/// qcow2-tool: Inspect and validate QCOW2 disk images.
#[derive(Parser)]
#[command(name = "qcow2-tool", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Display header information for a QCOW2 image.
    Info {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },

    /// Dump metadata tables (L1, L2, refcount) in a human-readable format.
    Dump {
        /// Path to the QCOW2 image file.
        path: PathBuf,

        /// Which table to dump.
        #[arg(value_enum, default_value_t = DumpTarget::L1)]
        target: DumpTarget,
    },

    /// Check image consistency (refcount validation).
    Check {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },

    /// Manage image snapshots.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Resize the image's virtual disk size (grow only).
    Resize {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// New virtual size (supports K/M/G/T suffixes).
        size: String,
    },

    /// Convert between QCOW2 and raw image formats.
    Convert {
        /// Input image file.
        input: PathBuf,
        /// Output image file.
        output: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = convert::OutputFormat::Qcow2)]
        format: convert::OutputFormat,
        /// Compress output clusters (QCOW2 output only).
        #[arg(long)]
        compress: bool,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    /// List all snapshots.
    List {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },
    /// Create a new snapshot.
    Create {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name for the new snapshot.
        name: String,
    },
    /// Delete an existing snapshot.
    Delete {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name or ID of the snapshot to delete.
        name: String,
    },
    /// Revert the image to a snapshot's state.
    Apply {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name or ID of the snapshot to apply.
        name: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum DumpTarget {
    /// L1 table entries.
    L1,
    /// L2 table entries (for the first L1 entry).
    L2,
    /// Refcount table entries.
    Refcount,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Info { path } => info::run(&path),
        Command::Dump { path, target } => dump::run(&path, &target),
        Command::Check { path } => check::run(&path),
        Command::Snapshot { action } => match action {
            SnapshotAction::List { path } => snapshot::run_list(&path),
            SnapshotAction::Create { path, name } => snapshot::run_create(&path, &name),
            SnapshotAction::Delete { path, name } => snapshot::run_delete(&path, &name),
            SnapshotAction::Apply { path, name } => snapshot::run_apply(&path, &name),
        },
        Command::Resize { path, size } => resize::run(&path, &size),
        Command::Convert {
            input,
            output,
            format,
            compress,
        } => convert::run(&input, &output, &format, compress),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
