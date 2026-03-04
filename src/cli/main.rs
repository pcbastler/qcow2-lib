//! CLI tool for inspecting and managing QCOW2 images.
//!
//! Provides subcommands for viewing header information, dumping metadata
//! tables, checking image consistency, and managing snapshots.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

mod bitmap;
mod check;
mod commit;
mod compact;
mod convert;
mod dump;
mod hash;
mod info;
mod rebase;
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
        /// Repair any inconsistencies found.
        #[arg(long)]
        repair: bool,
    },

    /// Manage image snapshots.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Manage persistent dirty bitmaps.
    Bitmap {
        #[command(subcommand)]
        action: BitmapAction,
    },

    /// Manage BLAKE3 per-hash-chunk hashes.
    Hash {
        #[command(subcommand)]
        action: HashAction,
    },

    /// Resize the image's virtual disk size.
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

    /// Compact/defragment a QCOW2 image into a new file.
    Compact {
        /// Input image file.
        input: PathBuf,
        /// Output image file.
        output: PathBuf,
        /// Compress output clusters.
        #[arg(long)]
        compress: bool,
    },

    /// Merge overlay data into its backing file.
    Commit {
        /// Path to the overlay QCOW2 image file.
        path: PathBuf,
    },

    /// Change the backing file reference (unsafe, no data migration).
    Rebase {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// New backing file path. Omit to remove the backing reference.
        #[arg(long)]
        backing: Option<PathBuf>,
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

#[derive(Subcommand)]
enum BitmapAction {
    /// List all bitmaps.
    List {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },
    /// Create a new bitmap.
    Create {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name for the new bitmap.
        name: String,
        /// Granularity in bits (9=512B, 16=64KiB, 20=1MiB). Default: 16.
        #[arg(long)]
        granularity: Option<u8>,
        /// Enable automatic dirty tracking on writes.
        #[arg(long)]
        auto: bool,
    },
    /// Delete an existing bitmap.
    Delete {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name of the bitmap to delete.
        name: String,
    },
    /// Dump dirty regions of a bitmap.
    Dump {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Name of the bitmap to dump.
        name: String,
    },
}

#[derive(Subcommand)]
enum HashAction {
    /// Initialize BLAKE3 hash extension (creates empty hash table).
    Init {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Hash size in bytes (16 or 32). Default: 32.
        #[arg(long)]
        hash_size: Option<u8>,
        /// Hash chunk size in bytes (must be power-of-2, 4K–16M). Default: 64K.
        #[arg(long)]
        chunk_size: Option<u64>,
    },
    /// Recompute hashes for all allocated clusters.
    Rehash {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },
    /// Verify all stored hashes against cluster data.
    Verify {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },
    /// Show hash extension information.
    Info {
        /// Path to the QCOW2 image file.
        path: PathBuf,
    },
    /// Export stored hashes.
    Export {
        /// Path to the QCOW2 image file.
        path: PathBuf,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove the hash extension and free all hash clusters.
    Remove {
        /// Path to the QCOW2 image file.
        path: PathBuf,
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
        Command::Check { path, repair } => check::run(&path, repair),
        Command::Snapshot { action } => match action {
            SnapshotAction::List { path } => snapshot::run_list(&path),
            SnapshotAction::Create { path, name } => snapshot::run_create(&path, &name),
            SnapshotAction::Delete { path, name } => snapshot::run_delete(&path, &name),
            SnapshotAction::Apply { path, name } => snapshot::run_apply(&path, &name),
        },
        Command::Bitmap { action } => match action {
            BitmapAction::List { path } => bitmap::run_list(&path),
            BitmapAction::Create { path, name, granularity, auto } => {
                bitmap::run_create(&path, &name, granularity, auto)
            }
            BitmapAction::Delete { path, name } => bitmap::run_delete(&path, &name),
            BitmapAction::Dump { path, name } => bitmap::run_dump(&path, &name),
        },
        Command::Hash { action } => match action {
            HashAction::Init { path, hash_size, chunk_size } => hash::run_init(&path, hash_size, chunk_size),
            HashAction::Rehash { path } => hash::run_rehash(&path),
            HashAction::Verify { path } => hash::run_verify(&path),
            HashAction::Info { path } => hash::run_info(&path),
            HashAction::Export { path, json } => hash::run_export(&path, None, json),
            HashAction::Remove { path } => hash::run_remove(&path),
        },
        Command::Resize { path, size } => resize::run(&path, &size),
        Command::Convert {
            input,
            output,
            format,
            compress,
        } => convert::run(&input, &output, &format, compress),
        Command::Compact {
            input,
            output,
            compress,
        } => compact::run(&input, &output, compress),
        Command::Commit { path } => commit::run(&path),
        Command::Rebase { path, backing } => rebase::run(&path, backing.as_ref()),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
