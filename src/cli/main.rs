//! CLI tool for inspecting QCOW2 images.
//!
//! Provides subcommands for viewing header information, dumping metadata
//! tables, and checking image consistency.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

mod info;
mod dump;
mod check;

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
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
