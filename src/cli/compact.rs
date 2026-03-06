//! `compact` subcommand: defragment and compact a QCOW2 image.
//!
//! Creates a new, defragmented copy of the image. The output contains
//! only allocated clusters in sequential order, eliminating fragmentation
//! and reclaiming leaked space.

use std::path::Path;

use qcow2::engine::converter;
use qcow2::error::Result;

/// Run the compact subcommand.
pub fn run(input: &Path, output: &Path, compress: bool) -> Result<()> {
    println!(
        "Compacting: {} -> {}{}",
        input.display(),
        output.display(),
        if compress { " (compressed)" } else { "" }
    );

    converter::convert_qcow2_to_qcow2(input, output, compress, None, None, None, None)?;

    println!("Done.");
    Ok(())
}
