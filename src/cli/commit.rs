//! `commit` subcommand: merge overlay data into backing file.

use std::path::Path;

use qcow2::engine::image::Qcow2Image;
use qcow2::error::Result;

/// Run the commit subcommand.
pub fn run(path: &Path) -> Result<()> {
    println!("Committing: {}", path.display());

    let mut image = Qcow2Image::open_rw(path)?;
    image.commit()?;

    println!("Done.");
    Ok(())
}
