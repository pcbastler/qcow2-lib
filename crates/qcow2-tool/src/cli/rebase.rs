//! `rebase` subcommand: change or remove the backing file reference.

use std::path::{Path, PathBuf};

use qcow2::engine::image::Qcow2Image;
use qcow2::error::Result;

/// Run the rebase subcommand.
pub fn run(path: &Path, backing: Option<&PathBuf>) -> Result<()> {
    let mut image = Qcow2Image::open_rw(path)?;

    match backing {
        Some(b) => {
            println!(
                "Rebasing: {} -> backing {}",
                path.display(),
                b.display()
            );
            image.rebase_unsafe(Some(b))?;
        }
        None => {
            println!("Rebasing: {} -> removing backing", path.display());
            image.rebase_unsafe(None)?;
        }
    }

    println!("Done.");
    Ok(())
}
