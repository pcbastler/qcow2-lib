//! QCOW2 file discovery in directories.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// Discover all QCOW2 files at a path.
///
/// If `path` is a file, returns just that file.
/// If `path` is a directory, returns all `*.qcow2` files in it (non-recursive).
pub(super) fn discover_qcow2_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                if has_qcow2_extension(&p) || has_qcow2_magic(&p) {
                    files.push(p);
                }
            }
        }
        files.sort();
        Ok(files)
    } else {
        Ok(vec![])
    }
}

/// Check if a file has a .qcow2 extension.
fn has_qcow2_extension(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == "qcow2" || ext == "qcow")
        .unwrap_or(false)
}

/// Check if a file starts with the QCOW2 magic bytes.
fn has_qcow2_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    u32::from_be_bytes(magic) == qcow2_format::constants::QCOW2_MAGIC
}
