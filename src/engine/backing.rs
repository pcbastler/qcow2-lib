//! Backing file chain resolution.
//!
//! A QCOW2 image can reference a backing file. When a cluster is
//! unallocated in the current image, the data should be read from
//! the backing file instead. Backing files can themselves have
//! backing files, forming a chain.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::constants::MAX_BACKING_CHAIN_DEPTH;

/// A single entry in the backing file chain.
#[derive(Debug)]
pub struct BackingEntry {
    /// Absolute path of the backing file.
    pub path: PathBuf,
}

/// Resolved backing file chain from the current image to the base.
///
/// Index 0 is the first backing file (parent of the current image).
/// The last entry is the base image with no further backing file.
#[derive(Debug)]
pub struct BackingChain {
    /// Ordered list of backing files.
    entries: Vec<BackingEntry>,
}

impl BackingChain {
    /// Build a backing chain starting from the given backing file path.
    ///
    /// The `image_dir` is the directory of the current image, used to
    /// resolve relative backing file paths.
    ///
    /// Returns `None` if there is no backing file.
    pub fn resolve(backing_file_name: &str, image_dir: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        let mut visited = HashSet::new();

        let path = resolve_backing_path(backing_file_name, image_dir);
        let canonical = path
            .canonicalize()
            .map_err(|_| Error::BackingFileNotFound {
                path: path.display().to_string(),
            })?;

        if !visited.insert(canonical.clone()) {
            return Err(Error::BackingChainTooDeep {
                max_depth: MAX_BACKING_CHAIN_DEPTH,
            });
        }

        entries.push(BackingEntry {
            path: canonical.clone(),
        });

        // TODO: Read the backing file's header to check if it itself has
        // a backing file, and walk the chain up to MAX_BACKING_CHAIN_DEPTH.
        // For Phase 1 we only resolve the immediate backing file.

        Ok(Self { entries })
    }

    /// Number of backing files in the chain.
    pub fn depth(&self) -> usize {
        self.entries.len()
    }

    /// Get the backing file entries.
    pub fn entries(&self) -> &[BackingEntry] {
        &self.entries
    }
}

/// Resolve a backing file name to a full path, handling both absolute
/// and relative paths.
fn resolve_backing_path(name: &str, image_dir: &Path) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        image_dir.join(name)
    }
}

/// Read the backing file name from the image file.
///
/// The name is stored at `backing_file_offset` with length `backing_file_size`.
pub fn read_backing_file_name(
    backend: &dyn crate::io::IoBackend,
    offset: u64,
    size: u32,
) -> Result<String> {
    let mut buf = vec![0u8; size as usize];
    backend.read_exact_at(&mut buf, offset)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn resolve_existing_backing_file() {
        let tmp = NamedTempFile::new().unwrap();
        let dir = tmp.path().parent().unwrap();
        let name = tmp.path().file_name().unwrap().to_str().unwrap();

        let chain = BackingChain::resolve(name, dir).unwrap();
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn resolve_nonexistent_backing_file() {
        let result = BackingChain::resolve("nonexistent_file.qcow2", Path::new("/tmp"));
        assert!(result.is_err());
        match result {
            Err(Error::BackingFileNotFound { .. }) => {}
            other => panic!("expected BackingFileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn read_backing_name_from_memory() {
        let name = "base.qcow2";
        let backend = crate::io::MemoryBackend::new(name.as_bytes().to_vec());
        let result = read_backing_file_name(&backend, 0, name.len() as u32).unwrap();
        assert_eq!(result, "base.qcow2");
    }
}
