//! Backing file chain resolution.
//!
//! A QCOW2 image can reference a backing file. When a cluster is
//! unallocated in the current image, the data should be read from
//! the backing file instead. Backing files can themselves have
//! backing files, forming a chain.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::constants::{HEADER_V3_MIN_LENGTH, MAX_BACKING_CHAIN_DEPTH};
use crate::format::header::Header;
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

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
        let mut current_name = backing_file_name.to_string();
        let mut current_dir = image_dir.to_path_buf();

        loop {
            if entries.len() >= MAX_BACKING_CHAIN_DEPTH as usize {
                return Err(Error::BackingChainTooDeep {
                    max_depth: MAX_BACKING_CHAIN_DEPTH,
                });
            }

            let path = resolve_backing_path(&current_name, &current_dir);
            let canonical =
                path.canonicalize()
                    .map_err(|_| Error::BackingFileNotFound {
                        path: path.display().to_string(),
                    })?;

            if !visited.insert(canonical.clone()) {
                return Err(Error::BackingChainLoop {
                    path: canonical.display().to_string(),
                });
            }

            entries.push(BackingEntry {
                path: canonical.clone(),
            });

            // Read this backing file's header to check for further backing
            let backend = SyncFileBackend::open(&canonical)?;
            let mut header_buf = vec![0u8; HEADER_V3_MIN_LENGTH];
            backend.read_exact_at(&mut header_buf, 0)?;
            let header = Header::read_from(&header_buf)?;

            if !header.has_backing_file() {
                break;
            }

            // Read the next backing file name and continue
            let name = read_backing_file_name(
                &backend,
                header.backing_file_offset,
                header.backing_file_size,
            )?;
            current_dir = canonical
                .parent()
                .unwrap_or(Path::new("/"))
                .to_path_buf();
            current_name = name;
        }

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
    use crate::engine::image::{CreateOptions, Qcow2Image};

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

    #[test]
    fn resolve_single_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.qcow2");
        Qcow2Image::create(
            &base_path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            refcount_order: None,
            },
        )
        .unwrap();

        let overlay_path = dir.path().join("overlay.qcow2");
        Qcow2Image::create_overlay(&overlay_path, &base_path, 1024 * 1024).unwrap();

        // Open overlay and check its backing chain
        let image = Qcow2Image::open(&overlay_path).unwrap();
        let chain = image.backing_chain().unwrap();
        assert_eq!(chain.depth(), 1);
        assert_eq!(chain.entries()[0].path, base_path.canonicalize().unwrap());
    }

    #[test]
    fn resolve_three_level_chain() {
        let dir = tempfile::tempdir().unwrap();

        // base → mid → top
        let base_path = dir.path().join("base.qcow2");
        Qcow2Image::create(
            &base_path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            refcount_order: None,
            },
        )
        .unwrap();

        let mid_path = dir.path().join("mid.qcow2");
        Qcow2Image::create_overlay(&mid_path, &base_path, 1024 * 1024).unwrap();

        let top_path = dir.path().join("top.qcow2");
        Qcow2Image::create_overlay(&top_path, &mid_path, 1024 * 1024).unwrap();

        // Resolve chain from top
        let chain = BackingChain::resolve(
            "mid.qcow2",
            dir.path(),
        )
        .unwrap();
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.entries()[0].path, mid_path.canonicalize().unwrap());
        assert_eq!(chain.entries()[1].path, base_path.canonicalize().unwrap());
    }

    #[test]
    fn resolve_detects_loop() {
        let dir = tempfile::tempdir().unwrap();

        // Create base
        let base_path = dir.path().join("base.qcow2");
        Qcow2Image::create(
            &base_path,
            CreateOptions {
                virtual_size: 1024 * 1024,
                cluster_bits: None,
            extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
            refcount_order: None,
            },
        )
        .unwrap();

        // Create A → base
        let a_path = dir.path().join("a.qcow2");
        Qcow2Image::create_overlay(&a_path, &base_path, 1024 * 1024).unwrap();

        // Create B → A
        let b_path = dir.path().join("b.qcow2");
        Qcow2Image::create_overlay(&b_path, &a_path, 1024 * 1024).unwrap();

        // Now rewrite A's backing to point to B (creating a loop: B → A → B → ...)
        // We do this by using rebase at the raw level
        {
            let backend = SyncFileBackend::open_rw(&a_path).unwrap();
            let mut header_buf = vec![0u8; HEADER_V3_MIN_LENGTH];
            backend.read_exact_at(&mut header_buf, 0).unwrap();
            let mut header = Header::read_from(&header_buf).unwrap();

            // Write new backing name at the existing offset
            let new_name = "b.qcow2";
            let name_bytes = new_name.as_bytes();
            backend
                .write_all_at(name_bytes, header.backing_file_offset)
                .unwrap();
            header.backing_file_size = name_bytes.len() as u32;

            let mut buf = vec![0u8; header.serialized_length()];
            header.write_to(&mut buf).unwrap();
            backend.write_all_at(&buf, 0).unwrap();
            backend.flush().unwrap();
        }

        // Now resolving from B should detect the loop
        let result = BackingChain::resolve("b.qcow2", dir.path());
        match result {
            Err(Error::BackingChainLoop { .. }) => {}
            other => panic!("expected BackingChainLoop, got {other:?}"),
        }
    }
}
