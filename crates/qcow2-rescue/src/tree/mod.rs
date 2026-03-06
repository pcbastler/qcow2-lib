//! Phase 3: Backing file tree detection and reconstruction.
//!
//! Scans a directory for QCOW2 files, reads their backing file references,
//! and builds a tree of base images → overlays.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::report::{TreeNode, TreeReport};

/// Build the backing file tree from a directory of QCOW2 images.
///
/// Reads the header of each `.qcow2` file in the directory to extract
/// backing file references, virtual size, and cluster size. Then assembles
/// these into a tree where base images are roots and overlays are children.
///
/// If `path` is a single file, the tree contains just that file.
pub fn build_tree(path: &Path) -> Result<TreeReport> {
    let files = discover_qcow2_files(path)?;

    // Parse headers and collect metadata for each file
    let mut nodes: HashMap<String, FileInfo> = HashMap::new();

    for file_path in &files {
        let info = read_file_info(file_path);
        let canonical = file_path.display().to_string();
        nodes.insert(canonical, info);
    }

    // Build parent→children relationships
    // A file is a child of whatever it references as backing file
    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut has_parent: HashMap<String, bool> = HashMap::new();

    for (path_str, info) in &nodes {
        has_parent.insert(path_str.clone(), false);
        if let Some(ref backing) = info.backing_file {
            // Resolve the backing file path relative to this file
            let resolved = resolve_backing_path(path_str, backing);
            children_map
                .entry(resolved)
                .or_default()
                .push(path_str.clone());
        }
    }

    // Mark files that have parents
    for children in children_map.values() {
        for child in children {
            has_parent.insert(child.clone(), true);
        }
    }

    // Build tree nodes starting from roots (files with no parent)
    let mut roots: Vec<TreeNode> = Vec::new();
    for (path_str, info) in &nodes {
        if !has_parent.get(path_str).copied().unwrap_or(false) {
            let node = build_tree_node(path_str, info, &nodes, &children_map);
            roots.push(node);
        }
    }

    // Sort roots by path for deterministic output
    roots.sort_by(|a, b| a.path.cmp(&b.path));

    // Enumerate all leaf-to-root paths
    let paths = enumerate_paths(&roots);

    Ok(TreeReport { roots, paths })
}

/// Information extracted from a single QCOW2 file's header.
struct FileInfo {
    backing_file: Option<String>,
    virtual_size: Option<u64>,
    cluster_size: Option<u64>,
    header_intact: bool,
    allocated_clusters: u64,
}

/// Discover all QCOW2 files at a path.
///
/// If `path` is a file, returns just that file.
/// If `path` is a directory, returns all `*.qcow2` files in it (non-recursive).
fn discover_qcow2_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                // Accept .qcow2 files or files with QCOW2 magic
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

/// Read metadata from a QCOW2 file's header.
fn read_file_info(path: &Path) -> FileInfo {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return FileInfo {
                backing_file: None,
                virtual_size: None,
                cluster_size: None,
                header_intact: false,
                allocated_clusters: 0,
            };
        }
    };

    let mut header_buf = vec![0u8; 4096];
    let bytes_read = match file.read(&mut header_buf) {
        Ok(n) => n,
        Err(_) => {
            return FileInfo {
                backing_file: None,
                virtual_size: None,
                cluster_size: None,
                header_intact: false,
                allocated_clusters: 0,
            };
        }
    };
    header_buf.truncate(bytes_read);

    match qcow2_format::Header::read_from(&header_buf) {
        Ok(header) => {
            let cluster_size = 1u64 << header.cluster_bits;

            // Read backing file name if present
            let backing_file = if header.backing_file_offset > 0 && header.backing_file_size > 0 {
                let off = header.backing_file_offset as usize;
                let len = header.backing_file_size as usize;
                if off + len <= header_buf.len() {
                    Some(
                        String::from_utf8_lossy(&header_buf[off..off + len]).to_string(),
                    )
                } else {
                    // Backing file name extends beyond what we read — try reading more
                    read_backing_name(&mut file, header.backing_file_offset, header.backing_file_size)
                }
            } else {
                None
            };

            // Quick estimate of allocated clusters from file size
            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let allocated_clusters = if cluster_size > 0 {
                file_size / cluster_size
            } else {
                0
            };

            FileInfo {
                backing_file,
                virtual_size: Some(header.virtual_size),
                cluster_size: Some(cluster_size),
                header_intact: true,
                allocated_clusters,
            }
        }
        Err(_) => FileInfo {
            backing_file: None,
            virtual_size: None,
            cluster_size: None,
            header_intact: false,
            allocated_clusters: 0,
        },
    }
}

/// Read the backing file name from the image.
fn read_backing_name(
    file: &mut std::fs::File,
    offset: u64,
    size: u32,
) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; size as usize];
    file.read_exact(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Resolve a backing file path relative to the referencing file.
fn resolve_backing_path(referencing_file: &str, backing_ref: &str) -> String {
    let backing_path = Path::new(backing_ref);
    if backing_path.is_absolute() {
        return backing_ref.to_string();
    }

    // Relative to the directory containing the referencing file
    if let Some(parent) = Path::new(referencing_file).parent() {
        let resolved = parent.join(backing_ref);
        // Canonicalize if possible, otherwise use as-is
        resolved
            .canonicalize()
            .unwrap_or(resolved)
            .display()
            .to_string()
    } else {
        backing_ref.to_string()
    }
}

/// Recursively build a tree node.
fn build_tree_node(
    path_str: &str,
    info: &FileInfo,
    all_nodes: &HashMap<String, FileInfo>,
    children_map: &HashMap<String, Vec<String>>,
) -> TreeNode {
    let file_name = Path::new(path_str)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path_str.to_string());

    let mut children = Vec::new();
    if let Some(child_paths) = children_map.get(path_str) {
        for child_path in child_paths {
            if let Some(child_info) = all_nodes.get(child_path) {
                children.push(build_tree_node(
                    child_path,
                    child_info,
                    all_nodes,
                    children_map,
                ));
            }
        }
        children.sort_by(|a, b| a.path.cmp(&b.path));
    }

    TreeNode {
        file_name,
        path: path_str.to_string(),
        backing_file: info.backing_file.clone(),
        virtual_size: info.virtual_size,
        cluster_size: info.cluster_size,
        header_intact: info.header_intact,
        allocated_clusters: info.allocated_clusters,
        children,
    }
}

/// Enumerate all leaf-to-root paths in the tree.
fn enumerate_paths(roots: &[TreeNode]) -> Vec<Vec<String>> {
    let mut result = Vec::new();
    for root in roots {
        let mut current_path = vec![root.path.clone()];
        enumerate_paths_recursive(root, &mut current_path, &mut result);
    }
    result
}

fn enumerate_paths_recursive(
    node: &TreeNode,
    current_path: &mut Vec<String>,
    result: &mut Vec<Vec<String>>,
) {
    if node.children.is_empty() {
        // Leaf node: emit the path (reversed: leaf → root)
        let mut path = current_path.clone();
        path.reverse();
        result.push(path);
    } else {
        for child in &node.children {
            current_path.push(child.path.clone());
            enumerate_paths_recursive(child, current_path, result);
            current_path.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};
    use std::io::Write;

    /// Create a minimal QCOW2 file with optional backing file reference.
    fn create_qcow2_file(
        dir: &Path,
        name: &str,
        virtual_size: u64,
        backing_file: Option<&str>,
    ) -> PathBuf {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let mut buf = vec![0u8; cluster_size as usize];

        // Header
        BigEndian::write_u32(&mut buf[0..4], qcow2_format::constants::QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], qcow2_format::constants::VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        // l1_table_entries
        BigEndian::write_u32(&mut buf[36..40], 1);
        // l1_table_offset
        BigEndian::write_u64(&mut buf[40..48], cluster_size);
        // header_length (v3)
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Write backing file name if present
        if let Some(backing) = backing_file {
            let name_offset = 104u64; // right after v3 header
            let name_bytes = backing.as_bytes();
            buf[name_offset as usize..name_offset as usize + name_bytes.len()]
                .copy_from_slice(name_bytes);
            BigEndian::write_u64(&mut buf[8..16], name_offset);
            BigEndian::write_u32(&mut buf[16..20], name_bytes.len() as u32);
        }

        let file_path = dir.join(name);
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(&buf).unwrap();

        file_path
    }

    #[test]
    fn single_file_tree() {
        let dir = tempfile::tempdir().unwrap();
        create_qcow2_file(dir.path(), "base.qcow2", 1 << 30, None);

        let report = build_tree(dir.path()).unwrap();
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].file_name, "base.qcow2");
        assert!(report.roots[0].header_intact);
        assert_eq!(report.roots[0].virtual_size, Some(1 << 30));
        assert!(report.roots[0].children.is_empty());
        assert_eq!(report.paths.len(), 1);
    }

    #[test]
    fn backing_chain() {
        let dir = tempfile::tempdir().unwrap();
        create_qcow2_file(dir.path(), "base.qcow2", 1 << 30, None);
        create_qcow2_file(
            dir.path(),
            "overlay.qcow2",
            1 << 30,
            Some("base.qcow2"),
        );

        let report = build_tree(dir.path()).unwrap();

        // Should have 1 root (base) with 1 child (overlay)
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].file_name, "base.qcow2");
        assert_eq!(report.roots[0].children.len(), 1);
        assert_eq!(report.roots[0].children[0].file_name, "overlay.qcow2");

        // 1 path: overlay → base
        assert_eq!(report.paths.len(), 1);
        assert_eq!(report.paths[0].len(), 2);
        assert!(report.paths[0][0].contains("overlay.qcow2"));
        assert!(report.paths[0][1].contains("base.qcow2"));
    }

    #[test]
    fn three_level_chain() {
        let dir = tempfile::tempdir().unwrap();
        create_qcow2_file(dir.path(), "base.qcow2", 1 << 30, None);
        create_qcow2_file(
            dir.path(),
            "snap1.qcow2",
            1 << 30,
            Some("base.qcow2"),
        );
        create_qcow2_file(
            dir.path(),
            "snap2.qcow2",
            1 << 30,
            Some("snap1.qcow2"),
        );

        let report = build_tree(dir.path()).unwrap();
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].children.len(), 1);
        assert_eq!(report.roots[0].children[0].children.len(), 1);

        // Path: snap2 → snap1 → base
        assert_eq!(report.paths.len(), 1);
        assert_eq!(report.paths[0].len(), 3);
    }

    #[test]
    fn branching_tree() {
        let dir = tempfile::tempdir().unwrap();
        create_qcow2_file(dir.path(), "base.qcow2", 1 << 30, None);
        create_qcow2_file(
            dir.path(),
            "branch_a.qcow2",
            1 << 30,
            Some("base.qcow2"),
        );
        create_qcow2_file(
            dir.path(),
            "branch_b.qcow2",
            1 << 30,
            Some("base.qcow2"),
        );

        let report = build_tree(dir.path()).unwrap();
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].children.len(), 2);

        // 2 paths: branch_a → base, branch_b → base
        assert_eq!(report.paths.len(), 2);
    }

    #[test]
    fn single_file_no_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = create_qcow2_file(dir.path(), "test.qcow2", 1 << 20, None);

        let report = build_tree(&file_path).unwrap();
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.paths.len(), 1);
    }
}
