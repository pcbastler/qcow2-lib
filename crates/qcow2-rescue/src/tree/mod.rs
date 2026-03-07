//! Phase 3: Backing file tree detection and reconstruction.
//!
//! Scans a directory for QCOW2 files, reads their backing file references,
//! and builds a tree of base images and overlays.

mod discovery;
mod resolve;

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;
use crate::report::{TreeNode, TreeReport};

use discovery::discover_qcow2_files;
use resolve::{read_file_info, resolve_backing_path, FileInfo};

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

    // Build parent-to-children relationships
    // A file is a child of whatever it references as backing file
    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut has_parent: HashMap<String, bool> = HashMap::new();

    for (path_str, info) in &nodes {
        has_parent.insert(path_str.clone(), false);
        if let Some(ref backing) = info.backing_file {
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
        // Leaf node: emit the path (reversed: leaf to root)
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
    use std::path::PathBuf;

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

        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].file_name, "base.qcow2");
        assert_eq!(report.roots[0].children.len(), 1);
        assert_eq!(report.roots[0].children[0].file_name, "overlay.qcow2");

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
