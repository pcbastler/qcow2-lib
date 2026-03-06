//! qcow2-rescue: Recovery library for corrupted QCOW2 images.
//!
//! Scans, analyzes, and reconstructs data from damaged QCOW2 files
//! that `qemu-img check -r all` cannot repair.

pub mod config;
pub mod error;
pub mod recover;
pub mod reconstruct;
pub mod report;
pub mod scan;
pub mod tree;
pub mod validate;

use std::path::PathBuf;

use config::{OutputFormat, RescueConfig};
use error::{RescueError, Result};
use report::TreeNode;

/// Run the analyze pipeline: scan, reconstruct, validate, tree detection.
///
/// Writes JSON reports to the output directory.
pub fn run_analyze(path: PathBuf, output: PathBuf, cluster_size: Option<u64>) -> Result<()> {
    if !path.exists() {
        return Err(RescueError::InputNotFound { path });
    }

    std::fs::create_dir_all(&output).map_err(|e| RescueError::OutputDirFailed {
        path: output.clone(),
        reason: e.to_string(),
    })?;

    // Phase 1: Cluster scan
    let file_size = std::fs::metadata(&path)?.len();
    let cluster_size = match cluster_size {
        Some(cs) => {
            println!("using user-specified cluster size: {} bytes", cs);
            cs
        }
        None => {
            println!("detecting cluster size from header...");
            scan::detect_cluster_size(&path)?
        }
    };

    println!(
        "scanning {} ({} bytes, {} clusters of {} bytes)",
        path.display(),
        file_size,
        file_size / cluster_size,
        cluster_size,
    );

    let cluster_map = scan::scan_file(&path, cluster_size)?;

    println!(
        "scan complete: {} headers, {} L1, {} L2, {} refcount, {} compressed, {} data, {} empty, {} unknown",
        cluster_map.summary.headers,
        cluster_map.summary.l1_tables,
        cluster_map.summary.l2_tables,
        cluster_map.summary.refcount_blocks,
        cluster_map.summary.compressed,
        cluster_map.summary.data,
        cluster_map.summary.empty,
        cluster_map.summary.unknown,
    );

    // Write cluster map report
    let report_path = output.join("cluster_map.json");
    let json = serde_json::to_string_pretty(&cluster_map)?;
    std::fs::write(&report_path, json)?;
    println!("wrote {}", report_path.display());

    // Phase 2: Metadata reconstruction
    println!("reconstructing metadata...");
    let mut tables_report = reconstruct::reconstruct(&path, &cluster_map)?;

    println!(
        "reconstruction complete: {} L1 entries, {} L2 verified, {} L2 suspicious, {} mappings ({} from L2), {} orphan data clusters",
        tables_report.l1_entries,
        tables_report.l2_tables_verified,
        tables_report.l2_tables_suspicious,
        tables_report.mappings_total,
        tables_report.mappings_from_l2,
        tables_report.orphan_data_clusters,
    );

    // Phase 2b: Content validation (decompression/decryption probes)
    let has_compressed = tables_report.mappings.iter().any(|m| m.compressed);
    let has_encrypted = tables_report.mappings.iter().any(|m| m.encrypted);

    if has_compressed || has_encrypted {
        println!("validating content ({} compressed, {} encrypted mappings)...",
            tables_report.mappings.iter().filter(|m| m.compressed).count(),
            tables_report.mappings.iter().filter(|m| m.encrypted).count(),
        );
        let validation = validate::validate_content(
            &path,
            cluster_size,
            &tables_report.mappings,
            None, // no crypt context in analyze mode
        )?;
        println!(
            "validation: {}/{} compressed OK, {}/{} encrypted OK",
            validation.compressed_ok, validation.compressed_probed,
            validation.encrypted_ok, validation.encrypted_probed,
        );
        tables_report.content_validation = Some(validation);
    }

    let tables_path = output.join("reconstructed_tables.json");
    let json = serde_json::to_string_pretty(&tables_report)?;
    std::fs::write(&tables_path, json)?;
    println!("wrote {}", tables_path.display());

    // Phase 3: Backing tree detection
    println!("detecting backing file tree...");
    let tree_report = tree::build_tree(&path)?;

    let num_files: usize = count_tree_nodes(&tree_report.roots);
    println!(
        "tree: {} files, {} roots, {} recoverable paths",
        num_files,
        tree_report.roots.len(),
        tree_report.paths.len(),
    );

    let tree_path = output.join("backing_tree.json");
    let json = serde_json::to_string_pretty(&tree_report)?;
    std::fs::write(&tree_path, json)?;
    println!("wrote {}", tree_path.display());

    Ok(())
}

fn count_tree_nodes(nodes: &[TreeNode]) -> usize {
    nodes
        .iter()
        .map(|n| 1 + count_tree_nodes(&n.children))
        .sum()
}

/// Run the recovery pipeline: scan, reconstruct, recover, report.
pub fn run_recover(config: RescueConfig) -> Result<()> {
    let input = &config.input;
    if !input.exists() {
        return Err(RescueError::InputNotFound { path: input.clone() });
    }

    std::fs::create_dir_all(&config.output).map_err(|e| RescueError::OutputDirFailed {
        path: config.output.clone(),
        reason: e.to_string(),
    })?;

    let format = config.format.unwrap_or(OutputFormat::Raw);

    let options = recover::RecoverOptions {
        format,
        skip_corrupt: true,
        password: config.password,
        cluster_size_override: config.cluster_size_override,
        resume: config.resume,
        on_conflict: config.on_conflict,
    };

    // Determine if we have a chain or a single file
    let report = if input.is_dir() {
        // Directory: detect backing chain
        println!("detecting backing file tree...");
        let tree_report = tree::build_tree(input)?;

        if tree_report.paths.is_empty() {
            return Err(RescueError::NoHeaderFound);
        }

        // Use the first path (leaf → root). Reverse to get base → leaf.
        let chain: Vec<PathBuf> = tree_report.paths[0]
            .iter()
            .rev()
            .map(PathBuf::from)
            .collect();

        println!(
            "recovering chain of {} layers: {}",
            chain.len(),
            chain.iter().map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string()).collect::<Vec<_>>().join(" → "),
        );

        let ext = match format {
            OutputFormat::Raw => "raw",
            OutputFormat::Qcow2 | OutputFormat::Chain => "qcow2",
        };
        let out_path = config.output.join(format!("recovered.{ext}"));

        recover::recover_chain(&chain, &out_path, &options)?
    } else {
        // Single file
        println!("recovering single image: {}", input.display());

        let ext = match format {
            OutputFormat::Raw => "raw",
            OutputFormat::Qcow2 | OutputFormat::Chain => "qcow2",
        };
        let out_path = config.output.join(format!("recovered.{ext}"));

        recover::recover_single(input, &out_path, &options)?
    };

    println!(
        "recovery complete: {} clusters written, {} failed, {} zeroed",
        report.clusters_written, report.clusters_failed, report.clusters_zeroed,
    );
    println!("output: {}", report.output_path);

    // Write report
    let report_path = config.output.join("recovery_report.json");
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&report_path, json)?;
    println!("wrote {}", report_path.display());

    Ok(())
}
