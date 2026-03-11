use std::path::Path;

use crate::config::*;
use crate::corruptor;
use crate::fs_setup;
use crate::image_gen;
use crate::recovery;
use crate::validator;

/// Manifest entry describing a generated test image.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ImageEntry {
    pub name: String,
    pub partition: String,
    pub filesystem: String,
    pub data_types: String,
    pub compressed: bool,
    /// Path to the QCOW2 file (relative to images dir)
    pub qcow2: String,
    /// Path to the reference raw file (relative to images dir)
    pub reference_raw: String,
}

#[allow(dead_code)]
pub struct TestResult {
    pub name: String,
    pub image: String,
    pub corruption: String,
    pub passed: bool,
    pub match_pct: f64,
    pub qemu_match_pct: Option<f64>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Generate phase (runs in Docker with root)
// ---------------------------------------------------------------------------

/// Generate all test images: partition, format, write data, convert to QCOW2.
/// Writes a manifest.json to the output directory.
pub fn generate_all(output_dir: &Path) -> Result<(), String> {
    let specs = build_image_specs();
    let total = specs.len();
    let mut manifest = Vec::new();

    for (i, spec) in specs.iter().enumerate() {
        println!("[{}/{}] generating {} ...", i + 1, total, spec.name);

        let img_dir = output_dir.join(&spec.name);
        let _ = std::fs::remove_dir_all(&img_dir);
        std::fs::create_dir_all(&img_dir)
            .map_err(|e| format!("mkdir {}: {e}", img_dir.display()))?;

        match generate_one(&img_dir, spec) {
            Ok(entry) => {
                println!("  OK: {}", entry.qcow2);
                manifest.push(entry);
            }
            Err(e) => {
                println!("  SKIP: {e}");
                let _ = std::fs::remove_dir_all(&img_dir);
            }
        }
    }

    // Write manifest
    let manifest_path = output_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, json)
        .map_err(|e| format!("write manifest: {e}"))?;
    println!("wrote manifest: {} entries -> {}", manifest.len(), manifest_path.display());

    Ok(())
}

fn generate_one(img_dir: &Path, spec: &ImageSpec) -> Result<ImageEntry, String> {
    let raw_path = img_dir.join("disk.raw");
    let qcow2_path = img_dir.join("disk.qcow2");
    let reference_raw = img_dir.join("reference.raw");
    let mount_point = img_dir.join("mnt");

    // 1. Create raw disk image
    image_gen::create_raw_image(&raw_path, spec.image_size_mb)?;

    // 2. Partition
    let (part_offset, part_size) = fs_setup::partition_image(&raw_path, spec.partition)?;

    // 3. Loop device + format
    let loop_dev = fs_setup::setup_loop(&raw_path, part_offset, part_size)?;
    let format_result = fs_setup::format_fs(&loop_dev, spec.filesystem);
    if let Err(e) = format_result {
        let _ = fs_setup::detach_loop(&loop_dev);
        return Err(format!("mkfs failed: {e}"));
    }

    // 4. Mount + write test data (3 passes for churn)
    let mount_result = fs_setup::mount_fs(&loop_dev, &mount_point, spec.filesystem);
    if let Err(e) = mount_result {
        let _ = fs_setup::detach_loop(&loop_dev);
        return Err(format!("mount failed: {e}"));
    }

    let write_result = fs_setup::write_test_data(&mount_point, &spec.data_types, 3);
    let _ = fs_setup::umount(&mount_point);
    let _ = fs_setup::detach_loop(&loop_dev);
    write_result?;

    // 5. Convert raw -> QCOW2
    image_gen::raw_to_qcow2(&raw_path, &qcow2_path, spec.compressed)?;

    // 6. Create reference raw from good QCOW2
    recovery::qcow2_to_raw(&qcow2_path, &reference_raw)?;

    // 7. Remove the large raw disk image (keep only qcow2 + reference)
    let _ = std::fs::remove_file(&raw_path);
    let _ = std::fs::remove_dir_all(&mount_point);

    let dtypes_str = spec
        .data_types
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join("+");

    Ok(ImageEntry {
        name: spec.name.clone(),
        partition: spec.partition.to_string(),
        filesystem: spec.filesystem.to_string(),
        data_types: dtypes_str,
        compressed: spec.compressed,
        qcow2: format!("{}/disk.qcow2", spec.name),
        reference_raw: format!("{}/reference.raw", spec.name),
    })
}

// ---------------------------------------------------------------------------
// Test phase (runs on host, no root needed)
// ---------------------------------------------------------------------------

/// Load manifest, then for each image try all corruption types.
/// If `compare_qemu` is true, also run `qemu-img check -r all` + convert for comparison.
pub fn test_all(images_dir: &Path, rescue_bin: &Path, compare_qemu: bool) -> Vec<TestResult> {
    let manifest_path = images_dir.join("manifest.json");
    let manifest_data = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", manifest_path.display());
        std::process::exit(1);
    });
    let entries: Vec<ImageEntry> = serde_json::from_str(&manifest_data).unwrap_or_else(|e| {
        eprintln!("cannot parse manifest: {e}");
        std::process::exit(1);
    });

    let corruptions = [
        CorruptionType::HeaderZeroed,
        CorruptionType::L1Corrupted,
        CorruptionType::L2Corrupted,
        CorruptionType::RefcountCorrupted,
        CorruptionType::HeaderAndL1,
        CorruptionType::AllMetadata,
    ];

    let total = entries.len() * corruptions.len();
    let mut results = Vec::with_capacity(total);
    let mut idx = 0;

    for entry in &entries {
        let qcow2_path = images_dir.join(&entry.qcow2);
        let reference_path = images_dir.join(&entry.reference_raw);

        for &corr in &corruptions {
            idx += 1;
            let test_name = format!("{}_{corr}", entry.name);
            println!("[{idx}/{total}] {test_name} ...");

            let r = run_corruption_test(&qcow2_path, &reference_path, corr, rescue_bin, compare_qemu);

            if compare_qemu {
                let qemu_str = match r.qemu_pct {
                    Some(q) => format!("{q:.0}%"),
                    None => "FAIL".into(),
                };
                if r.passed {
                    println!("  PASS: rescue={:.0}% qemu={}", r.rescue_pct, qemu_str);
                } else {
                    println!("  FAIL: rescue={:.0}% qemu={}", r.rescue_pct, qemu_str);
                }
            } else if r.passed {
                println!("  PASS: {:.0}%", r.rescue_pct);
            } else {
                println!("  FAIL: {:.0}% | {}", r.rescue_pct, r.error.as_deref().unwrap_or(""));
            }

            results.push(TestResult {
                name: test_name,
                image: entry.name.clone(),
                corruption: corr.to_string(),
                passed: r.passed,
                match_pct: r.rescue_pct,
                qemu_match_pct: r.qemu_pct,
                error: r.error,
            });
        }
    }

    results
}

/// Result of a single corruption test with both rescue and qemu results.
struct CorruptionTestResult {
    rescue_pct: f64,
    qemu_pct: Option<f64>,
    passed: bool,
    error: Option<String>,
}

fn run_corruption_test(
    qcow2_path: &Path,
    reference_path: &Path,
    corruption: CorruptionType,
    rescue_bin: &Path,
    compare_qemu: bool,
) -> CorruptionTestResult {
    let test_dir = std::env::temp_dir().join(format!(
        "qcow2-e2e-{}-{corruption}",
        qcow2_path.parent().unwrap().file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&test_dir);
    if let Err(e) = std::fs::create_dir_all(&test_dir) {
        return CorruptionTestResult {
            rescue_pct: 0.0, qemu_pct: None,
            passed: false, error: Some(format!("mkdir: {e}")),
        };
    }

    let corrupt_path = test_dir.join("corrupt.qcow2");
    let recovery_dir = test_dir.join("recovery");
    let qemu_dir = test_dir.join("qemu");
    let _ = std::fs::create_dir_all(&qemu_dir);

    if let Err(e) = std::fs::copy(qcow2_path, &corrupt_path) {
        return CorruptionTestResult {
            rescue_pct: 0.0, qemu_pct: None,
            passed: false, error: Some(format!("copy qcow2: {e}")),
        };
    }

    let corruption_desc = match corruptor::corrupt(&corrupt_path, corruption) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&test_dir);
            return CorruptionTestResult {
                rescue_pct: 0.0, qemu_pct: None,
                passed: false, error: Some(e),
            };
        }
    };

    // --- qcow2-rescue ---
    let rescue_pct = match recovery::run_rescue(rescue_bin, &corrupt_path, &recovery_dir) {
        Ok(recovered_raw) => {
            match validator::compare_raw_images(reference_path, &recovered_raw) {
                Ok(cmp) => cmp.match_percent(),
                Err(_) => 0.0,
            }
        }
        Err(_) => 0.0,
    };

    // --- qemu-img repair (optional) ---
    let qemu_pct = if compare_qemu {
        match recovery::run_qemu_repair(&corrupt_path, &qemu_dir) {
            Ok(qemu_raw) => {
                match validator::compare_raw_images(reference_path, &qemu_raw) {
                    Ok(cmp) => Some(cmp.match_percent()),
                    Err(_) => Some(0.0),
                }
            }
            Err(_) => None, // qemu couldn't even open/convert
        }
    } else {
        None
    };

    let _ = std::fs::remove_dir_all(&test_dir);

    let min_match = match corruption {
        CorruptionType::HeaderZeroed | CorruptionType::RefcountCorrupted => 95.0,
        CorruptionType::L1Corrupted | CorruptionType::L2Corrupted => 80.0,
        CorruptionType::HeaderAndL1 => 70.0,
        CorruptionType::AllMetadata => 50.0,
    };

    let passed = rescue_pct >= min_match;
    let error = if !passed {
        Some(format!("{corruption_desc} -> {rescue_pct:.1}% (need {min_match}%)"))
    } else {
        None
    };

    CorruptionTestResult {
        rescue_pct,
        qemu_pct,
        passed,
        error,
    }
}

// ---------------------------------------------------------------------------
// Result matrix
// ---------------------------------------------------------------------------

const CORRUPTION_COLS: &[&str] = &[
    "header_zeroed",
    "l1_corrupted",
    "l2_corrupted",
    "refcount_corrupted",
    "header_and_l1",
    "all_metadata",
];

const COL_HEADERS: &[&str] = &["header", "L1", "L2", "refcnt", "hdr+L1", "allMD"];
const COL_WIDTH: usize = 10;

/// Print a result matrix: images x corruption types.
pub fn print_matrix(results: &[TestResult]) {
    use std::collections::HashMap;

    let has_qemu = results.iter().any(|r| r.qemu_match_pct.is_some());

    let mut images: Vec<String> = Vec::new();
    for r in results {
        if !images.contains(&r.image) {
            images.push(r.image.clone());
        }
    }

    type Lookup<'a> = HashMap<(&'a str, &'a str), (bool, f64, Option<f64>)>;
    let mut lookup: Lookup = HashMap::new();
    for r in results {
        lookup.insert(
            (r.image.as_str(), r.corruption.as_str()),
            (r.passed, r.match_pct, r.qemu_match_pct),
        );
    }

    let nw = images.iter().map(|s| s.len()).max().unwrap_or(20).max(5) + 2;

    if has_qemu {
        print_comparison_matrix(results, &images, &lookup, nw);
    } else {
        print_rescue_only_matrix(results, &images, &lookup, nw);
    }

    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    println!();
    println!("Total: {passed}/{total} passed, {} failed", total - passed);
}

type Lookup<'a> = std::collections::HashMap<(&'a str, &'a str), (bool, f64, Option<f64>)>;

fn print_table_header(nw: usize, headers: &[&str], col_width: usize) {
    print!("{:<nw$} |", "Image");
    for hdr in headers {
        print!("{:^width$}|", hdr, width = col_width);
    }
    println!();
    print_table_separator(nw, headers.len(), col_width);
}

fn print_table_separator(nw: usize, cols: usize, col_width: usize) {
    print!("{:-<nw$}-+", "");
    for _ in 0..cols {
        print!("{:-<width$}+", "", width = col_width);
    }
    println!();
}

#[allow(clippy::cognitive_complexity)]
fn print_comparison_matrix(
    results: &[TestResult],
    images: &[String],
    lookup: &Lookup<'_>,
    nw: usize,
) {
    let cw = 13;

    println!();
    println!("=== Comparison: qcow2-rescue vs qemu-img repair ===");
    println!("  (cell format: rescue% / qemu%)");
    println!();

    print_table_header(nw, COL_HEADERS, cw);

    for img in images {
        print!("{:<nw$} |", img);
        for &corr in CORRUPTION_COLS {
            if let Some(&(_, rpct, qpct)) = lookup.get(&(img.as_str(), corr)) {
                let qstr = match qpct {
                    Some(q) => format!("{q:3.0}"),
                    None => " --".into(),
                };
                let cell = format!("{:3.0} / {}", rpct, qstr);
                print!("{:^width$}|", cell, width = cw);
            } else {
                print!("{:^width$}|", "-", width = cw);
            }
        }
        println!();
    }

    print_table_separator(nw, COL_HEADERS.len(), cw);

    // Average per corruption
    print!("{:<nw$} |", "avg rescue");
    for &corr in CORRUPTION_COLS {
        let vals: Vec<f64> = results.iter()
            .filter(|r| r.corruption == corr)
            .map(|r| r.match_pct)
            .collect();
        let avg = if vals.is_empty() { 0.0 } else { vals.iter().sum::<f64>() / vals.len() as f64 };
        print!("{:^width$}|", format!("{avg:5.1}%"), width = cw);
    }
    println!();

    print!("{:<nw$} |", "avg qemu");
    for &corr in CORRUPTION_COLS {
        let vals: Vec<f64> = results.iter()
            .filter(|r| r.corruption == corr)
            .filter_map(|r| r.qemu_match_pct)
            .collect();
        if vals.is_empty() {
            print!("{:^width$}|", "--", width = cw);
        } else {
            let avg = vals.iter().sum::<f64>() / vals.len() as f64;
            print!("{:^width$}|", format!("{avg:5.1}%"), width = cw);
        }
    }
    println!();

    // Wins comparison
    println!();
    let mut rescue_wins = 0u32;
    let mut qemu_wins = 0u32;
    let mut ties = 0u32;
    for r in results {
        if let Some(q) = r.qemu_match_pct {
            if r.match_pct > q + 0.1 {
                rescue_wins += 1;
            } else if q > r.match_pct + 0.1 {
                qemu_wins += 1;
            } else {
                ties += 1;
            }
        }
    }
    println!("  rescue wins: {rescue_wins} | qemu wins: {qemu_wins} | ties: {ties}");
}

fn print_rescue_only_matrix(
    results: &[TestResult],
    images: &[String],
    lookup: &Lookup<'_>,
    nw: usize,
) {
    println!();
    print_table_header(nw, COL_HEADERS, COL_WIDTH);

    for img in images {
        print!("{:<nw$} |", img);
        for &corr in CORRUPTION_COLS {
            if let Some(&(passed, pct, _)) = lookup.get(&(img.as_str(), corr)) {
                let cell = if passed {
                    format!("{:3.0}% OK", pct)
                } else {
                    format!("{:3.0}% FAIL", pct)
                };
                print!("{:^width$}|", cell, width = COL_WIDTH);
            } else {
                print!("{:^width$}|", "-", width = COL_WIDTH);
            }
        }
        println!();
    }

    print_table_separator(nw, COL_HEADERS.len(), COL_WIDTH);

    print!("{:<nw$} |", "PASSED");
    for &corr in CORRUPTION_COLS {
        let p = results.iter().filter(|r| r.corruption == corr && r.passed).count();
        let t = results.iter().filter(|r| r.corruption == corr).count();
        let cell = format!("{p}/{t}");
        print!("{:^width$}|", cell, width = COL_WIDTH);
    }
    println!();
}

// ---------------------------------------------------------------------------
// Image spec matrix (what to generate)
// ---------------------------------------------------------------------------

struct ImageSpec {
    name: String,
    partition: PartitionScheme,
    filesystem: Filesystem,
    data_types: Vec<DataType>,
    compressed: bool,
    image_size_mb: u32,
}

fn build_image_specs() -> Vec<ImageSpec> {
    let partitions = [PartitionScheme::Mbr, PartitionScheme::Gpt];
    let filesystems = [
        Filesystem::Ext2,
        Filesystem::Ext3,
        Filesystem::Ext4,
        Filesystem::Fat32,
        Filesystem::Ntfs,
        Filesystem::Btrfs,
        Filesystem::Xfs,
    ];

    let mut specs = Vec::new();

    // Each partition × each FS × mixed data (uncompressed)
    for &part in &partitions {
        for &fs in &filesystems {
            specs.push(ImageSpec {
                name: format!("{part}_{fs}_mixed"),
                partition: part,
                filesystem: fs,
                data_types: vec![DataType::Text, DataType::Binary, DataType::Image],
                compressed: false,
                image_size_mb: min_image_size(fs),
            });
        }
    }

    // Compressed variants: GPT + each FS
    for &fs in &filesystems {
        specs.push(ImageSpec {
            name: format!("gpt_{fs}_mixed_compressed"),
            partition: PartitionScheme::Gpt,
            filesystem: fs,
            data_types: vec![DataType::Text, DataType::Binary, DataType::Image],
            compressed: true,
            image_size_mb: min_image_size(fs),
        });
    }

    // Data type isolation: GPT + ext4 + individual types
    for dtype in [DataType::Text, DataType::Binary, DataType::Image] {
        specs.push(ImageSpec {
            name: format!("gpt_ext4_{dtype}_only"),
            partition: PartitionScheme::Gpt,
            filesystem: Filesystem::Ext4,
            data_types: vec![dtype],
            compressed: false,
            image_size_mb: 128,
        });
    }

    println!("generated {} image specs", specs.len());
    specs
}

/// Minimum image size for each filesystem.
/// Must fit ~22MB per pass × 3 passes of test data (with deletions between passes).
/// btrfs needs ~128MB overhead, xfs needs ~300MB minimum.
fn min_image_size(fs: Filesystem) -> u32 {
    match fs {
        Filesystem::Btrfs => 256,
        Filesystem::Xfs => 512,
        _ => 128,
    }
}
