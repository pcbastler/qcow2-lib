use std::path::Path;
use std::process::Command;

use crate::config::{DataType, Filesystem, PartitionScheme};

/// Partition a raw disk image with the specified scheme, returning the byte
/// offset and size of the first partition.
pub fn partition_image(
    image: &Path,
    scheme: PartitionScheme,
) -> Result<(u64, u64), String> {
    match scheme {
        PartitionScheme::Mbr => partition_mbr(image),
        PartitionScheme::Gpt => partition_gpt(image),
    }
}

fn partition_mbr(image: &Path) -> Result<(u64, u64), String> {
    // Use sfdisk to create a single partition spanning the whole disk
    let input = "label: dos\ntype=83\n";
    let output = Command::new("sfdisk")
        .arg(image.display().to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .map_err(|e| format!("sfdisk failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "sfdisk failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    get_first_partition_offset(image)
}

fn partition_gpt(image: &Path) -> Result<(u64, u64), String> {
    let img = image.display().to_string();

    // Create GPT with sgdisk
    run_cmd("sgdisk", &["--zap-all", &img])?;
    run_cmd("sgdisk", &["-n", "1:2048:0", "-t", "1:8300", &img])?;

    get_first_partition_offset(image)
}

/// Read partition table to get offset + size of first partition.
fn get_first_partition_offset(image: &Path) -> Result<(u64, u64), String> {
    let output = Command::new("sfdisk")
        .args(["-J", &image.display().to_string()])
        .output()
        .map_err(|e| format!("sfdisk -J failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "sfdisk -J failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| format!("parse sfdisk JSON: {e}"))?;

    let parts = json["partitiontable"]["partitions"]
        .as_array()
        .ok_or("no partitions in sfdisk output")?;

    if parts.is_empty() {
        return Err("no partitions found".into());
    }

    let start_sectors = parts[0]["start"]
        .as_u64()
        .ok_or("missing start in partition")?;
    let size_sectors = parts[0]["size"]
        .as_u64()
        .ok_or("missing size in partition")?;

    let sector_size = json["partitiontable"]["sectorsize"]
        .as_u64()
        .unwrap_or(512);

    Ok((start_sectors * sector_size, size_sectors * sector_size))
}

/// Set up a loop device for a partition within a raw image.
/// Returns the loop device path (e.g. /dev/loop0).
pub fn setup_loop(image: &Path, offset: u64, size: u64) -> Result<String, String> {
    let output = Command::new("losetup")
        .args([
            "--find",
            "--show",
            "--offset",
            &offset.to_string(),
            "--sizelimit",
            &size.to_string(),
            &image.display().to_string(),
        ])
        .output()
        .map_err(|e| format!("losetup failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(dev)
}

/// Detach a loop device.
pub fn detach_loop(dev: &str) -> Result<(), String> {
    run_cmd("losetup", &["-d", dev])
}

/// Format a device with the given filesystem.
pub fn format_fs(device: &str, fs: Filesystem) -> Result<(), String> {
    let mut cmd_parts = fs.mkfs_cmd();
    cmd_parts.push(device);
    let program = cmd_parts[0];
    let args: Vec<&str> = cmd_parts[1..].to_vec();
    run_cmd(program, &args)
}

/// Mount a device at the given mount point.
pub fn mount_fs(device: &str, mount_point: &Path, fs: Filesystem) -> Result<(), String> {
    std::fs::create_dir_all(mount_point)
        .map_err(|e| format!("mkdir {}: {e}", mount_point.display()))?;

    let fs_type = match fs {
        Filesystem::Ntfs => "ntfs3",
        Filesystem::Fat32 => "vfat",
        Filesystem::Ext2 => "ext2",
        Filesystem::Ext3 => "ext3",
        Filesystem::Ext4 => "ext4",
        Filesystem::Btrfs => "btrfs",
        Filesystem::Xfs => "xfs",
    };

    run_cmd("mount", &[
        "-t", fs_type,
        device,
        &mount_point.display().to_string(),
    ])
}

/// Unmount a mount point.
pub fn umount(mount_point: &Path) -> Result<(), String> {
    run_cmd("umount", &[&mount_point.display().to_string()])
}

/// Write test data to a mounted filesystem.
/// Writes, deletes, and rewrites to create realistic write patterns.
pub fn write_test_data(
    mount_point: &Path,
    data_types: &[DataType],
    passes: u32,
) -> Result<(), String> {
    for pass in 0..passes {
        for dtype in data_types {
            let subdir = mount_point.join(format!("pass{pass}"));
            std::fs::create_dir_all(&subdir)
                .map_err(|e| format!("mkdir: {e}"))?;

            match dtype {
                DataType::Text => write_text_files(&subdir, pass)?,
                DataType::Binary => write_binary_files(&subdir, pass)?,
                DataType::Image => write_image_files(&subdir, pass)?,
            }
        }

        // Delete some files from earlier passes to create churn
        if pass > 0 {
            let old_dir = mount_point.join(format!("pass{}", pass - 1));
            if old_dir.exists() {
                // Delete half the files
                if let Ok(entries) = std::fs::read_dir(&old_dir) {
                    for (i, entry) in entries.flatten().enumerate() {
                        if i % 2 == 0 {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }

        // Sync to ensure data is written
        run_cmd("sync", &[])?;
    }

    Ok(())
}

// ~8MB text per pass: 8 files × ~1MB each
fn write_text_files(dir: &Path, pass: u32) -> Result<(), String> {
    let paragraphs = [
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n",
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n",
        "Curabitur pretium tincidunt lacus. Nulla gravida orci a odio. Nullam varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus magna felis sollicitudin mauris.\n",
        "Integer in mauris eu nibh euismod gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis risus a elit. Etiam tempor. Ut ullamcorper, ligula ut dictum pharetra, nisi nunc fringilla magna.\n",
    ];
    for i in 0..8 {
        let path = dir.join(format!("text_{pass}_{i}.txt"));
        let target_size = 1024 * 1024; // 1MB
        let mut content = format!("=== Test file pass={pass} index={i} ===\n\n");
        while content.len() < target_size {
            let para = paragraphs[(content.len() / 100) % paragraphs.len()];
            content.push_str(para);
        }
        std::fs::write(&path, content.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

// ~8MB binary per pass: 4 files × 2MB each
fn write_binary_files(dir: &Path, pass: u32) -> Result<(), String> {
    for i in 0..4 {
        let path = dir.join(format!("binary_{pass}_{i}.bin"));
        let size = 2 * 1024 * 1024; // 2MB
        let mut data = vec![0u8; size];
        let mut state: u32 = (pass * 1000 + i as u32).wrapping_mul(2654435761);
        for byte in data.iter_mut() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (state >> 16) as u8;
        }
        std::fs::write(&path, &data)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

// ~6MB images per pass: 3 BMP files × ~2MB each (832×832 24bpp)
fn write_image_files(dir: &Path, pass: u32) -> Result<(), String> {
    for i in 0..3 {
        let path = dir.join(format!("image_{pass}_{i}.bmp"));
        let width: u32 = 832;
        let height: u32 = 832;
        let row_size = ((width * 3 + 3) / 4) * 4;
        let pixel_data_size = row_size * height;
        let file_size = 54 + pixel_data_size;

        let mut data = Vec::with_capacity(file_size as usize);

        // BMP header
        data.extend_from_slice(b"BM");
        data.extend_from_slice(&file_size.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&54u32.to_le_bytes());

        // DIB header (BITMAPINFOHEADER)
        data.extend_from_slice(&40u32.to_le_bytes());
        data.extend_from_slice(&width.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&24u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&pixel_data_size.to_le_bytes());
        data.extend_from_slice(&2835u32.to_le_bytes());
        data.extend_from_slice(&2835u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        // Pixel data - gradient pattern
        let seed = pass * 100 + i as u32;
        for y in 0..height {
            for x in 0..width {
                let r = ((x.wrapping_mul(4).wrapping_add(seed)) % 256) as u8;
                let g = ((y.wrapping_mul(4).wrapping_add(seed)) % 256) as u8;
                let b = (((x + y).wrapping_mul(2).wrapping_add(seed)) % 256) as u8;
                data.push(b);
                data.push(g);
                data.push(r);
            }
            let padding = row_size - width * 3;
            data.resize(data.len() + padding as usize, 0);
        }

        std::fs::write(&path, &data)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{program} failed: {stderr}"));
    }
    Ok(())
}
