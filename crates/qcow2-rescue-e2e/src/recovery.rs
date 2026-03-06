use std::path::Path;
use std::process::Command;

/// Run qcow2-rescue recover on a corrupted image.
/// Returns the path to the recovered raw file.
pub fn run_rescue(
    rescue_bin: &Path,
    corrupt_image: &Path,
    output_dir: &Path,
) -> Result<std::path::PathBuf, String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("mkdir {}: {e}", output_dir.display()))?;

    let output = Command::new(rescue_bin)
        .args([
            "recover",
            &corrupt_image.display().to_string(),
            "-o",
            &output_dir.display().to_string(),
            "--format",
            "raw",
            "--on-conflict",
            "newer",
        ])
        .output()
        .map_err(|e| format!("failed to run qcow2-rescue: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(format!(
            "qcow2-rescue failed (exit {})\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        ));
    }

    let recovered = output_dir.join("recovered.raw");
    if !recovered.exists() {
        return Err(format!(
            "qcow2-rescue succeeded but no recovered.raw found\nstdout: {stdout}\nstderr: {stderr}"
        ));
    }

    Ok(recovered)
}

/// Run `qemu-img check -r all` on a corrupted image, then convert to raw.
/// Returns the path to the repaired raw file, or an error description.
pub fn run_qemu_repair(
    corrupt_image: &Path,
    output_dir: &Path,
) -> Result<std::path::PathBuf, String> {
    let repaired = output_dir.join("qemu-repaired.qcow2");
    std::fs::copy(corrupt_image, &repaired)
        .map_err(|e| format!("copy for qemu repair: {e}"))?;

    // Run qemu-img check -r all (ignore exit code, it returns non-zero for corruptions)
    let _ = Command::new("qemu-img")
        .args(["check", "-r", "all", &repaired.display().to_string()])
        .output();

    // Try to convert repaired image to raw
    let raw_path = output_dir.join("qemu-recovered.raw");
    let output = Command::new("qemu-img")
        .args([
            "convert",
            "-f", "qcow2",
            "-O", "raw",
            &repaired.display().to_string(),
            &raw_path.display().to_string(),
        ])
        .output()
        .map_err(|e| format!("qemu-img convert failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "qemu-img convert after repair failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    if !raw_path.exists() {
        return Err("qemu-img convert produced no output".into());
    }

    Ok(raw_path)
}

/// Convert a QCOW2 to raw using qemu-img for comparison.
pub fn qcow2_to_raw(qcow2_path: &Path, raw_path: &Path) -> Result<(), String> {
    let output = Command::new("qemu-img")
        .args([
            "convert",
            "-f", "qcow2",
            "-O", "raw",
            &qcow2_path.display().to_string(),
            &raw_path.display().to_string(),
        ])
        .output()
        .map_err(|e| format!("qemu-img convert failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "qemu-img convert failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
