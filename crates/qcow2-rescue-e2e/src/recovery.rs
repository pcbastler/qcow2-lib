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
