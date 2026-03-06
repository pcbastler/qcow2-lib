use std::path::Path;
use std::process::Command;

/// Create a raw disk image of the given size.
pub fn create_raw_image(path: &Path, size_mb: u32) -> Result<(), String> {
    run_cmd("dd", &[
        "if=/dev/zero",
        &format!("of={}", path.display()),
        "bs=1M",
        &format!("count={size_mb}"),
    ])?;
    // Verify size
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let expected = size_mb as u64 * 1024 * 1024;
    if meta.len() != expected {
        return Err(format!(
            "raw image size mismatch: got {}, expected {expected}",
            meta.len()
        ));
    }
    Ok(())
}

/// Convert a raw image to QCOW2 using qemu-img.
pub fn raw_to_qcow2(raw_path: &Path, qcow2_path: &Path, compressed: bool) -> Result<(), String> {
    let mut args = vec![
        "convert",
        "-f", "raw",
        "-O", "qcow2",
    ];
    if compressed {
        args.push("-c");
    }
    let raw_s = raw_path.display().to_string();
    let qcow2_s = qcow2_path.display().to_string();
    args.push(&raw_s);
    args.push(&qcow2_s);
    run_cmd("qemu-img", &args)
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
