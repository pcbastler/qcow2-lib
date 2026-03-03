//! Shared test utilities for integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// A temporary QCOW2 image managed by a TempDir.
/// The image is automatically cleaned up when this struct is dropped.
pub struct TestImage {
    pub path: PathBuf,
    pub _dir: TempDir,
}

impl TestImage {
    /// Wrap an existing image path and its owning TempDir into a TestImage.
    pub fn wrap(path: PathBuf, dir: TempDir) -> Self {
        Self { path, _dir: dir }
    }

    /// Create a new QCOW2 v3 image with the given virtual size using qemu-img.
    pub fn create(size: &str) -> Self {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path().join("test.qcow2");

        let output = Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(&path)
            .arg(size)
            .output()
            .expect("failed to run qemu-img create");

        assert!(
            output.status.success(),
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self { path, _dir: dir }
    }

    /// Create a QCOW2 image with a specific cluster size.
    pub fn create_with_cluster_size(size: &str, cluster_size: usize) -> Self {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path().join("test.qcow2");

        let cluster_opt = format!("cluster_size={cluster_size}");
        let output = Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-o", &cluster_opt])
            .arg(&path)
            .arg(size)
            .output()
            .expect("failed to run qemu-img create");

        assert!(
            output.status.success(),
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self { path, _dir: dir }
    }

    /// Create a QCOW2 image with a backing file.
    pub fn create_with_backing(size: &str, backing: &Path) -> Self {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path().join("overlay.qcow2");

        let output = Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-b"])
            .arg(backing)
            .args(["-F", "qcow2"])
            .arg(&path)
            .arg(size)
            .output()
            .expect("failed to run qemu-img create");

        assert!(
            output.status.success(),
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self { path, _dir: dir }
    }

    /// Write data to the image at a given offset using qemu-io.
    pub fn write_data(&self, offset: u64, data: &[u8]) {
        // Write data to a temp file, then use dd-style qemu-io
        let data_file = self._dir.path().join("data.bin");
        std::fs::write(&data_file, data).expect("failed to write data file");

        // Use qemu-io to write the pattern
        let write_cmd = format!(
            "write -P 0x{:02x} {} {}",
            data[0], offset, data.len()
        );
        let output = Command::new("qemu-io")
            .args(["-f", "qcow2", "-c", &write_cmd])
            .arg(&self.path)
            .output()
            .expect("failed to run qemu-io");

        assert!(
            output.status.success(),
            "qemu-io write failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Write a pattern byte to the image at a given offset and length.
    pub fn write_pattern(&self, pattern: u8, offset: u64, length: usize) {
        let write_cmd = format!("write -P 0x{pattern:02x} {offset} {length}");
        let output = Command::new("qemu-io")
            .args(["-f", "qcow2", "-c", &write_cmd])
            .arg(&self.path)
            .output()
            .expect("failed to run qemu-io");

        assert!(
            output.status.success(),
            "qemu-io write failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Read data from the image at a given offset using qemu-io, returning raw bytes.
    pub fn read_via_qemu(&self, offset: u64, length: usize) -> Vec<u8> {
        let read_cmd = format!("read -v {offset} {length}");
        let output = Command::new("qemu-io")
            .args(["-f", "qcow2", "-c", &read_cmd])
            .arg(&self.path)
            .output()
            .expect("failed to run qemu-io");

        assert!(
            output.status.success(),
            "qemu-io read failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Parse the hex dump output from qemu-io
        parse_qemu_io_hex_dump(&String::from_utf8_lossy(&output.stdout))
    }

    /// Run qemu-img check on the image, returns true if clean.
    pub fn qemu_check(&self) -> bool {
        let output = Command::new("qemu-img")
            .args(["check", "-f", "qcow2"])
            .arg(&self.path)
            .output()
            .expect("failed to run qemu-img check");

        output.status.success()
    }
}

/// Parse the hex dump output from `qemu-io -c "read -v"`.
///
/// Format: `offset: xx xx xx xx ...  xxxxxxxx`
fn parse_qemu_io_hex_dump(output: &str) -> Vec<u8> {
    let mut bytes = Vec::new();

    for line in output.lines() {
        // Lines look like: "00000000:  48 65 6c 6c 6f 20 ...  Hello ..."
        let line = line.trim();
        if !line.contains(':') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        // Check if it's a hex address line (starts with hex digits)
        let addr_part = parts[0].trim();
        if addr_part.is_empty() || !addr_part.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        let hex_part = parts[1].trim();
        // Split on double space to separate hex from ASCII representation
        let hex_section = hex_part.split("  ").next().unwrap_or("");

        for hex_byte in hex_section.split_whitespace() {
            if let Ok(b) = u8::from_str_radix(hex_byte, 16) {
                bytes.push(b);
            }
        }
    }

    bytes
}

/// Check if qemu-io is available.
pub fn has_qemu_io() -> bool {
    Command::new("qemu-io")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if qemu-img is available.
pub fn has_qemu_img() -> bool {
    Command::new("qemu-img")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
