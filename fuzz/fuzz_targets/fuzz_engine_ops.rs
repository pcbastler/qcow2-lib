#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::io::MemoryBackend;

/// Image configuration — the fuzzer explores different cluster sizes and virtual sizes.
#[derive(Arbitrary, Debug)]
struct ImageConfig {
    /// Cluster bits: mapped to valid range 12–16 (4 KB to 64 KB).
    cluster_bits_raw: u8,
    /// Virtual size: mapped to 256 KB – 4 MB range.
    virtual_size_raw: u8,
}

impl ImageConfig {
    fn cluster_bits(&self) -> u32 {
        // Valid range: 12 (4KB) to 16 (64KB)
        12 + (self.cluster_bits_raw % 5) as u32
    }

    fn virtual_size(&self) -> u64 {
        // 256 KB to 4 MB in 256 KB steps
        ((self.virtual_size_raw % 16) as u64 + 1) << 18
    }
}

/// A single operation to perform on the image.
#[derive(Arbitrary, Debug)]
enum Op {
    /// Write data at a guest offset.
    Write { offset_raw: u32, data: Vec<u8> },
    /// Read data at a guest offset.
    Read { offset_raw: u32, len_raw: u16 },
    /// Write data, then read it back and assert equality.
    WriteAndVerify { offset_raw: u32, data: Vec<u8> },
    /// Create a snapshot with a given name index.
    SnapshotCreate { name_idx: u8 },
    /// Apply/revert to a snapshot by name index.
    SnapshotApply { name_idx: u8 },
    /// Delete a snapshot by name index.
    SnapshotDelete { name_idx: u8 },
    /// Snapshot depth test: create snapshot, write different data, apply, verify old data.
    SnapshotCowVerify {
        name_idx: u8,
        offset_raw: u32,
        data_before: Vec<u8>,
        data_after: Vec<u8>,
    },
    /// Resize the virtual disk.
    Resize { new_size_raw: u8 },
}

/// Top-level fuzz input.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: ImageConfig,
    ops: Vec<Op>,
}

/// Clamp a write buffer to fit within virtual_size at the given offset.
/// Returns None if no valid write is possible.
fn clamp_write(data: &[u8], offset: u64, virtual_size: u64) -> Option<(&[u8], u64)> {
    if data.is_empty() || data.len() > 64 * 1024 || offset >= virtual_size {
        return None;
    }
    let max_len = (virtual_size - offset) as usize;
    let len = data.len().min(max_len);
    if len == 0 {
        return None;
    }
    Some((&data[..len], offset))
}

const SNAP_NAMES: &[&str] = &[
    "snap-0", "snap-1", "snap-2", "snap-3", "snap-4", "snap-5", "snap-6", "snap-7",
];

fuzz_target!(|input: FuzzInput| {
    // Cap operations to avoid excessive runtime per input
    let max_ops = 48;
    let ops = if input.ops.len() > max_ops {
        &input.ops[..max_ops]
    } else {
        &input.ops
    };

    let virtual_size = input.config.virtual_size();
    let backend = Box::new(MemoryBackend::zeroed(0));
    let mut image = match Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(input.config.cluster_bits()),
        },
    ) {
        Ok(img) => img,
        Err(_) => return,
    };

    for op in ops {
        match op {
            Op::Write { offset_raw, data } => {
                let offset = *offset_raw as u64 % virtual_size;
                if let Some((buf, off)) = clamp_write(data, offset, virtual_size) {
                    let _ = image.write_at(buf, off);
                }
            }
            Op::Read { offset_raw, len_raw } => {
                let len = (*len_raw as usize).min(64 * 1024).max(1);
                let offset = *offset_raw as u64 % virtual_size;
                let actual_len = len.min((virtual_size - offset) as usize);
                if actual_len == 0 {
                    continue;
                }
                let mut buf = vec![0u8; actual_len];
                let _ = image.read_at(&mut buf, offset);
            }
            Op::WriteAndVerify { offset_raw, data } => {
                let offset = *offset_raw as u64 % virtual_size;
                if let Some((buf, off)) = clamp_write(data, offset, virtual_size) {
                    if image.write_at(buf, off).is_ok() {
                        let mut readback = vec![0u8; buf.len()];
                        if image.read_at(&mut readback, off).is_ok() {
                            assert_eq!(buf, &readback[..], "write/read mismatch at offset {off}");
                        }
                    }
                }
            }
            Op::SnapshotCreate { name_idx } => {
                let name = SNAP_NAMES[*name_idx as usize % SNAP_NAMES.len()];
                let _ = image.snapshot_create(name);
            }
            Op::SnapshotApply { name_idx } => {
                let name = SNAP_NAMES[*name_idx as usize % SNAP_NAMES.len()];
                let _ = image.snapshot_apply(name);
            }
            Op::SnapshotDelete { name_idx } => {
                let name = SNAP_NAMES[*name_idx as usize % SNAP_NAMES.len()];
                let _ = image.snapshot_delete(name);
            }
            Op::SnapshotCowVerify {
                name_idx,
                offset_raw,
                data_before,
                data_after,
            } => {
                let name = SNAP_NAMES[*name_idx as usize % SNAP_NAMES.len()];
                let offset = *offset_raw as u64 % virtual_size;

                let before = match clamp_write(data_before, offset, virtual_size) {
                    Some((b, _)) => b,
                    None => continue,
                };
                let after = match clamp_write(data_after, offset, virtual_size) {
                    Some((a, _)) => a,
                    None => continue,
                };
                // Use the shorter length so both writes cover the same region
                let len = before.len().min(after.len());
                if len == 0 {
                    continue;
                }
                let before = &before[..len];
                let after = &after[..len];

                // 1. Write initial data
                if image.write_at(before, offset).is_err() {
                    continue;
                }
                // 2. Create snapshot (captures "before" state)
                if image.snapshot_create(name).is_err() {
                    continue;
                }
                // 3. Overwrite with different data
                if image.write_at(after, offset).is_err() {
                    continue;
                }
                // 4. Verify current state shows "after"
                let mut readback = vec![0u8; len];
                if image.read_at(&mut readback, offset).is_ok() {
                    assert_eq!(
                        after, &readback[..],
                        "post-write data mismatch at offset {offset}"
                    );
                }
                // 5. Revert to snapshot — should restore "before"
                if image.snapshot_apply(name).is_ok() {
                    let mut readback = vec![0u8; len];
                    if image.read_at(&mut readback, offset).is_ok() {
                        assert_eq!(
                            before, &readback[..],
                            "COW snapshot revert mismatch at offset {offset}"
                        );
                    }
                }
            }
            Op::Resize { new_size_raw } => {
                // 256 KB to 4 MB
                let new_size = ((*new_size_raw as u64 % 16) + 1) << 18;
                let _ = image.resize(new_size);
            }
        }
    }
});
