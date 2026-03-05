#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::io::MemoryBackend;

/// Fuzz engine operations with extended L2 entries enabled.
/// Complements fuzz_engine_ops which only tests standard L2.

#[derive(Arbitrary, Debug)]
struct ImageConfig {
    cluster_bits_raw: u8,
    virtual_size_raw: u8,
    use_zstd: bool,
}

impl ImageConfig {
    fn cluster_bits(&self) -> u32 {
        // Valid range: 12 (4KB) to 16 (64KB)
        12 + (self.cluster_bits_raw % 5) as u32
    }
    fn virtual_size(&self) -> u64 {
        ((self.virtual_size_raw % 8) as u64 + 1) << 18 // 256KB–2MB
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    /// Write a subcluster-sized chunk.
    WriteSubcluster { offset_raw: u32, pattern: u8 },
    /// Write a full cluster.
    WriteCluster { offset_raw: u32, pattern: u8 },
    /// Read and verify a previous write.
    Read { offset_raw: u32, len_raw: u16 },
    /// Write then verify round-trip.
    WriteAndVerify { offset_raw: u32, data: Vec<u8> },
    /// Snapshot lifecycle.
    SnapshotCreate { name_idx: u8 },
    SnapshotApply { name_idx: u8 },
    SnapshotDelete { name_idx: u8 },
    /// Integrity check.
    CheckIntegrity,
}

const SNAP_NAMES: &[&str] = &["s0", "s1", "s2", "s3"];

fuzz_target!(|input: (ImageConfig, Vec<Op>)| {
    let (config, ops) = input;
    let max_ops = 32;
    let ops = if ops.len() > max_ops { &ops[..max_ops] } else { &ops };

    let virtual_size = config.virtual_size();
    let cluster_bits = config.cluster_bits();
    let cluster_size = 1u64 << cluster_bits;
    let sc_size = (cluster_size / 32) as usize;

    let comp_type = if config.use_zstd { Some(1u8) } else { None };

    let backend = Box::new(MemoryBackend::zeroed(0));
    let mut image = match Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: true,
            compression_type: comp_type,
            data_file: None,
            encryption: None,
        },
    ) {
        Ok(img) => img,
        Err(_) => return,
    };

    for op in ops {
        match op {
            Op::WriteSubcluster { offset_raw, pattern } => {
                let offset = (*offset_raw as u64) % virtual_size;
                let len = sc_size.min((virtual_size - offset) as usize);
                if len > 0 {
                    let _ = image.write_at(&vec![*pattern; len], offset);
                }
            }
            Op::WriteCluster { offset_raw, pattern } => {
                let offset = ((*offset_raw as u64) % virtual_size) & !(cluster_size - 1);
                let len = (cluster_size as usize).min((virtual_size - offset) as usize);
                if len > 0 {
                    let _ = image.write_at(&vec![*pattern; len], offset);
                }
            }
            Op::Read { offset_raw, len_raw } => {
                let len = (*len_raw as usize).min(cluster_size as usize).max(1);
                let offset = (*offset_raw as u64) % virtual_size;
                let actual_len = len.min((virtual_size - offset) as usize);
                if actual_len > 0 {
                    let mut buf = vec![0u8; actual_len];
                    let _ = image.read_at(&mut buf, offset);
                }
            }
            Op::WriteAndVerify { offset_raw, data } => {
                if data.is_empty() || data.len() > cluster_size as usize {
                    continue;
                }
                let offset = (*offset_raw as u64) % virtual_size;
                let len = data.len().min((virtual_size - offset) as usize);
                if len == 0 {
                    continue;
                }
                let buf = &data[..len];
                if image.write_at(buf, offset).is_ok() {
                    let mut readback = vec![0u8; len];
                    if image.read_at(&mut readback, offset).is_ok() {
                        assert_eq!(buf, &readback[..], "mismatch at {offset}");
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
            Op::CheckIntegrity => {
                let _ = image.check_integrity();
            }
        }
    }
});
