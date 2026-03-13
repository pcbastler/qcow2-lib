//! Generate a 13 TiB sparse QCOW2 image using the BlockWriter.
//!
//! Writes the same data as `test_normal_writer_compress` for comparison:
//! ~1500 small data blocks scattered across the 13 TiB address space,
//! plus 4 larger blocks (5-15 MB), with compression enabled.
//!
//! Usage: cargo run --release --example generate_13t -- [output_path]

use std::io::{Seek, SeekFrom, Write};

use qcow2::engine::block_writer::BlockWriterOptions;
use qcow2::engine::image::CreateOptions;
use qcow2::Qcow2BlockWriter;

const TIB: u64 = 1024 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const KIB: u64 = 1024;

/// Shared write pattern for both BlockWriter and normal writer examples.
/// This module ensures both produce identical guest data for comparison.
mod workload {
    use super::*;

    /// Simple PRNG (xorshift64) — deterministic, no deps.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    pub const SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

    pub const LARGE_POSITIONS: &[(u64, u64, u8)] = &[
        (1 * TIB + 100 * MIB, 15 * MIB, 0), // 15 MB pseudo-random at ~1.1 TiB
        (4 * TIB + 500 * MIB, 8 * MIB, 1),   // 8 MB repeating text at ~4.5 TiB
        (9 * TIB, 5 * MIB, 2),                // 5 MB pattern at 9 TiB
        (12 * TIB + 800 * MIB, 10 * MIB, 1),  // 10 MB text near the end
    ];

    pub const NUM_SMALL: u64 = 1500;

    pub fn small_block_offset(i: u64, virtual_size: u64, rng: &mut Rng) -> Option<u64> {
        let slot_size = virtual_size / NUM_SMALL;
        let base = i * slot_size;
        let cluster_size = 64 * KIB;
        let max_clusters = slot_size / cluster_size;
        let cluster_idx = rng.next() % max_clusters.max(1);
        let offset = base + cluster_idx * cluster_size;
        if offset >= virtual_size { None } else { Some(offset) }
    }

    pub fn small_block_data(i: u64, rng: &mut Rng) -> Vec<u8> {
        match i % 5 {
            0 => {
                let text = format!(
                    "[section-{i}]\nkey = value_{i}\npath = /data/vol{i}\nenabled = true\n"
                );
                let mut buf = text.into_bytes();
                buf.resize(((rng.next() % 3 + 1) * KIB) as usize, b'\n');
                buf
            }
            1 => {
                let mut buf = Vec::new();
                let lines = 10 + (rng.next() % 40) as usize;
                for l in 0..lines {
                    let line = format!(
                        "2026-03-12T12:00:00+00:00 INFO  log entry {l} for service {i}\n"
                    );
                    buf.extend_from_slice(line.as_bytes());
                }
                buf
            }
            2 => {
                let len = (1 + rng.next() % 8) * KIB;
                (0..len).map(|j| ((rng.next() ^ j) & 0xFF) as u8).collect()
            }
            3 => {
                let text = format!(
                    "fn process_{i}() {{\n    let data = vec![0u8; {i}];\n    assert!(!data.is_empty());\n}}\n"
                );
                text.into_bytes()
            }
            _ => {
                let pattern = format!("BLOCK-{i:06}-");
                let pat_bytes = pattern.as_bytes();
                let len = ((rng.next() % 4 + 1) * KIB) as usize;
                pat_bytes.iter().copied().cycle().take(len).collect()
            }
        }
    }

    pub fn large_block_data(size: u64, kind: u8, rng: &mut Rng) -> Vec<u8> {
        match kind {
            0 => (0..size).map(|j| ((rng.next() ^ j) & 0xFF) as u8).collect(),
            1 => {
                let line = b"2026-03-12T12:00:00+00:00 INFO  access_log GET /api/v1/data 200 OK duration=42ms\n";
                line.iter().copied().cycle().take(size as usize).collect()
            }
            _ => {
                let pattern = b"DATA_BLOCK_PATTERN_0123456789ABCDEF";
                pattern.iter().copied().cycle().take(size as usize).collect()
            }
        }
    }
}

fn main() {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test-13t-blockwriter.qcow2".to_string());

    let virtual_size = 13 * TIB;

    println!("Creating {output} with BlockWriter (13 TiB, compressed) ...");

    let mut writer = Qcow2BlockWriter::create(
        &output,
        BlockWriterOptions {
            create: CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
            compress: true,
            memory_limit: Some(256 * MIB),
            hash_size: None,
        },
    )
    .expect("failed to create block writer");

    let mut rng = workload::Rng(workload::SEED);

    // ── 1. Scatter ~1500 small writes ────────────────────────────────
    println!("Writing ~1500 small blocks ...");
    for i in 0..workload::NUM_SMALL {
        let Some(offset) = workload::small_block_offset(i, virtual_size, &mut rng) else {
            continue;
        };
        let data = workload::small_block_data(i, &mut rng);
        writer.seek(SeekFrom::Start(offset)).unwrap();
        writer.write_all(&data).unwrap();
    }

    // ── 2. Larger blocks at specific positions ───────────────────────
    println!("Writing larger blocks ...");
    for &(offset, size, kind) in workload::LARGE_POSITIONS {
        println!(
            "  {:.1} TiB: {} MiB ({})",
            offset as f64 / TIB as f64,
            size / MIB,
            match kind { 0 => "binary", 1 => "text", _ => "pattern" }
        );
        let data = workload::large_block_data(size, kind, &mut rng);
        writer.seek(SeekFrom::Start(offset)).unwrap();
        writer.write_all(&data).unwrap();
    }

    // ── 3. Finalize ──────────────────────────────────────────────────
    println!("Finalizing ...");
    writer.finalize().expect("finalize failed");

    let meta = std::fs::metadata(&output).unwrap();
    println!(
        "Done: {output}\n  virtual size: 13 TiB\n  disk size:    {:.1} MiB",
        meta.len() as f64 / MIB as f64
    );
}
