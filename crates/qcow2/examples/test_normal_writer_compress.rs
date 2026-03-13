//! Generate a 13 TiB sparse QCOW2 image using the normal Qcow2Image writer.
//!
//! Writes the same data as `generate_13t` (BlockWriter) for comparison:
//! ~1500 small data blocks scattered across the 13 TiB address space,
//! plus 4 larger blocks (5-15 MB). No compression (normal writer doesn't
//! compress on write).
//!
//! Usage: cargo run --release --example test_normal_writer_compress -- [output_path]

use qcow2::engine::image::{CreateOptions, Qcow2Image};

const TIB: u64 = 1024 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const KIB: u64 = 1024;

/// Same PRNG and workload as generate_13t — must stay in sync.
mod workload {
    use super::*;

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
        (1 * TIB + 100 * MIB, 15 * MIB, 0),
        (4 * TIB + 500 * MIB, 8 * MIB, 1),
        (9 * TIB, 5 * MIB, 2),
        (12 * TIB + 800 * MIB, 10 * MIB, 1),
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
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test-normal-writer-compress.qcow2".to_string());

    let virtual_size = 13 * TIB;

    println!("Creating {path} with normal Qcow2Image writer (13 TiB) ...");

    let mut image = Qcow2Image::create(
        &path,
        CreateOptions {
            virtual_size,
            cluster_bits: Some(16),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .expect("create failed");

    let mut rng = workload::Rng(workload::SEED);

    // ── 1. Scatter ~1500 small writes ────────────────────────────────
    println!("Writing ~1500 small blocks ...");
    for i in 0..workload::NUM_SMALL {
        let Some(offset) = workload::small_block_offset(i, virtual_size, &mut rng) else {
            continue;
        };
        let data = workload::small_block_data(i, &mut rng);
        image.write_at(&data, offset).unwrap();
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
        // Write in 64 KiB chunks (normal writer doesn't buffer internally)
        let chunk = 64 * KIB;
        let mut pos = 0u64;
        while pos < data.len() as u64 {
            let end = (pos + chunk).min(data.len() as u64) as usize;
            image.write_at(&data[pos as usize..end], offset + pos).unwrap();
            pos += chunk;
        }
    }

    println!("Flushing ...");
    image.flush().unwrap();
    drop(image);

    // ── 3. Read back and verify ──────────────────────────────────────
    println!("\nReading back ...");
    let mut image = Qcow2Image::open(&path).unwrap();

    // Spot-check a few offsets
    let check_offsets: Vec<(u64, &str)> = workload::LARGE_POSITIONS
        .iter()
        .map(|&(o, _, _)| {
            let label = match o {
                o if o < TIB => "< 1 TiB",
                o if o < 2 * TIB => "~1.1 TiB",
                o if o < 5 * TIB => "~4.5 TiB",
                o if o < 10 * TIB => "~9 TiB",
                _ => "~12.8 TiB",
            };
            (o, label)
        })
        .collect();

    for (offset, label) in &check_offsets {
        let mut buf = vec![0u8; 512];
        match image.read_at(&mut buf, *offset) {
            Ok(()) => {
                let nonzero = buf.iter().filter(|&&b| b != 0).count();
                println!(
                    "  {label}: OK, {nonzero}/512 non-zero, first 16: {:02x?}",
                    &buf[..16]
                );
            }
            Err(e) => {
                println!("  {label}: ERROR: {e}");
            }
        }
    }

    let meta = std::fs::metadata(&path).unwrap();
    println!(
        "\nDisk size: {:.1} MiB",
        meta.len() as f64 / MIB as f64
    );
}
