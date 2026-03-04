//! Generates seed corpus files for each fuzz target.
//!
//! Run: `cargo run --bin build_corpus` (from the fuzz/ directory)

use std::fs;
use std::path::Path;

use qcow2_lib::engine::image::{CreateOptions, Qcow2Image};
use qcow2_lib::format::header_extension::{FeatureNameEntry, HeaderExtension};
use qcow2_lib::format::snapshot::SnapshotHeader;
use qcow2_lib::format::types::ClusterOffset;
use qcow2_lib::io::MemoryBackend;

fn main() {
    build_image_open_corpus();
    build_header_extensions_corpus();
    build_snapshot_table_corpus();
    build_refcount_block_corpus();
    println!("Seed corpus generated.");
}

fn build_image_open_corpus() {
    let dir = Path::new("corpus/fuzz_image_open");
    fs::create_dir_all(dir).unwrap();

    // Minimal v3 image with small clusters (4KB) to keep seed small
    let backend = Box::new(MemoryBackend::zeroed(0));
    let image = Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size: 1 << 20, // 1 MB
            cluster_bits: Some(12), // 4KB clusters
            extended_l2: false, compression_type: None,
        },
    )
    .unwrap();
    let data = read_backend_data(image.backend());
    fs::write(dir.join("minimal_v3_4k.qcow2"), &data).unwrap();
    println!("  fuzz_image_open: {} bytes", data.len());

    // Default cluster size (64KB)
    let backend = Box::new(MemoryBackend::zeroed(0));
    let image = Qcow2Image::create_on_backend(
        backend,
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false, compression_type: None,
        },
    )
    .unwrap();
    let data = read_backend_data(image.backend());
    fs::write(dir.join("minimal_v3_64k.qcow2"), &data).unwrap();
    println!("  fuzz_image_open: {} bytes (64KB clusters)", data.len());
}

fn build_header_extensions_corpus() {
    let dir = Path::new("corpus/fuzz_header_extensions");
    fs::create_dir_all(dir).unwrap();

    // Single backing file format extension
    let exts = vec![HeaderExtension::BackingFileFormat("raw".to_string())];
    let data = HeaderExtension::write_all(&exts);
    fs::write(dir.join("backing_format.bin"), &data).unwrap();

    // Feature name table
    let exts = vec![HeaderExtension::FeatureNameTable(vec![
        FeatureNameEntry {
            feature_type: 0,
            bit_number: 0,
            name: "dirty bit".to_string(),
        },
        FeatureNameEntry {
            feature_type: 2,
            bit_number: 0,
            name: "bitmaps".to_string(),
        },
    ])];
    let data = HeaderExtension::write_all(&exts);
    fs::write(dir.join("feature_names.bin"), &data).unwrap();

    // Multiple extensions combined
    let exts = vec![
        HeaderExtension::BackingFileFormat("qcow2".to_string()),
        HeaderExtension::FeatureNameTable(vec![FeatureNameEntry {
            feature_type: 0,
            bit_number: 0,
            name: "dirty bit".to_string(),
        }]),
    ];
    let data = HeaderExtension::write_all(&exts);
    fs::write(dir.join("multi_extension.bin"), &data).unwrap();

    // Empty extensions (just end marker)
    let data = HeaderExtension::write_all(&[]);
    fs::write(dir.join("empty.bin"), &data).unwrap();

    println!("  fuzz_header_extensions: 4 seeds");
}

fn build_snapshot_table_corpus() {
    let dir = Path::new("corpus/fuzz_snapshot_table");
    fs::create_dir_all(dir).unwrap();

    // Single minimal snapshot
    let snap = SnapshotHeader {
        l1_table_offset: ClusterOffset(0x10000),
        l1_table_entries: 4,
        unique_id: "1".to_string(),
        name: "test-snap".to_string(),
        timestamp_seconds: 1700000000,
        timestamp_nanoseconds: 0,
        vm_clock_nanoseconds: 0,
        vm_state_size: 0,
        virtual_disk_size: Some(1 << 20),
        hash_table_offset: None,
        hash_table_entries: None,
        hash_size: None,
        hash_chunk_bits: None,
        extra_data_size: 16,
    };
    let mut data = Vec::new();
    snap.write_to(&mut data);
    fs::write(dir.join("single_snapshot.bin"), &data).unwrap();

    // Two snapshots (for read_table fuzzing — prefixed with count byte)
    let snap2 = SnapshotHeader {
        unique_id: "2".to_string(),
        name: "second-snap".to_string(),
        ..snap.clone()
    };
    let mut data = vec![2u8]; // count byte
    snap.write_to(&mut data);
    snap2.write_to(&mut data);
    fs::write(dir.join("two_snapshots.bin"), &data).unwrap();

    // Snapshot with BLAKE3 hash data in extra_data
    let snap_hash = SnapshotHeader {
        hash_table_offset: Some(0x20000),
        hash_table_entries: Some(16),
        hash_size: Some(32),
        hash_chunk_bits: Some(16),
        extra_data_size: 32,
        ..snap.clone()
    };
    let mut data = Vec::new();
    snap_hash.write_to(&mut data);
    fs::write(dir.join("snapshot_with_hashes.bin"), &data).unwrap();

    println!("  fuzz_snapshot_table: 3 seeds");
}

fn build_refcount_block_corpus() {
    let dir = Path::new("corpus/fuzz_refcount_block");
    fs::create_dir_all(dir).unwrap();

    // Generate a seed for each refcount_order (0–6)
    for order in 0..7u32 {
        let entry_bits = 1u32 << order;
        let entry_count = 64u32; // 64 entries
        let total_bits = entry_count * entry_bits;
        let byte_count = ((total_bits + 7) / 8) as usize;

        // Fill with a simple pattern
        let block_data: Vec<u8> = (0..byte_count).map(|i| (i % 256) as u8).collect();

        // Prefix with order byte (as the fuzz target expects)
        let mut seed = vec![order as u8];
        seed.extend_from_slice(&block_data);
        fs::write(dir.join(format!("order_{order}.bin")), &seed).unwrap();
    }

    println!("  fuzz_refcount_block: 7 seeds");
}

fn read_backend_data(backend: &dyn qcow2_lib::io::IoBackend) -> Vec<u8> {
    let size = backend.file_size().unwrap() as usize;
    let mut data = vec![0u8; size];
    backend.read_exact_at(&mut data, 0).unwrap();
    data
}
