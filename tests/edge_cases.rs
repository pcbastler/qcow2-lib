//! Edge cases and boundary condition tests.
//!
//! Tests boundary reads/writes, size extremes, data patterns, repeated
//! operations, and overflow prevention.

mod common;

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use qcow2::io::MemoryBackend;

const CS: usize = 65536;
const CSU: u64 = CS as u64;

fn create_mem(vs: u64) -> Qcow2Image {
    Qcow2Image::create_on_backend(
        Box::new(MemoryBackend::zeroed(0)),
        CreateOptions {
            virtual_size: vs,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        },
    )
    .unwrap()
}

// =====================================================================
// 1. Boundary reads
// =====================================================================

#[test]
fn read_first_byte() {
    let mut image = create_mem(1 << 20);
    let mut buf = [0xFFu8; 1];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf[0], 0);
}

#[test]
fn read_last_byte() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    let mut buf = [0xFFu8; 1];
    image.read_at(&mut buf, vs - 1).unwrap();
    assert_eq!(buf[0], 0);
}

#[test]
fn read_beyond_virtual_size_fails() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    let mut buf = [0u8; 1];
    assert!(image.read_at(&mut buf, vs).is_err());
}

#[test]
fn read_spanning_end_of_disk_fails() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    let mut buf = [0u8; 512];
    assert!(image.read_at(&mut buf, vs - 256).is_err());
}

#[test]
fn read_zero_bytes() {
    let mut image = create_mem(1 << 20);
    let mut buf = [];
    image.read_at(&mut buf, 0).unwrap(); // should be a no-op
}

// =====================================================================
// 2. Boundary writes
// =====================================================================

#[test]
fn write_first_byte() {
    let mut image = create_mem(1 << 20);
    image.write_at(&[0xAA], 0).unwrap();
    let mut buf = [0u8; 1];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf[0], 0xAA);
}

#[test]
fn write_last_byte() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    image.write_at(&[0xBB], vs - 1).unwrap();
    let mut buf = [0u8; 1];
    image.read_at(&mut buf, vs - 1).unwrap();
    assert_eq!(buf[0], 0xBB);
}

#[test]
fn write_beyond_virtual_size_fails() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    assert!(image.write_at(&[0xAA], vs).is_err());
}

#[test]
fn write_spanning_end_fails() {
    let vs = 1u64 << 20;
    let mut image = create_mem(vs);
    assert!(image.write_at(&[0xAA; 512], vs - 256).is_err());
}

// =====================================================================
// 3. Exactly cluster-aligned operations
// =====================================================================

#[test]
fn write_read_exactly_one_cluster() {
    let mut image = create_mem(CSU);
    let data = vec![0xCC; CS];
    image.write_at(&data, 0).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn read_exactly_at_cluster_boundary() {
    let mut image = create_mem(4 * CSU);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.write_at(&vec![0xBB; CS], CSU).unwrap();

    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0xBB));
}

// =====================================================================
// 4. Data patterns
// =====================================================================

#[test]
fn all_byte_values_roundtrip() {
    let mut image = create_mem(1 << 20);
    let data: Vec<u8> = (0..=255).collect();
    image.write_at(&data, 0).unwrap();
    let mut buf = vec![0u8; 256];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn alternating_bits_pattern() {
    let mut image = create_mem(1 << 20);
    let data = vec![0xAA; CS]; // 10101010
    image.write_at(&data, 0).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);

    let data = vec![0x55; CS]; // 01010101
    image.write_at(&data, CSU).unwrap();
    image.read_at(&mut buf, CSU).unwrap();
    assert_eq!(buf, data);
}

#[test]
fn sequential_byte_pattern() {
    let mut image = create_mem(1 << 20);
    let data: Vec<u8> = (0..CS).map(|i| (i & 0xFF) as u8).collect();
    image.write_at(&data, 0).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data);
}

// =====================================================================
// 5. Repeated operations
// =====================================================================

#[test]
fn overwrite_same_cluster_100_times() {
    let mut image = create_mem(1 << 20);
    for i in 0u8..100 {
        image.write_at(&vec![i; CS], 0).unwrap();
    }
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 99));
}

#[test]
fn alternate_read_write_many_times() {
    let mut image = create_mem(1 << 20);
    let mut buf = vec![0u8; 512];

    for i in 0u8..50 {
        image.write_at(&vec![i; 512], 0).unwrap();
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == i), "iteration {i}");
    }
}

// =====================================================================
// 6. Sparse access patterns
// =====================================================================

#[test]
fn sparse_write_scattered_clusters() {
    let vs = 256 * CSU;
    let mut image = create_mem(vs);

    // Write to clusters 0, 50, 100, 200
    let offsets = [0, 50, 100, 200];
    for &idx in &offsets {
        let data = vec![(idx as u8) | 0x80; CS];
        image.write_at(&data, idx as u64 * CSU).unwrap();
    }

    for &idx in &offsets {
        let mut buf = vec![0u8; CS];
        image.read_at(&mut buf, idx as u64 * CSU).unwrap();
        assert!(buf.iter().all(|&b| b == (idx as u8) | 0x80), "cluster {idx}");
    }

    // Unwritten cluster should be zeros
    let mut buf = vec![0xFFu8; CS];
    image.read_at(&mut buf, 25 * CSU).unwrap();
    assert!(buf.iter().all(|&b| b == 0x00));
}

// =====================================================================
// 7. Small reads/writes
// =====================================================================

#[test]
fn write_single_sector() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xDD; 512], 0).unwrap();
    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xDD));
}

#[test]
fn write_4096_bytes_aligned() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xEE; 4096], 0).unwrap();
    let mut buf = vec![0u8; 4096];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xEE));
}

#[test]
fn write_odd_size() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0x77; 7777], 0).unwrap();
    let mut buf = vec![0u8; 7777];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77));
}

// =====================================================================
// 8. Cross-cluster reads/writes
// =====================================================================

#[test]
fn read_spanning_three_clusters() {
    let mut image = create_mem(4 * CSU);
    image.write_at(&vec![0x11; CS], 0).unwrap();
    image.write_at(&vec![0x22; CS], CSU).unwrap();
    image.write_at(&vec![0x33; CS], 2 * CSU).unwrap();

    let start = CSU / 2;
    let len = 2 * CS;
    let mut buf = vec![0u8; len];
    image.read_at(&mut buf, start).unwrap();

    let half = CS / 2;
    assert!(buf[..half].iter().all(|&b| b == 0x11));
    assert!(buf[half..half + CS].iter().all(|&b| b == 0x22));
    assert!(buf[half + CS..].iter().all(|&b| b == 0x33));
}

#[test]
fn write_spanning_four_clusters() {
    let mut image = create_mem(8 * CSU);
    for i in 0..4u64 {
        image.write_at(&vec![(i as u8 + 1) * 0x10; CS], i * CSU).unwrap();
    }

    // Write across all 4 clusters
    let start = CSU / 4;
    let len = 3 * CS + CS / 2;
    image.write_at(&vec![0xFF; len], start).unwrap();

    let mut buf = vec![0u8; CS];
    // First quarter of cluster 0: original
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..CS / 4].iter().all(|&b| b == 0x10));
    assert!(buf[CS / 4..].iter().all(|&b| b == 0xFF));
}

// =====================================================================
// 9. Virtual size edge cases
// =====================================================================

#[test]
fn virtual_size_exactly_cluster_size() {
    let mut image = create_mem(CSU);
    assert_eq!(image.virtual_size(), CSU);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn virtual_size_one_byte_more_than_cluster() {
    let vs = CSU + 1;
    let mut image = create_mem(vs);
    image.write_at(&[0xBB], CSU).unwrap();
    let mut buf = [0u8; 1];
    image.read_at(&mut buf, CSU).unwrap();
    assert_eq!(buf[0], 0xBB);
}

// =====================================================================
// 10. Flush
// =====================================================================

#[test]
fn flush_idempotent() {
    let mut image = create_mem(1 << 20);
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.flush().unwrap();
    image.flush().unwrap(); // double flush
    let mut buf = vec![0u8; CS];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn flush_empty_image() {
    let mut image = create_mem(1 << 20);
    image.flush().unwrap(); // flush without writes
}

// =====================================================================
// 11. Integrity edge cases
// =====================================================================

#[test]
fn integrity_check_sparse_image() {
    let mut image = create_mem(256 * CSU);
    // Write to scattered clusters only
    image.write_at(&vec![0xAA; CS], 0).unwrap();
    image.write_at(&vec![0xBB; CS], 100 * CSU).unwrap();
    image.write_at(&vec![0xCC; CS], 200 * CSU).unwrap();
    image.flush().unwrap();

    let report = image.check_integrity().unwrap();
    assert!(report.is_clean());
}
