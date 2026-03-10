//! Benchmarks comparing QCOW2 I/O overhead against raw file I/O.
//!
//! Measures the per-operation cost of the QCOW2 metadata layer (L2 lookups,
//! refcount updates, cache evictions) relative to direct pread/pwrite syscalls.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use tempfile::{NamedTempFile, TempDir};

use qcow2::engine::image::{CreateOptions, Qcow2Image};

const CLUSTER_SIZE: usize = 65536; // 64 KB (cluster_bits = 16)

fn default_opts(virtual_size: u64) -> CreateOptions {
    CreateOptions {
        virtual_size,
        cluster_bits: None,
        extended_l2: false,
        compression_type: None,
        data_file: None,
        encryption: None,
    }
}

/// Create a fresh QCOW2 image in a temp directory, opened read-write.
fn create_qcow2(virtual_size: u64) -> (TempDir, Qcow2Image) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.qcow2");
    let image = Qcow2Image::create(&path, default_opts(virtual_size)).unwrap();
    (dir, image)
}

/// Create a pre-allocated raw file of `size` bytes.
fn create_raw(size: u64) -> (NamedTempFile, File) {
    let tmp = NamedTempFile::new().unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();
    file.set_len(size).unwrap();
    (tmp, file)
}

// ---------------------------------------------------------------------------
// Sequential write benchmarks
// ---------------------------------------------------------------------------

fn bench_sequential_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_write");

    for &size in &[1 << 20, 5 << 20, 10 << 20] {
        let label = format!("{}MB", size >> 20);
        group.throughput(Throughput::Bytes(size as u64));

        // Raw baseline: sequential pwrite in 64KB chunks
        group.bench_with_input(BenchmarkId::new("raw", &label), &size, |b, &size| {
            let (_tmp, file) = create_raw(size as u64);
            let chunk = vec![0xAAu8; CLUSTER_SIZE];
            b.iter(|| {
                let mut offset = 0u64;
                while offset < size as u64 {
                    file.write_all_at(&chunk, offset).unwrap();
                    offset += CLUSTER_SIZE as u64;
                }
                file.sync_data().unwrap();
            });
        });

        // QCOW2: sequential write_at in 64KB chunks
        group.bench_with_input(BenchmarkId::new("qcow2", &label), &size, |b, &size| {
            b.iter_with_setup(
                || create_qcow2(size as u64),
                |(_tmp, mut image)| {
                    let chunk = vec![0xAAu8; CLUSTER_SIZE];
                    let mut offset = 0u64;
                    while offset < size as u64 {
                        image.write_at(&chunk, offset).unwrap();
                        offset += CLUSTER_SIZE as u64;
                    }
                    image.flush().unwrap();
                },
            );
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Sequential read benchmarks (pre-written data)
// ---------------------------------------------------------------------------

fn bench_sequential_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_read");

    for &size in &[1 << 20, 5 << 20, 10 << 20] {
        let label = format!("{}MB", size >> 20);
        group.throughput(Throughput::Bytes(size as u64));

        // Raw baseline
        group.bench_with_input(BenchmarkId::new("raw", &label), &size, |b, &size| {
            let (_tmp, file) = create_raw(size as u64);
            // Pre-write data
            let chunk = vec![0xBBu8; CLUSTER_SIZE];
            let mut off = 0u64;
            while off < size as u64 {
                file.write_all_at(&chunk, off).unwrap();
                off += CLUSTER_SIZE as u64;
            }
            let mut buf = vec![0u8; CLUSTER_SIZE];
            b.iter(|| {
                let mut offset = 0u64;
                while offset < size as u64 {
                    file.read_exact_at(&mut buf, offset).unwrap();
                    black_box(&buf);
                    offset += CLUSTER_SIZE as u64;
                }
            });
        });

        // QCOW2: read pre-written data
        group.bench_with_input(BenchmarkId::new("qcow2", &label), &size, |b, &size| {
            // Create and pre-fill once
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("test.qcow2");
            {
                let mut image =
                    Qcow2Image::create(&path, default_opts(size as u64)).unwrap();
                let chunk = vec![0xBBu8; CLUSTER_SIZE];
                let mut off = 0u64;
                while off < size as u64 {
                    image.write_at(&chunk, off).unwrap();
                    off += CLUSTER_SIZE as u64;
                }
                image.flush().unwrap();
            }

            let mut image = Qcow2Image::open_rw(&path).unwrap();
            let mut buf = vec![0u8; CLUSTER_SIZE];
            b.iter(|| {
                let mut offset = 0u64;
                while offset < size as u64 {
                    image.read_at(&mut buf, offset).unwrap();
                    black_box(&buf);
                    offset += CLUSTER_SIZE as u64;
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Small-write benchmark (sub-cluster writes, worst case for metadata overhead)
// ---------------------------------------------------------------------------

fn bench_small_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_write_4KB");

    let total: usize = 1 << 20; // 1 MB total
    let chunk_size: usize = 4096; // 4 KB per write
    group.throughput(Throughput::Bytes(total as u64));

    // Raw: 4KB writes
    group.bench_function("raw", |b| {
        let (_tmp, file) = create_raw(total as u64);
        let chunk = vec![0xCCu8; chunk_size];
        b.iter(|| {
            let mut offset = 0u64;
            while offset < total as u64 {
                file.write_all_at(&chunk, offset).unwrap();
                offset += chunk_size as u64;
            }
            file.sync_data().unwrap();
        });
    });

    // QCOW2: 4KB writes — many writes per cluster → repeated L2 lookups
    group.bench_function("qcow2", |b| {
        b.iter_with_setup(
            || create_qcow2(total as u64),
            |(_tmp, mut image)| {
                let chunk = vec![0xCCu8; chunk_size];
                let mut offset = 0u64;
                while offset < total as u64 {
                    image.write_at(&chunk, offset).unwrap();
                    offset += chunk_size as u64;
                }
                image.flush().unwrap();
            },
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Overwrite benchmark (writing to already-allocated clusters)
// ---------------------------------------------------------------------------

fn bench_overwrite(c: &mut Criterion) {
    let mut group = c.benchmark_group("overwrite");

    let size: usize = 5 << 20; // 5 MB
    group.throughput(Throughput::Bytes(size as u64));

    // Raw
    group.bench_function("raw", |b| {
        let (_tmp, file) = create_raw(size as u64);
        let chunk = vec![0xDDu8; CLUSTER_SIZE];
        // Pre-fill
        let mut off = 0u64;
        while off < size as u64 {
            file.write_all_at(&chunk, off).unwrap();
            off += CLUSTER_SIZE as u64;
        }
        b.iter(|| {
            let mut offset = 0u64;
            while offset < size as u64 {
                file.write_all_at(&chunk, offset).unwrap();
                offset += CLUSTER_SIZE as u64;
            }
            file.sync_data().unwrap();
        });
    });

    // QCOW2: overwrite already-allocated clusters (no new allocation needed)
    group.bench_function("qcow2", |b| {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.qcow2");
        {
            let mut image =
                Qcow2Image::create(&path, default_opts(size as u64)).unwrap();
            let chunk = vec![0xDDu8; CLUSTER_SIZE];
            let mut off = 0u64;
            while off < size as u64 {
                image.write_at(&chunk, off).unwrap();
                off += CLUSTER_SIZE as u64;
            }
            image.flush().unwrap();
        }

        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let chunk = vec![0xEEu8; CLUSTER_SIZE];
        b.iter(|| {
            let mut offset = 0u64;
            while offset < size as u64 {
                image.write_at(&chunk, offset).unwrap();
                offset += CLUSTER_SIZE as u64;
            }
            image.flush().unwrap();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Cache statistics report (not a timed benchmark, just diagnostic output)
// ---------------------------------------------------------------------------

fn bench_cache_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_pressure");

    let size: usize = 10 << 20; // 10 MB
    group.throughput(Throughput::Bytes(size as u64));
    group.sample_size(10);

    group.bench_function("write_10MB_fresh", |b| {
        b.iter_with_setup(
            || {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("test.qcow2");
                let image =
                    Qcow2Image::create(&path, default_opts(size as u64)).unwrap();
                (dir, image)
            },
            |(_dir, mut image)| {
                let chunk = vec![0xAAu8; CLUSTER_SIZE];
                let mut offset = 0u64;
                while offset < size as u64 {
                    image.write_at(&chunk, offset).unwrap();
                    offset += CLUSTER_SIZE as u64;
                }
                image.flush().unwrap();

                // Print cache stats for diagnostics
                let stats = image.cache_stats();
                eprintln!(
                    "  L2 hits={}, misses={}, refcount hits={}, misses={}",
                    stats.l2_hits, stats.l2_misses,
                    stats.refcount_hits, stats.refcount_misses,
                );
            },
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// WriteBack vs WriteThrough comparison
// ---------------------------------------------------------------------------

fn bench_cache_mode_comparison(c: &mut Criterion) {
    use qcow2::CacheMode;

    let mut group = c.benchmark_group("cache_mode");

    for &size in &[5usize << 20, 500 << 20] {
        let label_mb = size >> 20;
        group.throughput(Throughput::Bytes(size as u64));
        if size >= 100 << 20 {
            group.sample_size(10);
        }

        for &(mode_label, mode) in &[
            ("write_back", CacheMode::WriteBack),
            ("write_through", CacheMode::WriteThrough),
        ] {
            group.bench_function(
                BenchmarkId::new(mode_label, format!("{}MB", label_mb)),
                |b| {
                    b.iter_with_setup(
                        || {
                            let (dir, mut image) = create_qcow2(size as u64);
                            image.set_cache_mode(mode).unwrap();
                            (dir, image)
                        },
                        |(_dir, mut image)| {
                            let chunk = vec![0xAAu8; CLUSTER_SIZE];
                            let mut offset = 0u64;
                            while offset < size as u64 {
                                image.write_at(&chunk, offset).unwrap();
                                offset += CLUSTER_SIZE as u64;
                            }
                            image.flush().unwrap();
                        },
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_write,
    bench_sequential_read,
    bench_small_writes,
    bench_overwrite,
    bench_cache_pressure,
    bench_cache_mode_comparison,
);
criterion_main!(benches);
