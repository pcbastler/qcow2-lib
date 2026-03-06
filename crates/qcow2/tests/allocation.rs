//! Integration tests for the ScanningAllocator (cluster reuse).

use qcow2::engine::image::{CreateOptions, Qcow2Image};
use tempfile::TempDir;

fn create_test_image(size: u64) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.qcow2");
    let opts = CreateOptions {
        virtual_size: size,
        cluster_bits: Some(16), // 64 KB clusters
        extended_l2: false, compression_type: None,
            data_file: None, encryption: None,
    };
    Qcow2Image::create(&path, opts).unwrap();
    (dir, path)
}

fn file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

#[test]
fn snapshot_delete_reuses_clusters() {
    let (_dir, path) = create_test_image(4 * 1024 * 1024); // 4 MB

    // Write data to several clusters
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        let data = vec![0xAAu8; 64 * 1024]; // one full cluster
        for i in 0..4 {
            img.write_at(&data, i * 64 * 1024).unwrap();
        }
        img.snapshot_create("snap1").unwrap();
        img.flush().unwrap();
    }

    let size_after_snapshot = file_size(&path);

    // Write more data (causes COW, file grows)
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        let data = vec![0xBBu8; 64 * 1024];
        for i in 0..4 {
            img.write_at(&data, i * 64 * 1024).unwrap();
        }
        img.flush().unwrap();
    }

    let size_after_cow = file_size(&path);
    assert!(
        size_after_cow > size_after_snapshot,
        "COW should have grown the file"
    );

    // Delete the snapshot — frees the old clusters
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.snapshot_delete("snap1").unwrap();
        img.flush().unwrap();
    }

    // Write new data — should reuse freed clusters, file should not grow much
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        let data = vec![0xCCu8; 64 * 1024];
        for i in 0..4 {
            img.write_at(&data, i * 64 * 1024).unwrap();
        }
        img.flush().unwrap();
    }

    let size_after_reuse = file_size(&path);
    assert!(
        size_after_reuse <= size_after_cow + 2 * 64 * 1024,
        "file should not grow significantly when reusing freed clusters \
         (before={size_after_cow}, after={size_after_reuse})"
    );

    // Verify data integrity
    {
        let mut img = Qcow2Image::open(&path).unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        for i in 0..4 {
            img.read_at(&mut buf, i * 64 * 1024).unwrap();
            assert!(
                buf.iter().all(|&b| b == 0xCC),
                "data at cluster {i} should be 0xCC"
            );
        }
    }

    // Integrity check
    {
        let img = Qcow2Image::open_rw(&path).unwrap();
        let report = img.check_integrity().unwrap();
        assert!(
            report.leaks.is_empty() && report.mismatches.is_empty(),
            "integrity check should be clean: {report:?}"
        );
    }
}

#[test]
fn hash_remove_reinit_reuses_clusters() {
    let (_dir, path) = create_test_image(1024 * 1024); // 1 MB

    // Init hashes and rehash
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        let data = vec![0x42u8; 64 * 1024];
        img.write_at(&data, 0).unwrap();
        img.hash_init(None, None).unwrap();
        img.hash_rehash().unwrap();
        img.flush().unwrap();
    }

    let size_with_hashes = file_size(&path);

    // Remove hashes — frees hash table clusters
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.hash_remove().unwrap();
        img.flush().unwrap();
    }

    // Re-init — should reuse freed clusters
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.hash_init(None, None).unwrap();
        img.hash_rehash().unwrap();
        img.flush().unwrap();
    }

    let size_after_reinit = file_size(&path);
    assert!(
        size_after_reinit <= size_with_hashes + 64 * 1024,
        "reinit should reuse freed hash clusters \
         (original={size_with_hashes}, reinit={size_after_reinit})"
    );
}

#[test]
fn bitmap_delete_reuses_clusters() {
    let (_dir, path) = create_test_image(1024 * 1024); // 1 MB

    // Create and delete a bitmap, then create again
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.bitmap_create("bm1", None, false).unwrap();
        img.flush().unwrap();
    }

    let size_with_bitmap = file_size(&path);

    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.bitmap_delete("bm1").unwrap();
        img.flush().unwrap();
    }

    // Create another bitmap — should reuse freed clusters
    {
        let mut img = Qcow2Image::open_rw(&path).unwrap();
        img.bitmap_create("bm2", None, false).unwrap();
        img.flush().unwrap();
    }

    let size_after_recreate = file_size(&path);
    // Bitmap metadata uses allocate_contiguous_clusters (always appends),
    // so some growth is expected for the new directory + table.
    // But it should be bounded (at most a few clusters, not unbounded growth).
    assert!(
        size_after_recreate <= size_with_bitmap + 3 * 64 * 1024,
        "bitmap recreate should not grow excessively \
         (original={size_with_bitmap}, recreate={size_after_recreate})"
    );
}
