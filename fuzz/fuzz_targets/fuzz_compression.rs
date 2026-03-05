#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2_lib::engine::compression::{compress_cluster, decompress_cluster};
use qcow2_lib::format::constants::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0];
    let rest = &data[1..];

    match mode % 3 {
        // 0: Deflate compress → decompress round-trip
        0 => {
            // Use a realistic cluster size (4K, 8K, 16K, 32K, 64K)
            let cluster_sizes = [4096, 8192, 16384, 32768, 65536];
            let cs = cluster_sizes[(data[0] as usize / 3) % cluster_sizes.len()];

            // Pad or truncate input to cluster size
            let mut input = vec![0u8; cs];
            let copy_len = rest.len().min(cs);
            input[..copy_len].copy_from_slice(&rest[..copy_len]);

            if let Ok(Some(compressed)) = compress_cluster(&input, cs, COMPRESSION_DEFLATE) {
                let decompressed =
                    decompress_cluster(&compressed, cs, 0, COMPRESSION_DEFLATE).unwrap();
                assert_eq!(input, decompressed);
            }
        }
        // 1: Zstd compress → decompress round-trip
        1 => {
            let cluster_sizes = [4096, 8192, 16384, 32768, 65536];
            let cs = cluster_sizes[(data[0] as usize / 3) % cluster_sizes.len()];

            let mut input = vec![0u8; cs];
            let copy_len = rest.len().min(cs);
            input[..copy_len].copy_from_slice(&rest[..copy_len]);

            if let Ok(Some(compressed)) = compress_cluster(&input, cs, COMPRESSION_ZSTD) {
                let decompressed =
                    decompress_cluster(&compressed, cs, 0, COMPRESSION_ZSTD).unwrap();
                assert_eq!(input, decompressed);
            }
        }
        // 2: Decompress arbitrary data (must not panic)
        _ => {
            let comp_type = if rest.is_empty() {
                COMPRESSION_DEFLATE
            } else {
                rest[0] % 2 // 0 = deflate, 1 = zstd
            };
            let _ = decompress_cluster(rest, 65536, 0, comp_type);
        }
    }
});
