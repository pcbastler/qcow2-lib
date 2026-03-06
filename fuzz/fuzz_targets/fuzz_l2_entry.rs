#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::format::compressed::CompressedClusterDescriptor;
use qcow2::format::l2::{L2Entry, L2Table, SubclusterBitmap};
use qcow2::format::ClusterGeometry;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let mode = data[0];
    let rest = &data[1..];

    match mode % 5 {
        // 0: Decode/encode round-trip for standard L2 entries
        0 => {
            if rest.len() < 9 {
                return;
            }
            let raw = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let cluster_bits = 9 + (rest[8] % 13) as u32; // 9–21
            let entry = L2Entry::decode(raw, cluster_bits);
            let geo = ClusterGeometry { cluster_bits, extended_l2: false };
            let re_encoded = entry.encode(geo);
            let decoded_again = L2Entry::decode(re_encoded, cluster_bits);
            // Both decodes should produce the same variant
            assert_eq!(
                std::mem::discriminant(&entry),
                std::mem::discriminant(&decoded_again),
            );
        }
        // 1: Decode/encode round-trip for extended L2 entries
        1 => {
            if rest.len() < 17 {
                return;
            }
            let raw = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let bitmap_raw = u64::from_be_bytes(rest[8..16].try_into().unwrap());
            let cluster_bits = 9 + (rest[16] % 13) as u32;
            let entry = L2Entry::decode_extended(raw, bitmap_raw, cluster_bits, true);
            let geo = ClusterGeometry { cluster_bits, extended_l2: true };
            let re_encoded = entry.encode(geo);
            let re_bitmap = entry.encode_bitmap();
            let decoded_again =
                L2Entry::decode_extended(re_encoded, re_bitmap, cluster_bits, true);
            assert_eq!(
                std::mem::discriminant(&entry),
                std::mem::discriminant(&decoded_again),
            );
        }
        // 2: L2Table read/write round-trip
        2 => {
            if rest.is_empty() {
                return;
            }
            let cluster_bits = 9 + (rest[0] % 13) as u32;
            let table_data = &rest[1..];
            let geo = ClusterGeometry { cluster_bits, extended_l2: false };
            if let Ok(table) = L2Table::read_from(table_data, geo) {
                let mut buf = vec![0u8; table.len() as usize * 8];
                if table.write_to(&mut buf).is_ok() {
                    let reparsed = L2Table::read_from(&buf, geo).unwrap();
                    assert_eq!(table.len(), reparsed.len());
                }
            }
        }
        // 3: SubclusterBitmap operations
        3 => {
            if rest.len() < 8 {
                return;
            }
            let raw = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let bm = SubclusterBitmap(raw);
            let _ = bm.allocation_mask();
            let _ = bm.zero_mask();
            let _ = bm.is_all_allocated();
            let _ = bm.is_all_unallocated();
            let _ = bm.is_all_zero();
            let _ = bm.validate();
            for i in 0..32 {
                let _ = bm.get(i);
            }
        }
        // 4: CompressedClusterDescriptor round-trip
        _ => {
            if rest.len() < 9 {
                return;
            }
            let raw = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let cluster_bits = 9 + (rest[8] % 13) as u32;
            let desc = CompressedClusterDescriptor::decode(raw, cluster_bits);
            let re_encoded = desc.encode(cluster_bits);
            let desc2 = CompressedClusterDescriptor::decode(re_encoded, cluster_bits);
            assert_eq!(desc.host_offset, desc2.host_offset);
            assert_eq!(desc.compressed_size, desc2.compressed_size);
        }
    }
});
