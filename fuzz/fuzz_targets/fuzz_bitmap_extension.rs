#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::format::bitmap::{
    BitmapDirectoryEntry, BitmapExtension, BitmapTable, BitmapTableEntry,
};
use qcow2::format::types::BitmapIndex;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0];
    let rest = &data[1..];

    match mode % 4 {
        // 0: BitmapExtension parse
        0 => {
            if let Ok(ext) = BitmapExtension::read_from(rest) {
                let written = ext.write_to();
                let reparsed = BitmapExtension::read_from(&written).unwrap();
                assert_eq!(ext.nb_bitmaps, reparsed.nb_bitmaps);
                assert_eq!(ext.bitmap_directory_offset, reparsed.bitmap_directory_offset);
                assert_eq!(ext.bitmap_directory_size, reparsed.bitmap_directory_size);
            }
        }
        // 1: BitmapDirectoryEntry parse
        1 => {
            let _ = BitmapDirectoryEntry::read_from(rest, 0);
        }
        // 2: BitmapDirectoryEntry read_directory
        2 => {
            if rest.is_empty() {
                return;
            }
            let count = (rest[0] as u32).min(16);
            let _ = BitmapDirectoryEntry::read_directory(&rest[1..], count);
        }
        // 3: BitmapTable parse round-trip
        _ => {
            if rest.is_empty() {
                return;
            }
            let entry_count = (rest[0] as u32).min(128);
            let table_data = &rest[1..];
            if let Ok(table) = BitmapTable::read_from(table_data, entry_count) {
                let mut buf = vec![0u8; table.len() as usize * 8];
                if table.write_to(&mut buf).is_ok() {
                    let reparsed = BitmapTable::read_from(&buf, entry_count).unwrap();
                    for i in 0..table.len() {
                        let idx = BitmapIndex(i);
                        let a = table.get(idx).unwrap();
                        let b = reparsed.get(idx).unwrap();
                        assert_eq!(a.raw(), b.raw());
                    }
                }
            }
        }
    }
});
