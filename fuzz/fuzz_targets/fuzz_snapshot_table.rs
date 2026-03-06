#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::format::snapshot::SnapshotHeader;

fuzz_target!(|data: &[u8]| {
    // Single snapshot entry
    let _ = SnapshotHeader::read_from(data, 0);

    // Multi-entry table: first byte selects count (capped at 32)
    if let Some((&count_byte, rest)) = data.split_first() {
        let count = (count_byte as u32).min(32);
        let _ = SnapshotHeader::read_table(rest, count, 0);
    }
});
