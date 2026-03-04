#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2_lib::format::refcount::RefcountBlock;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects refcount_order (0–6)
    let order = (data[0] % 7) as u32;
    let block_data = &data[1..];

    if let Ok(block) = RefcountBlock::read_from(block_data, order) {
        // Round-trip: parse → serialize → re-parse → verify equivalence
        let mut buf = vec![0u8; block_data.len()];
        if block.write_to(&mut buf).is_ok() {
            let reparsed = RefcountBlock::read_from(&buf, order).unwrap();
            for i in 0..block.len() {
                assert_eq!(block.get(i).unwrap(), reparsed.get(i).unwrap());
            }
        }
    }
});
