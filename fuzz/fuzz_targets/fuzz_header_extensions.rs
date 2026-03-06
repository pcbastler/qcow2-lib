#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::format::header_extension::HeaderExtension;

fuzz_target!(|data: &[u8]| {
    let _ = HeaderExtension::read_all(data);
});
