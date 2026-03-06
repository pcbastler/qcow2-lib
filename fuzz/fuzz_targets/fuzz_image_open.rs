#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::engine::image::Qcow2Image;
use qcow2::io::MemoryBackend;

fuzz_target!(|data: &[u8]| {
    let backend = Box::new(MemoryBackend::new(data.to_vec()));
    // Must never panic — Result::Err is fine.
    let _ = Qcow2Image::from_backend(backend);
});
