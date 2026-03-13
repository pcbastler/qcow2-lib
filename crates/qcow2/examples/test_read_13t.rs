//! Read-back verification for test-13t-blockwriter.qcow2.
//!
//! Checks data at the same offsets written by generate_13t.

use qcow2::engine::image::Qcow2Image;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test-13t-blockwriter.qcow2".to_string());

    let mut image = Qcow2Image::open(&path).unwrap();

    let tib: u64 = 1024 * 1024 * 1024 * 1024;
    let mib: u64 = 1024 * 1024;

    let offsets: &[(u64, &str)] = &[
        (0, "0"),
        (1 * tib + 100 * mib, "1 TiB + 100 MiB"),
        (4 * tib + 500 * mib, "4.5 TiB"),
        (9 * tib, "9 TiB"),
        (12 * tib + 800 * mib, "12.8 TiB"),
    ];

    for &(offset, label) in offsets {
        let mut buf = vec![0u8; 512];
        match image.read_at(&mut buf, offset) {
            Ok(()) => {
                let nonzero = buf.iter().filter(|&&b| b != 0).count();
                println!(
                    "  {label} (offset {offset:#x}): OK, {nonzero}/512 non-zero bytes, first 16: {:02x?}",
                    &buf[..16]
                );
            }
            Err(e) => {
                println!("  {label} (offset {offset:#x}): ERROR: {e}");
            }
        }
    }
}
