# Bitmaps API

<!-- TODO
- Document all bitmap operations on Qcow2Image (and Qcow2ImageAsync):
    create_bitmap(name: &str, granularity_bits: u8) -> Result<()>
    delete_bitmap(name: &str) -> Result<()>
    set_bitmap_region(name: &str, offset: u64, size: u64) -> Result<()>
    clear_bitmap_region(name: &str, offset: u64, size: u64) -> Result<()>
    list_bitmaps() -> Result<Vec<BitmapInfo>>
    get_bitmap_data(name: &str, offset: u64, size: u64) -> Result<Vec<u8>>

- Document BitmapInfo fields: name, granularity_bits, flags (in_use, auto, enabled)

- Explain granularity_bits: the bitmap tracks regions of size 2^granularity_bits bytes;
  typical values are 16 (64 KB, matching cluster size) or smaller for finer tracking

- Explain the AUTO flag: bitmap is automatically updated on every guest write
  (maintained by the engine's write path)

- Explain the ENABLED flag: bitmap updates are active; cleared = paused

- Explain the IN_USE flag: set while the bitmap is being modified; if set at open
  time the bitmap data may be inconsistent

- Explain the AUTOCLEAR_BITMAPS header flag interaction: cleared by any writer
  that does not maintain bitmaps; re-set by qcow2-lib after consistent close

- Show a use case: incremental backup with dirty tracking

- Reference: crates/qcow2-core/src/engine/bitmap_manager.rs
- Reference: crates/qcow2/src/engine/image/bitmap.rs
- Reference: crates/qcow2/src/engine/image_async/bitmap.rs
-->
