# 12. Persistent Dirty Bitmaps

The Bitmaps header extension points to a bitmap directory that lists named
bitmaps. Each bitmap tracks which guest regions have been written since a
reference point (e.g. a backup checkpoint).

<!-- TODO
- Explain purpose: incremental backup, dirty tracking, live migration
- Document BitmapExtension structure:
    nb_bitmaps: number of bitmaps
    bitmap_directory_size: total byte size of the directory
    bitmap_directory_offset: host offset of the first bitmap directory entry
- Document BitmapTableEntry (directory entry) fields:
    bitmap_table_offset: host offset of this bitmap's two-level table
    bitmap_table_size: number of entries in the bitmap table
    flags: IN_USE (bit 0), AUTO (bit 2), ENABLED (bit 3)
    type: must be 0 (dirty bitmap)
    granularity_bits: log2 of tracked region size per bit
    name_size + name: UTF-8 bitmap name
- Explain two-level bitmap data structure:
    bitmap table → bitmap data clusters (1 bit per granularity-sized region)
- Explain BitmapTableEntryState: Allocated, Zero, Unallocated
- Explain AUTOCLEAR_BITMAPS flag: set when bitmap data is consistent; cleared
  by any writer that does not properly maintain the bitmaps
- Reference: crates/qcow2-format/src/bitmap.rs
- Reference: crates/qcow2-core/src/engine/bitmap_manager.rs
-->
