# BackingImage Trait

`BackingImage` abstracts read access to a backing image. The engine calls it
whenever a cluster lookup returns `Unallocated` and a backing image is present.

<!-- TODO
- Show the trait definition:
    fn virtual_size(&self) -> u64
    fn read_at(&mut self, buf: &mut [u8], guest_offset: u64) -> Result<()>

- Explain that reads past virtual_size return zeros

- Describe how qcow2 implements this: Qcow2Image implements BackingImage,
  allowing QCOW2-over-QCOW2 chains

- Explain backing chain construction in Qcow2Image::open:
    1. Read backing_file field from header
    2. Resolve path relative to the overlay file directory
    3. Detect format (check magic; default raw if not QCOW2)
    4. Open recursively up to MAX_BACKING_CHAIN_DEPTH
    5. Detect cycles (compare resolved canonical paths)

- Show how to provide a custom BackingImage (e.g. a network block device)
- Reference: crates/qcow2-core/src/engine/mod.rs (BackingImage trait)
- Reference: crates/qcow2/src/engine/backing.rs (implementation)
- Reference: crates/qcow2/src/engine/image/open.rs (chain construction)
-->
