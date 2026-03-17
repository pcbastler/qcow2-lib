# 15. Backing File

A QCOW2 image can name a backing file in its header. Any guest cluster that is
unallocated in the overlay is read from the backing file instead of returning
zeros. This enables efficient copy-on-write overlays and snapshot chains.

<!-- TODO
- Document the two header fields:
    backing_file_offset: byte offset of the backing file name string
    backing_file_size: length of the backing file name (not null-terminated)
- Document the BackingFileFormat header extension: format hint for the backing
  file ("qcow2", "raw", etc.)
- Explain read semantics: L2 lookup → if Unallocated → read from backing image
- Explain that backing file paths are resolved relative to the overlay file's
  directory (not the process CWD)
- Explain the backing chain: backing images can themselves have backing images,
  forming a chain down to a base image (or a raw disk)
- Note: writes always go to the top-most overlay; backing files are never modified
- Mixed formats: a QCOW2 overlay can have a raw backing file
- Reference: crates/qcow2-format/src/header.rs (backing_file_offset, backing_file_size)
- Reference: crates/qcow2/src/engine/backing.rs (BackingImage trait implementation)
- Reference: crates/qcow2/src/engine/image/open.rs (backing chain construction)
-->
