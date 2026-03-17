# qcow2-tool resize

Change the virtual disk size of a QCOW2 image.

<!-- TODO
- Show usage:
    qcow2-tool resize <IMAGE> <SIZE>
    SIZE accepts K/M/G/T suffixes (e.g. "20G", "1T")

- Explain grow: the L1 table is extended if needed; new guest address space
  reads as zero (or backing) until written

- Explain shrink: truncates the virtual address space; any data above the new
  size is lost; L1 entries pointing to clusters above new_size are freed

- Warn: shrink is destructive; there is no confirmation prompt; backup first

- Explain that the host file size does NOT immediately change on grow
  (QCOW2 is sparse; clusters are only allocated on write)

- Reference: crates/qcow2-tool/src/cli/resize.rs
- Reference: crates/qcow2/src/engine/image/resize.rs
-->
