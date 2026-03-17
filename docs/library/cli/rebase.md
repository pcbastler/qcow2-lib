# qcow2-tool rebase

Change the backing file reference stored in a QCOW2 image header.

<!-- TODO
- Show usage:
    qcow2-tool rebase <IMAGE> [--backing <PATH>]
    qcow2-tool rebase <IMAGE>  (removes the backing file reference entirely)

- Explain what rebase does:
    Updates the backing_file_offset and backing_file_size fields in the header
    (and optionally the BackingFileFormat extension) to point to a new backing file

- WARN prominently: rebase does NOT validate or migrate data
    - It only updates the pointer in the header
    - If the new backing file has different content than the old one, any
      unallocated clusters in the overlay will now read WRONG data
    - Safe only if the new backing file is identical to the old one (or is a
      different snapshot of the same base that shares all clusters referenced
      by the overlay's unallocated regions)

- Explain the "unsafe rebase" vs "safe rebase" distinction (QEMU terminology):
    Safe rebase: re-allocates clusters from old backing that the new backing
                 does not have (not implemented here; this is unsafe rebase only)

- Reference: crates/qcow2-tool/src/cli/rebase.rs
-->
