# qcow2-tool check

Validate refcount consistency and optionally repair mismatches.

<!-- TODO
- Show usage:
    qcow2-tool check <IMAGE>
    qcow2-tool check <IMAGE> --repair
- Explain what check does: rebuilds the expected refcount table by traversing
  the L1/L2 tree and comparing against stored refcounts
- Document output:
    OK message if no errors
    Per-error line: cluster offset, stored refcount, computed refcount
    Summary: N errors found / N errors repaired
- Explain --repair flag: writes the corrected refcount table to disk
- Warn: --repair modifies the image in-place; make a backup first
- Mention: check should be run on any image with the DIRTY flag set
- Reference: crates/qcow2-tool/src/cli/check.rs
- Reference: crates/qcow2/src/engine/integrity.rs
-->
