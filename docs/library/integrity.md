# Integrity Check & Repair

<!-- TODO
- Explain what check() validates:
    - Rebuilds expected refcount table from L1/L2 traversal
    - Compares computed refcounts against stored refcounts
    - Reports: missing clusters, extra references, wrong refcount values
    - Also checks: refcount table clusters themselves are properly referenced

- Document IntegrityReport fields:
    errors: Vec<IntegrityError>  — mismatches found
    warnings: Vec<String>        — non-fatal anomalies

- Document IntegrityError variants:
    RefcountMismatch { cluster_offset, stored, computed }
    UnreferencedCluster { cluster_offset }
    etc. (read integrity.rs for the exact set)

- Document the repair modes:
    RepairMode::Validate   — check only, no writes
    RepairMode::AutoRepair — write corrected refcount table silently
    RepairMode::Interactive — (TBD: describe if interactive mode is implemented)

- Explain the DIRTY flag relationship: if the image was not closed cleanly,
  the DIRTY incompatible flag is set; check() should always be run after
  opening a DIRTY image

- Explain flush order importance for crash consistency (see cache.md)

- Document the API:
    image.check() -> Result<IntegrityReport>
    image.repair(mode: RepairMode) -> Result<IntegrityReport>

- Reference: crates/qcow2/src/engine/integrity.rs
- Reference: crates/qcow2/src/engine/image/integrity.rs
- Reference: crates/qcow2/src/engine/image_async/integrity.rs
-->
