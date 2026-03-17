# qcow2-rescue

`qcow2-rescue` is a standalone recovery tool for QCOW2 images that are too
corrupted for `qemu-img check -r all` to fix.

<!-- TODO
- Explain the target scenario: header intact but L1/L2/refcount structures
  partially or fully destroyed; or even header corrupted

- Document the recovery pipeline stages:
    1. Scan: read file in cluster-sized chunks; classify each cluster by heuristics
       (header magic, L1/L2 patterns, refcount patterns, compressed data)
    2. Detect: determine cluster size if header is unreadable
    3. Reconstruct: build candidate L1/L2/refcount tables from orphaned clusters;
       use scoring to rank candidates
    4. Validate: verify reconstructed structures for self-consistency
    5. Recover: merge best candidates, extract data clusters to output
    6. Report: emit JSON reports at each stage

- Document the output formats:
    - Repaired QCOW2 image (best-effort)
    - Raw image (extracted data clusters)
    - JSON reports: cluster analysis, reconstruction candidates, recovery statistics

- Document the JSON report structure (read report/*.rs for field names):
    cluster_report: per-cluster type classification
    reconstruction_report: candidate tables and scores
    recovery_report: recovered vs total clusters, per-cluster status
    tree_report: filesystem tree if data was interpretable

- Reference: crates/qcow2-rescue/src/scan/
- Reference: crates/qcow2-rescue/src/reconstruct/
- Reference: crates/qcow2-rescue/src/recover/
- Reference: crates/qcow2-rescue/src/report/
- Reference: crates/qcow2-rescue/src/validate/
-->
