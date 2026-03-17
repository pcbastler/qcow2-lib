# Documentation Audit

This file tracks claims in the documentation that are **not directly verifiable
from the qcow2-lib source code**. They originate from general knowledge about
the QCOW2 format and its ecosystem.

These claims are not necessarily wrong — but they cannot be proven correct by
reading this codebase alone. If audit-grade accuracy is required, each item
should be verified against the upstream QEMU QCOW2 specification
(`docs/interop/qcow2.txt` in the QEMU repository).

## format/README.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 13 | "QEMU Copy-On-Write version 2" as the expansion of QCOW2 | Name origin |
| 13–15 | "native disk image format of QEMU...widely used by KVM, libvirt, OpenStack" | Ecosystem context |
| 18 | "A 100 GB virtual disk might only use 2 GB on disk" | Illustrative example |
| 22 | "template-based provisioning and thin clones" | Use case description |
| 107 | "tens to hundreds of entries for typical images" | Unquantified claim |
| 115–124 | Refcount semantics: 0=free, 1=in-place write, >1=COW | Engine behavior (implied by `COPIED` flag in `constants.rs:68`, but the format layer does not define write semantics) |

## format/header.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 110 | cluster_bits=9: "Minimum, rarely used" | Editorial |
| 112 | cluster_bits=16: "Good balance of metadata overhead and space efficiency" | Editorial |
| 113 | cluster_bits=21: "Large clusters reduce metadata but waste space for small writes" | Editorial |
| 118 | "even a 1-byte write allocates a full cluster" | Engine behavior, not format spec |
| 122–128 | `l1_size` calculation formula (`ceil(virtual_size / bytes_per_l2)`) | Image creation logic, not format spec (the header just stores the value) |
| 149 | refcount_order=4: "Sufficient for most workloads" | Editorial |
| 150 | refcount_order=5: "Many snapshots sharing clusters" | Editorial |
| 151 | refcount_order=6: "Theoretical maximum" | Editorial |
| 161 | "For version 2, extensions may or may not be present" | Not explicitly stated in source |

## Status

- **Last audited**: 2026-03-17
- **Audited files**: `format/README.md`, `format/header.md`
- **Remaining**: All other docs files (still contain TODO placeholders)
