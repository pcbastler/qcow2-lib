# Documentation Audit

This file tracks claims in the documentation that are **not directly verifiable
from the qcow2-lib source code**. They originate from general knowledge about
the QCOW2 format and its ecosystem.

These claims are not necessarily wrong — but they cannot be proven correct by
reading this codebase alone. If audit-grade accuracy is required, each item
should be verified against the upstream QEMU QCOW2 specification
(`docs/interop/qcow2.txt` in the QEMU repository).

## format/01-overview.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 13 | "QEMU Copy-On-Write version 2" as the expansion of QCOW2 | Name origin |
| 13–15 | "native disk image format of QEMU...widely used by KVM, libvirt, OpenStack" | Ecosystem context |
| 18 | "A 100 GB virtual disk might only use 2 GB on disk" | Illustrative example |
| 22 | "template-based provisioning and thin clones" | Use case description |
| 107 | "tens to hundreds of entries for typical images" | Unquantified claim |
| 115–124 | Refcount semantics: 0=free, 1=in-place write, >1=COW | Engine behavior (implied by `COPIED` flag in `constants.rs:68`, but the format layer does not define write semantics) |

## format/02-header.md

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

## format/03-feature-flags.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 5–6 | "before they corrupt the image by misinterpreting its data" | Design rationale (source says "MUST NOT be opened" / "may not handle the format correctly", but doesn't mention corruption explicitly) |
| 28 | "These features add optional metadata that does not affect the core data layout" | Format spec explanation (source says "Unknown bits can be safely ignored" without explaining why) |
| 37–39 | "This mechanism is designed for consistency flags: the bit is set when the metadata is known to be consistent, and cleared when it might not be" | Editorial design rationale (source says "signaling that the associated metadata may be stale") |
| 49 | "should be checked before use" | Recommendation not in source (source says "refcounts may be inconsistent" without prescribing action) |
| 52 | "If this bit is not set, deflate (type 0) is assumed regardless of that byte's value" | Format spec behavior (source comment says "The compression type is not deflate; check header byte 104" — the "regardless" clause is additional) |
| 65 | "Unlike DIRTY, this is a deliberate optimization, not an error condition" | Editorial comparison (source says "refcounts may be stale and need a consistency check" without contrasting with DIRTY) |
| 73 | "Cleared by implementations that do not maintain bitmaps" | Format spec behavior (source says "Bitmaps extension data is consistent with the image content" without describing clearing behavior) |
| 75 | "not defined by the upstream QCOW2 specification" | External knowledge about upstream spec contents |
| 93 | "All remaining bits (5–63) are reserved" | Format spec terminology (source validates unknown bits but doesn't use the word "reserved") |

## format/04-header-extensions.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 13–14 | "if any data is present before the first cluster boundary" | Qualifier not in source (source defines `HEADER_V2_LENGTH = 72` but doesn't discuss this boundary condition) |
| 64 | "not null-terminated" | Implied by `String::from_utf8_lossy(data)` usage, but not explicitly stated in source |
| 96–98 | "so that tools can display meaningful messages for unknown features (e.g. 'incompatible feature bit 4: extended_l2' instead of just 'unknown bit 4')" | Illustrative example (source says "maps (type, bit) pairs to human-readable names") |

## format/06-extended-l2.md

| Line(s) | Claim | Category |
|---------|-------|----------|
| 13 | "even writing a single byte marks the entire 64 KB as allocated" | Engine behavior, not format spec |
| 14–16 | "enabling finer-grained tracking without reducing the cluster size" | Design rationale |

## Status

- **Last audited**: 2026-03-17
- **Audited files**: `format/01-overview.md`, `format/02-header.md`, `format/03-feature-flags.md`, `format/04-header-extensions.md`, `format/06-extended-l2.md`
- **Remaining**: All other docs files (still contain TODO placeholders)
