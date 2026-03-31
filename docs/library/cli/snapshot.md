# qcow2-tool snapshot

Create, delete, revert to, and list internal QCOW2 snapshots.

<!-- TODO
- Show all subcommand forms:
    qcow2-tool snapshot list <IMAGE>
    qcow2-tool snapshot create <IMAGE> <ID> <NAME>
    qcow2-tool snapshot delete <IMAGE> <ID>
    qcow2-tool snapshot revert <IMAGE> <ID>

- Document list output columns:
    ID, Name, Date/Time, VM clock, VM state size, Disk size

- Document create parameters:
    ID: unique numeric string identifier (e.g. "1", "2")
    NAME: human-readable label

- Warn about revert: the current live image state (uncommitted writes since
  the last snapshot) is lost after revert

- Warn about delete: deletes the snapshot record but does NOT restore data
  or roll back; use revert for rollback

- Show example session: create → list → revert → list

- Reference: crates/qcow2-tool/src/cli/snapshot.rs
- Reference: crates/qcow2-core/src/engine/snapshot_manager.rs
-->
