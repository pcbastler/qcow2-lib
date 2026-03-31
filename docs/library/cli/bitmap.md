# qcow2-tool bitmap

Manage persistent dirty bitmaps embedded in a QCOW2 image.

<!-- TODO
- Show all subcommand forms:
    qcow2-tool bitmap list <IMAGE>
    qcow2-tool bitmap create <IMAGE> <NAME> [--granularity-bits <N>]
    qcow2-tool bitmap delete <IMAGE> <NAME>
    qcow2-tool bitmap set <IMAGE> <NAME> <OFFSET> <SIZE>
    qcow2-tool bitmap clear <IMAGE> <NAME> <OFFSET> <SIZE>

- Document list output columns:
    Name, Granularity, Flags (in-use, auto, enabled)

- Explain granularity-bits default (matches cluster_bits of image)

- Document set/clear: OFFSET and SIZE accept K/M/G suffixes

- Explain use case: marking regions dirty for incremental backup tools;
  the AUTO flag enables automatic dirty tracking during normal writes

- Reference: crates/qcow2-tool/src/cli/bitmap.rs
- Reference: crates/qcow2-core/src/engine/bitmap_manager.rs
-->
