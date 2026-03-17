# qcow2-tool hash

Compute, verify, and list BLAKE3 per-chunk content hashes stored in the image.

<!-- TODO
- Show all subcommand forms:
    qcow2-tool hash compute <IMAGE> [--chunk-bits <N>] [--hash-size <16|32>]
    qcow2-tool hash verify <IMAGE>
    qcow2-tool hash list <IMAGE>

- Document compute options:
    --chunk-bits: log2 of chunk size (default 16 = 64 KB, range 12–24)
    --hash-size: 16 (128-bit) or 32 (256-bit, default)

- Document verify output:
    Summary: N/M chunks OK
    Per-mismatch line: guest offset, stored hash (hex), computed hash (hex)

- Document list output:
    guest_offset, hash (hex)

- Remind user: this is a qcow2-lib extension; BLAKE3 data is ignored by QEMU
  (autoclear flag ensures graceful degradation)

- Reference: crates/qcow2-tool/src/cli/hash.rs
- Reference: crates/qcow2-core/src/engine/hash_manager.rs
-->
