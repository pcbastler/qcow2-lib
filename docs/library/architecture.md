# Architecture

qcow2-lib is split into four crates with a strict layered dependency. Lower
layers are `no_std`-compatible; higher layers add `std` dependencies
incrementally.

<!-- TODO
- Draw the crate dependency graph:
    qcow2-format  (no_std, alloc)
         ↓
    qcow2-core    (no_std, alloc)
         ↓
    qcow2         (std)
         ↓
    qcow2-tool    (std, binary)

- Describe each layer's responsibility:
    qcow2-format: on-disk types, encode/decode, no I/O, no validation
    qcow2-core:   stateful engine, trait abstractions (IoBackend, Compressor,
                  BackingImage), no concrete I/O or compression implementations
    qcow2:        std wrapper; SyncFileBackend, MemoryBackend, StdCompressor,
                  full LUKS, argon2, Qcow2Image, Qcow2ImageAsync, Qcow2BlockWriter
    qcow2-tool:   CLI binary wrapping the qcow2 public API

- Explain the no_std split: allows embedding qcow2-core in firmware or WASM
  with a custom IoBackend

- Explain the error domain split:
    qcow2_format::Error  — format parsing errors (bad magic, wrong version, etc.)
    qcow2_core::Error    — engine errors, wraps FormatError via Error::Format(e)
    qcow2::Error         — same type re-exported, additional std IO errors

- Mention qcow2-rescue as a separate recovery utility that depends on all layers

- Reference: Cargo.toml (workspace root), each crate's Cargo.toml and lib.rs
-->
