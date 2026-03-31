# qcow2-tool CLI

`qcow2-tool` is the command-line interface for inspecting and managing QCOW2
images. It wraps the `qcow2` library API.

<!-- TODO
- Show installation: cargo install --path crates/qcow2-tool
- Show the top-level help output (run qcow2-tool --help and paste)
- Describe global options if any (verbosity, color, etc.)
- List all subcommands with a one-line description each (link to their doc pages)
- Reference: crates/qcow2-tool/src/cli/main.rs
-->

## Subcommands

| Command | Description |
|---------|-------------|
| [info](info.md) | Display image metadata and geometry |
| [dump](dump.md) | Print raw L1, L2, or refcount table entries |
| [check](check.md) | Validate (and optionally repair) refcount consistency |
| [snapshot](snapshot.md) | Create, delete, revert, and list snapshots |
| [bitmap](bitmap.md) | Manage persistent dirty bitmaps |
| [hash](hash.md) | Compute, verify, and list BLAKE3 hashes |
| [resize](resize.md) | Change the virtual disk size |
| [convert](convert.md) | Convert between raw and QCOW2, or recompress |
| [compact](compact.md) | Defragment and repack an image |
| [commit](commit.md) | Merge overlay data into the backing file |
| [rebase](rebase.md) | Change the backing file reference |
