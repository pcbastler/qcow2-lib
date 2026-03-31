# qcow2-tool info

Display metadata and geometry of a QCOW2 image.

<!-- TODO
- Show the usage line: qcow2-tool info <IMAGE>
- Document all output fields:
    File, Format, Virtual size, Disk size (actual allocated)
    QCOW2 version (v2 / v3)
    Cluster size
    Encryption (none / AES-CBC / LUKS)
    Compression type (deflate / zstd)
    Feature flags: incompatible, compatible, autoclear (with names if known)
    Header extensions present
    Backing file (if set) + backing file format
    Number of snapshots
    Number of bitmaps
    BLAKE3 hashes: present / absent
    DIRTY / CORRUPT flag warnings
- Show example output
- Reference: crates/qcow2-tool/src/cli/info.rs
-->
