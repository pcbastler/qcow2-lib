# qcow2-tool convert

Convert between raw and QCOW2 formats, or recompress an existing QCOW2 image.

<!-- TODO
- Show usage:
    qcow2-tool convert <INPUT> <OUTPUT> [OPTIONS]

- Document all options:
    --format <qcow2|raw>           output format (default: qcow2)
    --compress                     compress data clusters
    --compression-type <deflate|zstd>  algorithm (default: deflate)
    --cluster-bits <N>             output cluster size (default: 16)
    --data-file <PATH>             write guest data to a separate file
    --password <PWD>               password to decrypt encrypted input
    --encrypt                      encrypt output with LUKS
    --encrypt-password <PWD>       password for encrypted output
    --threads <N>                  worker threads for raw→qcow2 (default: 1)
    --extended-l2                  enable extended L2 subclusters in output
    --blake3-hashes                compute and store BLAKE3 hashes in output

- Explain supported conversion directions:
    raw → qcow2   (with optional compression, encryption, parallel)
    qcow2 → raw   (with optional decryption)
    qcow2 → qcow2 (recompress, change encryption, change cluster size)

- Note: qcow2 → qcow2 produces a defragmented, contiguous output image

- Note: --threads only applies to raw→qcow2; other conversions are single-threaded

- Reference: crates/qcow2-tool/src/cli/convert.rs
- Reference: crates/qcow2/src/engine/converter.rs
-->
