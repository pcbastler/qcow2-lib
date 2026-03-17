# Qcow2BlockWriter

`Qcow2BlockWriter` creates a new QCOW2 image by streaming data sequentially.
It implements `std::io::Write` and `std::io::Seek`, making it a drop-in sink
for any code that writes to a `Write`+`Seek` target.

<!-- TODO
- Explain the use case: converting from raw, writing image files from a stream,
  pipeline-style image creation without random access patterns

- Document BlockWriterOptions fields:
    virtual_size: u64
    cluster_bits: u8
    compress: bool
    compression_type: CompressionType
    encryption: Option<EncryptionOptions>
    blake3_hashes: bool
    hash_size: u8 (16 or 32)
    hash_chunk_bits: u8
    external_data_file: Option<PathBuf>
    memory_limit: Option<usize>

- Document lifecycle:
    Qcow2BlockWriter::create(path, opts) -> Result<Self>
    writer.write(buf)   — std::io::Write impl
    writer.seek(pos)    — std::io::Seek impl (forward seek only in practice)
    writer.finalize()   — flush data, write all metadata (L1, L2, refcounts,
                          bitmaps, hashes), close file

- Explain internal behavior:
    - Data clusters buffered in RAM during write phase
    - Zero-cluster detection: all-zero input cluster → L2 entry set to Zero, no data written
    - Compressed clusters: input cluster → compress → write at current end of file
    - finalize() writes metadata structures sequentially after data

- Explain memory_limit: caps RAM used for buffering; triggers early flush if exceeded

- Reference: crates/qcow2-core/src/engine/block_writer/ (core engine)
- Reference: crates/qcow2/src/engine/block_writer/ (std layer: create, write, finalize)
-->
