# Format Conversion

<!-- TODO
- Document the four conversion functions:
    convert_from_raw(src: &Path, dst: &Path, opts: ConvertOptions) -> Result<()>
    convert_from_raw_parallel(src: &Path, dst: &Path, opts: ConvertOptions, threads: usize) -> Result<()>
    convert_qcow2_to_qcow2(src: &Path, dst: &Path, opts: ConvertOptions) -> Result<()>
    convert_to_raw(src: &Path, dst: &Path, opts: ConvertOptions) -> Result<()>

- Document ConvertOptions fields:
    compress: bool
    compression_type: CompressionType
    encryption: Option<EncryptionOptions>
    external_data_file: Option<PathBuf>
    cluster_bits: Option<u8>
    extended_l2: bool
    blake3_hashes: bool

- Explain the parallel raw→qcow2 converter:
    - Splits input into chunks, each processed by a worker thread
    - Workers compress clusters independently
    - Main thread serializes output to maintain sequential file layout
    - threads parameter controls parallelism; 0 or 1 = single-threaded

- Explain qcow2→qcow2 conversion (compact/recompress):
    - Re-reads all allocated clusters from source
    - Optionally recompresses with a different algorithm or level
    - Output has contiguous cluster layout (defragmented)

- Explain the zero-cluster optimization: all-zero input → Zero L2 entry (no data written)

- Reference: crates/qcow2/src/engine/converter.rs
-->
