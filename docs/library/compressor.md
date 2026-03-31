# Compressor Trait

`Compressor` abstracts the compression algorithm so the engine stays
`no_std`-compatible. The concrete `StdCompressor` implementation is provided
by the `qcow2` crate.

<!-- TODO
- Show the full trait definition:
    fn decompress(&self, input: &[u8], output: &mut [u8], compression_type: u8) -> Result<usize>
    fn compress(&self, input: &[u8], output: &mut [u8], compression_type: u8) -> Result<usize>
  Both return the number of bytes written to output.

- Explain compression_type values: 0 = deflate, 1 = zstd

- Document StdCompressor:
    Deflate: uses flate2::DeflateDecoder / DeflateEncoder (raw deflate, RFC 1951)
    Zstd: decompression via zstd::Decoder (streaming); compression via zstd::bulk::compress
    Construction: StdCompressor::new()

- Note: Zstd decompressor uses streaming decoder (not zstd::bulk::decompress) because
  compressed clusters may span multiple sectors and exact output size is known only
  after decompression

- Show how to pass a custom Compressor to the engine (no-compression stub, LZ4, etc.)
- Reference: crates/qcow2-core/src/engine/mod.rs (Compressor trait)
- Reference: crates/qcow2/src/engine/compression.rs (StdCompressor)
-->
