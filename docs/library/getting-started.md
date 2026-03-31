# Getting Started

<!-- TODO
- Add Cargo.toml dependency snippet for the qcow2 crate
- Show the three most common use cases with minimal code examples:

  1. Open and read an existing image:
     Qcow2Image::open(path) → read_at(buf, offset)

  2. Create a new image and write data:
     Qcow2Image::create(path, CreateOptions { virtual_size, .. }) → write_at(buf, offset) → flush()

  3. Stream-write a new image (Qcow2BlockWriter):
     Qcow2BlockWriter::create(path, opts) → write() → finalize()

- Show how to open an encrypted image (pass password via OpenOptions)
- Show how to open an image with a backing file
- Mention flush() / Drop behavior: Drop does a best-effort flush; always call
  flush() explicitly in production code
- Reference: crates/qcow2/src/engine/image/create.rs
- Reference: crates/qcow2/src/engine/image/open.rs
- Reference: crates/qcow2/src/engine/image/read_write.rs
-->
