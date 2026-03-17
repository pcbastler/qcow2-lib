# Header Extensions

After the fixed header fields, QCOW2 v3 allows a variable-length list of
type-length-value (TLV) extensions. The list is terminated by a zero-type entry.

<!-- TODO
- Explain TLV layout: 4-byte type, 4-byte length, length bytes of data (8-byte aligned)
- Document all known extension types:
  - 0x00000000: End of extension list
  - 0xe2792aca: BackingFileFormat — format name of backing file (e.g. "qcow2", "raw")
  - 0x6803f857: FeatureNameTable — maps (feature_type, bit_index) to human-readable name
  - 0x23852875: Bitmaps — offset + size of bitmap directory
  - 0x0537be77: FullDiskEncryption — offset + length of LUKS header
  - 0x44415441: ExternalDataFile — path string of external data file
  - (custom): Blake3Hashes — offset + entry count + hash size + chunk bits
  - unknown types: preserved for round-trip fidelity
- Note 8-byte alignment padding rule
- Reference: crates/qcow2-format/src/header_extension.rs
-->
