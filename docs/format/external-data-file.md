# External Data File

When the `EXTERNAL_DATA_FILE` incompatible feature flag is set, guest data
clusters are stored in a separate file instead of the QCOW2 file itself.
The QCOW2 file then contains only metadata.

<!-- TODO
- Explain the ExternalDataFile header extension: stores the path string of
  the external data file (relative or absolute)
- Explain the RAW_EXTERNAL autoclear flag:
    Set: external file contains raw data; L2 lookup is bypassed entirely,
         guest_offset maps directly to host_offset in the external file
    Cleared: external file has its own structure (future use, not yet defined)
- Explain read/write path when RAW_EXTERNAL is set:
    read_at(guest_offset) → external_backend.read_at(guest_offset)
    no L1/L2 table involved
- Use cases: separate metadata and data devices, thin provisioning on raw block devices
- Note that with RAW_EXTERNAL, the QCOW2 file still holds all metadata
  (snapshots, bitmaps, hashes, refcounts) while data lives elsewhere
- Reference: crates/qcow2-format/src/header_extension.rs (ExternalDataFile variant)
- Reference: crates/qcow2-format/src/feature_flags.rs (AutoclearFeatures::RAW_EXTERNAL)
- Reference: crates/qcow2-core/src/engine/reader.rs (RAW_EXTERNAL read path)
-->
