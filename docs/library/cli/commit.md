# qcow2-tool commit

Merge an overlay image's data into its backing file.

<!-- TODO
- Show usage:
    qcow2-tool commit <OVERLAY>

- Explain the operation:
    Reads every allocated cluster from the overlay and writes it to the
    corresponding offset in the backing file. After commit, the overlay
    has no unique data — it is effectively empty relative to its backing.

- Warn clearly: this is DESTRUCTIVE and IRREVERSIBLE
    - The backing file is permanently modified
    - The overlay should be considered invalid after commit
    - Make a backup of the backing file before running commit

- Explain typical use case: finalizing an overlay after testing; merging
  a short-lived snapshot chain into the base image

- Note: commit does NOT delete the overlay file; that is the user's responsibility

- Reference: crates/qcow2-tool/src/cli/commit.rs
-->
