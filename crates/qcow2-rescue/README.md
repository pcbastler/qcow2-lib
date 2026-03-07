# qcow2-rescue

Recovery tool for corrupted QCOW2 disk images. Designed for cases where `qemu-img check -r all` fails — when L1/L2 tables, refcounts, or the header itself are damaged.

## How it works

qcow2-rescue operates in three phases:

### Phase 1: Cluster Scanning

Reads every cluster in the image and classifies it using heuristics:

| Type | Detection method |
|------|-----------------|
| Header | QCOW2 magic bytes + version field |
| L1 Table | Sparse array of cluster-aligned 8-byte offsets (<=80% non-zero) |
| L2 Table | Dense array of cluster descriptors (standard 8-byte or extended 16-byte) |
| Refcount Block | Array of u16 values, mostly 0 or 1 |
| Compressed | Deflate (zlib CMF/FLG) or Zstd (magic 0x28B52FFD) signatures |
| Data | Non-zero content that doesn't match metadata patterns |
| Empty | All-zero clusters |

A refinement pass removes false-positive L2 classifications by scoring candidates against known data cluster offsets.

### Phase 2: Metadata Reconstruction

Rebuilds guest-to-host cluster mappings from the scan results:

- **L1 recovery**: Reads L1 table from header, falls back to scan-detected L1 clusters
- **L2 parsing**: Validates entries (cluster-aligned, within file bounds, pointing to actual data)
- **Orphan detection**: Finds L2 tables not referenced by L1 and infers their guest offset via partition layout analysis (MBR) or disk position ordering
- **Refcount cross-check**: Verifies mapped clusters against refcount blocks (leaked, shared, correct)
- **Plausibility scoring**: Ranks mappings by structural consistency

### Phase 3: Data Recovery

Reads mapped clusters, applies decompression and decryption as needed, writes output.

- **Compression**: Deflate and Zstd decompression
- **Encryption**: LUKS1/LUKS2 with password-based key derivation; falls back to writing encrypted data if no password is provided
- **Layer merging**: For backing chains, later layers override earlier ones per guest offset
- **Resume**: Saves progress every 100 clusters; interrupted recoveries can be continued with `--resume`

## Usage

### Analyze (non-destructive scan + report)

```sh
qcow2-rescue analyze corrupted.qcow2 -o analysis/
```

Produces JSON reports:
- `cluster_map.json` — per-cluster classification
- `reconstructed_tables.json` — recovered guest-to-host mappings, refcount status, validation results
- `backing_tree.json` — detected backing chain structure

### Recover

```sh
# Extract as raw image
qcow2-rescue recover corrupted.qcow2 -o recovery/ -f raw

# Extract as QCOW2
qcow2-rescue recover corrupted.qcow2 -o recovery/ -f qcow2

# Preserve backing chain structure
qcow2-rescue recover /path/to/images/ -o recovery/ -f chain

# With encryption password
qcow2-rescue recover encrypted.qcow2 -o recovery/ -f raw --password-file pwd.txt

# Resume interrupted recovery
qcow2-rescue recover corrupted.qcow2 -o recovery/ -f raw --resume
```

### Options

| Option | Description |
|--------|-------------|
| `-o <DIR>` | Output directory |
| `-f <FORMAT>` | Output format: `raw`, `qcow2`, `chain` |
| `--cluster-size <BYTES>` | Override auto-detected cluster size |
| `--password-file <FILE>` | LUKS password file for encrypted images |
| `--on-conflict <STRATEGY>` | Conflict resolution: `ask`, `newer`, `safer`, `both` |
| `--resume` | Resume interrupted recovery from progress file |

## Output formats

| Format | Description |
|--------|-------------|
| `raw` | Flat sparse disk image, all layers flattened |
| `qcow2` | Single QCOW2 file, all layers flattened |
| `chain` | One QCOW2 per layer with backing references preserved |

## Supported features

- Standard and extended L2 entries (32 subclusters per cluster)
- Deflate and Zstd compressed clusters
- LUKS1/LUKS2 encrypted images (AES-XTS, AES-CBC)
- Backing chains with automatic directory-based tree discovery
- Cluster sizes from 4 KiB to 2 MiB (auto-detected or manual override)
- MBR partition layout detection for orphan L2 placement

## Recovery success rates

End-to-end test results across different filesystem and partition layouts. Each column represents a corruption scenario where the corresponding metadata structure was zeroed out before recovery. The percentage shows byte-level accuracy of the recovered image compared to the original.

```
Image                        |  header  |    L1    |    L2    |  refcnt  |  hdr+L1  |  allMD   |
-----------------------------+----------+----------+----------+----------+----------+----------+
mbr_ext2_mixed               | 66% FAIL | 100% OK  | 33% FAIL | 100% OK  | 66% FAIL |  66% OK  |
mbr_ext3_mixed               | 65% FAIL | 100% OK  | 37% FAIL | 100% OK  | 65% FAIL |  65% OK  |
mbr_ext4_mixed               |  0% FAIL | 100% OK  | 24% FAIL | 100% OK  |  0% FAIL |  0% FAIL |
mbr_fat32_mixed              | 100% OK  | 100% OK  | 47% FAIL | 100% OK  | 100% OK  | 100% OK  |
mbr_ntfs_mixed               |  0% FAIL | 100% OK  |  0% FAIL | 100% OK  |  0% FAIL |  0% FAIL |
mbr_btrfs_mixed              |  99% OK  | 100% OK  | 57% FAIL | 100% OK  |  99% OK  |  99% OK  |
mbr_xfs_mixed                |  0% FAIL | 100% OK  | 78% FAIL | 100% OK  |  0% FAIL |  0% FAIL |
gpt_ext2_mixed               | 67% FAIL | 100% OK  | 39% FAIL | 100% OK  | 67% FAIL |  67% OK  |
gpt_ext3_mixed               |  2% FAIL | 100% OK  | 35% FAIL | 100% OK  |  2% FAIL |  2% FAIL |
gpt_ext4_mixed               | 74% FAIL | 100% OK  | 27% FAIL | 100% OK  |  74% OK  |  74% OK  |
gpt_fat32_mixed              | 100% OK  | 100% OK  | 47% FAIL | 100% OK  | 100% OK  | 100% OK  |
gpt_ntfs_mixed               | 100% OK  | 100% OK  |  0% FAIL | 100% OK  | 100% OK  | 100% OK  |
gpt_btrfs_mixed              |  99% OK  | 100% OK  | 57% FAIL | 100% OK  |  99% OK  |  99% OK  |
gpt_xfs_mixed                |  0% FAIL | 100% OK  | 78% FAIL | 100% OK  |  0% FAIL |  0% FAIL |
gpt_ext2_mixed_compressed    |  98% OK  |  98% OK  | 42% FAIL |  97% OK  |  98% OK  |  98% OK  |
gpt_ext3_mixed_compressed    |  99% OK  |  98% OK  | 43% FAIL |  98% OK  |  99% OK  |  99% OK  |
gpt_ext4_mixed_compressed    |  98% OK  |  98% OK  | 45% FAIL |  98% OK  |  98% OK  |  98% OK  |
gpt_fat32_mixed_compressed   |  95% OK  |  97% OK  | 46% FAIL |  97% OK  |  95% OK  |  95% OK  |
gpt_ntfs_mixed_compressed    |  97% OK  |  97% OK  | 29% FAIL |  97% OK  |  97% OK  |  97% OK  |
gpt_btrfs_mixed_compressed   |  98% OK  |  99% OK  | 70% FAIL |  99% OK  |  98% OK  |  98% OK  |
gpt_xfs_mixed_compressed     |  99% OK  |  99% OK  |  86% OK  |  99% OK  |  99% OK  |  99% OK  |
gpt_ext4_text_only           | 100% OK  | 100% OK  | 69% FAIL | 100% OK  | 100% OK  | 100% OK  |
gpt_ext4_binary_only         | 100% OK  | 100% OK  | 70% FAIL | 100% OK  | 100% OK  | 100% OK  |
gpt_ext4_image_only          | 75% FAIL | 100% OK  | 79% FAIL | 100% OK  |  75% OK  |  75% OK  |
-----------------------------+----------+----------+----------+----------+----------+----------+
PASSED                       |  14/24   |  24/24   |   1/24   |  24/24   |  16/24   |  19/24   |

Total: 98/144 passed, 46 failed
```

**Key takeaways:**
- **L1 and refcount corruption**: Near-perfect recovery across all scenarios (24/24)
- **Header corruption**: Reliable when guest data has distinctive patterns (fat32, btrfs, compressed images); struggles with ext/xfs/ntfs where data clusters resemble metadata
- **L2 corruption**: The hardest scenario — L2 tables are the primary guest-to-host mapping, and without them recovery depends on heuristic orphan detection
- **Combined corruption** (hdr+L1, allMD): Recovery quality follows the weakest link, but still succeeds in 16-19 of 24 cases

## Limitations

- **Requires L2 remnants** — If all L2 tables are completely destroyed, there is no way to reconstruct guest-to-host mappings. The tool cannot rebuild mappings from raw data content alone.
- **No snapshot metadata recovery** — Internal QCOW2 snapshots are not reconstructed. Backing chain recovery works via overlay merging, not snapshot table repair.
- **MBR-only partition detection** — Orphan L2 index inference uses MBR layout heuristics. GPT-only images fall back to disk-position ordering, which may place orphan data at wrong guest offsets.
- **Single-threaded** — All I/O is synchronous and sequential.
- **Read-only** — The original image is never modified; output is always written to a new file.
- **Report limits** — Refcount mismatches are capped at 1000 entries per report. Content validation probes up to 100 compressed and 100 encrypted clusters.
- **No guarantee of completeness** — Recovery is best-effort. The amount of recoverable data depends on how much metadata survived the corruption.

## License

This software is proprietary. See [LICENSE](../../LICENSE) for details.
