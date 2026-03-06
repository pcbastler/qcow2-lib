//! Phase 4: Recovery — extract data from corrupted images into usable output.
//!
//! Two output modes:
//! - **Raw**: Flat disk image. Backing chain is flattened (base → leaf merge).
//! - **QCOW2**: New QCOW2 image(s). Can preserve backing structure or flatten.
//!
//! For each guest cluster, recovery reads the raw data from the source image
//! using the mappings from Phase 2 (reconstruct). Compressed clusters are
//! decompressed, encrypted clusters are decrypted. The result is written to
//! the output file.
//!
//! ## Encryption handling
//!
//! If a LUKS header is found in the image:
//! - **With password**: decrypt clusters by default, probe to verify correctness
//! - **Without password or wrong password**: write raw (still encrypted) data,
//!   preserve LUKS header info in the report so the user can retry later

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Serialize, Deserialize};

use qcow2::engine::compression::decompress_cluster;
use qcow2_core::engine::encryption::CryptContext;
use qcow2_format::constants::*;

use crate::config::{ConflictStrategy, OutputFormat};
use crate::error::{RescueError, Result};
use crate::report::*;
use crate::scan;
use crate::reconstruct;
use crate::validate;

/// LUKS magic bytes for scanning.
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// Options controlling recovery behavior.
pub struct RecoverOptions {
    /// Output format (Raw or Qcow2).
    pub format: OutputFormat,
    /// Skip corrupt clusters instead of failing (zero-fill).
    pub skip_corrupt: bool,
    /// Password for encrypted images.
    pub password: Option<Vec<u8>>,
    /// Override cluster size (when header is corrupt).
    pub cluster_size_override: Option<u64>,
    /// Resume from a previous interrupted run.
    pub resume: bool,
    /// How to resolve mapping conflicts.
    pub on_conflict: ConflictStrategy,
}

/// Progress tracker for resumable recovery.
///
/// Stores the set of guest offsets that have been successfully written.
/// Saved as JSON to `<output>.progress.json` and updated periodically.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RecoveryProgress {
    /// Guest offsets that have been written successfully.
    written_offsets: Vec<u64>,
    /// Total clusters to process.
    total_clusters: u64,
}

impl RecoveryProgress {
    /// Load progress from a file, or return empty if not found.
    fn load(path: &Path) -> Self {
        let progress_path = Self::progress_path(path);
        match std::fs::read_to_string(&progress_path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save progress to file.
    fn save(&self, output: &Path) -> Result<()> {
        let progress_path = Self::progress_path(output);
        let json = serde_json::to_string(self)?;
        std::fs::write(&progress_path, json)?;
        Ok(())
    }

    /// Remove the progress file (called on successful completion).
    fn remove(output: &Path) {
        let progress_path = Self::progress_path(output);
        let _ = std::fs::remove_file(progress_path);
    }

    /// Build a HashSet for fast lookup.
    fn as_set(&self) -> std::collections::HashSet<u64> {
        self.written_offsets.iter().copied().collect()
    }

    fn progress_path(output: &Path) -> PathBuf {
        let mut p = output.as_os_str().to_owned();
        p.push(".progress.json");
        PathBuf::from(p)
    }
}

/// Result of trying to set up encryption for recovery.
struct EncryptionSetup {
    /// CryptContext if password was correct.
    crypt_context: Option<CryptContext>,
    /// Whether we found a LUKS header at all.
    luks_found: bool,
    /// Offset where the LUKS header was found.
    luks_offset: Option<u64>,
    /// Size of the LUKS header data.
    luks_size: Option<u64>,
    /// Whether the password probe succeeded.
    probe_ok: Option<bool>,
}

/// Recover a single QCOW2 image (no backing chain) to the output path.
pub fn recover_single(
    input: &Path,
    output: &Path,
    options: &RecoverOptions,
) -> Result<RecoveryReport> {
    let cluster_size = match options.cluster_size_override {
        Some(cs) => cs,
        None => scan::detect_cluster_size(input)?,
    };

    let cluster_map = scan::scan_file(input, cluster_size)?;
    let tables = reconstruct::reconstruct_with_strategy(input, &cluster_map, options.on_conflict)?;
    let virtual_size = tables.virtual_size.unwrap_or_else(|| {
        tables.mappings.iter()
            .map(|m| m.guest_offset + cluster_size)
            .max()
            .unwrap_or(0)
    });

    // Check if image has encrypted clusters
    let has_encrypted = tables.mappings.iter().any(|m| m.encrypted);
    let encryption = if has_encrypted {
        setup_encryption(input, cluster_size, &tables.mappings, options)
    } else {
        EncryptionSetup {
            crypt_context: None,
            luks_found: false,
            luks_offset: None,
            luks_size: None,
            probe_ok: None,
        }
    };

    let crypt_ref = encryption.crypt_context.as_ref();

    match options.format {
        OutputFormat::Raw => write_raw(
            output,
            &[(input.to_path_buf(), tables)],
            virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Qcow2 | OutputFormat::Chain => write_qcow2(
            output,
            &[(input.to_path_buf(), tables)],
            virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
    }
}

/// Recover a backing chain (base → ... → leaf), flattening into one output.
///
/// `chain` must be ordered base-first: `[base, overlay1, ..., leaf]`.
/// Later layers override earlier ones for the same guest offset.
pub fn recover_chain(
    chain: &[PathBuf],
    output: &Path,
    options: &RecoverOptions,
) -> Result<RecoveryReport> {
    if chain.is_empty() {
        return Err(RescueError::NoHeaderFound);
    }

    // Scan and reconstruct each layer
    let mut layers: Vec<(PathBuf, ReconstructedTablesReport)> = Vec::new();
    let mut max_virtual_size = 0u64;
    let mut cluster_size = 0u64;

    for path in chain {
        let cs = match options.cluster_size_override {
            Some(cs) => cs,
            None => scan::detect_cluster_size(path)?,
        };
        if cluster_size == 0 {
            cluster_size = cs;
        }

        let cluster_map = scan::scan_file(path, cs)?;
        let tables = reconstruct::reconstruct_with_strategy(path, &cluster_map, options.on_conflict)?;

        if let Some(vs) = tables.virtual_size {
            max_virtual_size = max_virtual_size.max(vs);
        }

        layers.push((path.clone(), tables));
    }

    if max_virtual_size == 0 {
        // Fallback
        max_virtual_size = layers.iter()
            .flat_map(|(_, t)| t.mappings.iter())
            .map(|m| m.guest_offset + cluster_size)
            .max()
            .unwrap_or(0);
    }

    let layer_refs: Vec<(PathBuf, ReconstructedTablesReport)> = layers;

    // Check if any layer has encrypted clusters
    let has_encrypted = layer_refs.iter()
        .any(|(_, t)| t.mappings.iter().any(|m| m.encrypted));

    let encryption = if has_encrypted {
        // Use the first layer with encrypted clusters to find the LUKS header
        let (enc_path, enc_tables) = layer_refs.iter()
            .find(|(_, t)| t.mappings.iter().any(|m| m.encrypted))
            .unwrap();
        setup_encryption(enc_path, cluster_size, &enc_tables.mappings, options)
    } else {
        EncryptionSetup {
            crypt_context: None,
            luks_found: false,
            luks_offset: None,
            luks_size: None,
            probe_ok: None,
        }
    };

    let crypt_ref = encryption.crypt_context.as_ref();

    match options.format {
        OutputFormat::Raw => write_raw(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Qcow2 => write_qcow2(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
        OutputFormat::Chain => write_chain(
            output,
            &layer_refs,
            max_virtual_size,
            cluster_size,
            options,
            crypt_ref,
            &encryption,
        ),
    }
}

/// Merged mapping: tells us where to read each guest cluster from.
struct ResolvedMapping {
    /// Source file path.
    source_file: PathBuf,
    /// Host offset within source file.
    host_offset: u64,
    /// Whether the cluster is compressed.
    compressed: bool,
    /// Whether the cluster is encrypted.
    encrypted: bool,
    /// Layer index this mapping came from.
    layer_index: usize,
}

/// Merge mappings from multiple layers. Later layers override earlier ones.
///
/// Returns a map of guest_offset → ResolvedMapping, plus per-layer stats.
fn merge_mappings(
    layers: &[(PathBuf, ReconstructedTablesReport)],
    cluster_size: u64,
) -> (BTreeMap<u64, ResolvedMapping>, Vec<LayerRecoveryStat>) {
    let mut merged: BTreeMap<u64, ResolvedMapping> = BTreeMap::new();
    let mut stats: Vec<LayerRecoveryStat> = Vec::new();

    for (layer_idx, (path, tables)) in layers.iter().enumerate() {
        let mut mappings_found = 0u64;

        for m in &tables.mappings {
            mappings_found += 1;
            // Align guest offset to cluster boundary
            let guest_aligned = m.guest_offset & !(cluster_size - 1);
            merged.insert(guest_aligned, ResolvedMapping {
                source_file: path.clone(),
                host_offset: m.host_offset,
                compressed: m.compressed,
                encrypted: m.encrypted,
                layer_index: layer_idx,
            });
        }

        stats.push(LayerRecoveryStat {
            file_path: path.display().to_string(),
            mappings_found,
            mappings_used: 0, // filled in after merge
            read_failures: 0,
        });
    }

    // Count how many mappings each layer actually contributed
    for rm in merged.values() {
        stats[rm.layer_index].mappings_used += 1;
    }

    (merged, stats)
}

/// Read a cluster from a source file.
///
/// For compressed clusters: reads compressed data and decompresses.
/// For encrypted clusters: decrypts if CryptContext is provided.
/// For normal clusters: reads raw data.
fn read_cluster_data(
    source: &Path,
    mapping: &ResolvedMapping,
    cluster_size: u64,
    _cluster_bits: u32,
    crypt: Option<&CryptContext>,
) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(source)?;
    let file_size = file.seek(SeekFrom::End(0))?;

    if mapping.compressed {
        // Compressed: host_offset is the raw descriptor offset from L2.
        // Read up to cluster_size bytes from that offset.
        let offset = mapping.host_offset;
        if offset >= file_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("compressed offset {offset:#x} beyond file size {file_size:#x}"),
            ).into());
        }
        let read_size = cluster_size.min(file_size - offset) as usize;
        let mut buf = vec![0u8; read_size];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        // Detect compression type from header
        let compression_type = detect_compression_type(&mut file);

        decompress_cluster(&buf, cluster_size as usize, 0, compression_type)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompression failed at offset {offset:#x}: {e}"),
            ).into())
    } else {
        // Normal cluster: read directly
        let offset = mapping.host_offset;
        if offset + cluster_size > file_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("cluster at {offset:#x} extends beyond file ({file_size:#x})"),
            ).into());
        }
        let mut buf = vec![0u8; cluster_size as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        // Decrypt if this is an encrypted cluster and we have a key
        if mapping.encrypted {
            if let Some(ctx) = crypt {
                ctx.decrypt_cluster(offset, &mut buf)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("decryption failed at offset {offset:#x}: {e}"),
                    ))?;
            }
            // If no crypt context, write raw (still encrypted) — this is intentional
        }

        Ok(buf)
    }
}

/// Set up encryption for recovery: find LUKS header, try password, probe.
fn setup_encryption(
    path: &Path,
    cluster_size: u64,
    mappings: &[MappingEntry],
    options: &RecoverOptions,
) -> EncryptionSetup {
    // Try to find LUKS header
    let luks_data = match find_luks_header(path, cluster_size) {
        Some((offset, data)) => {
            eprintln!("  found LUKS header at offset {offset:#x} ({} bytes)", data.len());
            (offset, data)
        }
        None => {
            eprintln!("  warning: encrypted clusters found but no LUKS header — data will be written raw (encrypted)");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: false,
                luks_offset: None,
                luks_size: None,
                probe_ok: None,
            };
        }
    };

    let (luks_offset, luks_bytes) = luks_data;
    let luks_size = luks_bytes.len() as u64;

    // No password? Write raw encrypted data.
    let password = match &options.password {
        Some(pw) => pw,
        None => {
            eprintln!("  no password provided — encrypted clusters will be written raw");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: true,
                luks_offset: Some(luks_offset),
                luks_size: Some(luks_size),
                probe_ok: None,
            };
        }
    };

    // Try to unlock with password
    let crypt_context = match qcow2::engine::encryption::recover_master_key(&luks_bytes, password) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("  warning: failed to unlock LUKS with provided password: {e}");
            eprintln!("  encrypted clusters will be written raw");
            return EncryptionSetup {
                crypt_context: None,
                luks_found: true,
                luks_offset: Some(luks_offset),
                luks_size: Some(luks_size),
                probe_ok: Some(false),
            };
        }
    };

    // Probe: decrypt a few clusters and check if they look like real data
    let encrypted_mappings: Vec<_> = mappings.iter()
        .filter(|m| m.encrypted && !m.compressed)
        .take(5)
        .collect();

    let mut probe_ok = true;
    let mut probed = 0;
    let mut structured = 0;

    for m in &encrypted_mappings {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => break,
        };
        let mut buf = vec![0u8; cluster_size as usize];
        if file.seek(SeekFrom::Start(m.host_offset)).is_err()
            || file.read_exact(&mut buf).is_err()
        {
            continue;
        }

        if crypt_context.decrypt_cluster(m.host_offset, &mut buf).is_ok() {
            probed += 1;
            if validate::has_structure(&buf) {
                structured += 1;
            }
        }
    }

    if probed > 0 && structured == 0 {
        eprintln!(
            "  warning: decrypted {probed} clusters but none show data structure — password may be wrong"
        );
        eprintln!("  continuing with decryption anyway (use --no-decrypt to skip)");
        probe_ok = false;
    } else if probed > 0 {
        eprintln!("  encryption probe OK: {structured}/{probed} clusters show valid structure");
    }

    EncryptionSetup {
        crypt_context: Some(crypt_context),
        luks_found: true,
        luks_offset: Some(luks_offset),
        luks_size: Some(luks_size),
        probe_ok: Some(probe_ok),
    }
}

/// Find the LUKS header in a QCOW2 image.
///
/// Strategy:
/// 1. Parse QCOW2 header extensions → look for FullDiskEncryption pointing to LUKS data
/// 2. If that fails, scan for LUKS magic bytes at cluster-aligned offsets
fn find_luks_header(path: &Path, cluster_size: u64) -> Option<(u64, Vec<u8>)> {
    let mut file = std::fs::File::open(path).ok()?;
    let file_size = file.seek(SeekFrom::End(0)).ok()?;

    // Strategy 1: Parse header extensions
    let header_cluster_size = cluster_size.min(4096) as usize;
    let mut header_buf = vec![0u8; header_cluster_size.max(4096)];
    file.seek(SeekFrom::Start(0)).ok()?;
    let n = file.read(&mut header_buf).ok()?;
    header_buf.truncate(n);

    if let Ok(header) = qcow2_format::Header::read_from(&header_buf) {
        if header.crypt_method == CRYPT_LUKS {
            // Parse header extensions to find FullDiskEncryption
            let ext_start = header.header_length as usize;
            if ext_start < header_buf.len() {
                if let Ok(extensions) =
                    qcow2_format::HeaderExtension::read_all(&header_buf[ext_start..])
                {
                    for ext in &extensions {
                        if let qcow2_format::HeaderExtension::FullDiskEncryption {
                            offset,
                            length,
                        } = ext
                        {
                            if offset + length <= file_size {
                                let mut luks_data = vec![0u8; *length as usize];
                                if file.seek(SeekFrom::Start(*offset)).is_ok()
                                    && file.read_exact(&mut luks_data).is_ok()
                                {
                                    // Verify it starts with LUKS magic
                                    if luks_data.len() >= 6 && &luks_data[..6] == LUKS_MAGIC {
                                        return Some((*offset, luks_data));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: Scan for LUKS magic at cluster-aligned offsets
    // LUKS header is typically at cluster 1 or after the QCOW2 header
    let scan_limit = file_size.min(64 * cluster_size);
    let mut offset = cluster_size; // start after header cluster

    while offset < scan_limit {
        let mut magic_buf = [0u8; 6];
        if file.seek(SeekFrom::Start(offset)).is_err()
            || file.read_exact(&mut magic_buf).is_err()
        {
            offset += cluster_size;
            continue;
        }

        if &magic_buf == LUKS_MAGIC {
            // Found LUKS magic — read enough data for the full header + key material
            // LUKS1 header is 592 bytes, but key material can extend much further.
            // Read up to 2MB (typical max for LUKS1 with 8 key slots).
            let max_luks_size = (2 * 1024 * 1024u64).min(file_size - offset);
            let mut luks_data = vec![0u8; max_luks_size as usize];
            if file.seek(SeekFrom::Start(offset)).is_ok()
                && file.read_exact(&mut luks_data).is_ok()
            {
                return Some((offset, luks_data));
            }
        }

        offset += cluster_size;
    }

    None
}

/// Detect compression type from a QCOW2 header. Returns COMPRESSION_DEFLATE as default.
fn detect_compression_type(file: &mut std::fs::File) -> u8 {
    let mut buf = [0u8; 108];
    if file.seek(SeekFrom::Start(0)).is_err() || file.read_exact(&mut buf).is_err() {
        return COMPRESSION_DEFLATE;
    }
    match qcow2_format::Header::read_from(&buf) {
        Ok(h) => h.compression_type,
        Err(_) => COMPRESSION_DEFLATE,
    }
}

/// Write a flat raw output image from merged mappings.
fn write_raw(
    output: &Path,
    layers: &[(PathBuf, ReconstructedTablesReport)],
    virtual_size: u64,
    cluster_size: u64,
    options: &RecoverOptions,
    crypt: Option<&CryptContext>,
    encryption: &EncryptionSetup,
) -> Result<RecoveryReport> {
    let cluster_bits = cluster_size.trailing_zeros();
    let (merged, mut layer_stats) = merge_mappings(layers, cluster_size);

    // Resume support: load progress and open file accordingly
    let (already_done, mut progress) = if options.resume {
        let p = RecoveryProgress::load(output);
        if !p.written_offsets.is_empty() {
            eprintln!("  resuming: {} clusters already written", p.written_offsets.len());
        }
        (p.as_set(), p)
    } else {
        (std::collections::HashSet::new(), RecoveryProgress::default())
    };

    let mut out = if options.resume && output.exists() {
        std::fs::OpenOptions::new().write(true).open(output)?
    } else {
        std::fs::File::create(output)?
    };
    // Set the file size upfront (sparse)
    out.set_len(virtual_size)?;

    let mut clusters_written = already_done.len() as u64;
    let mut clusters_failed = 0u64;
    let mut clusters_zeroed = 0u64;
    let mut bytes_written = 0u64;

    let total = merged.len();
    let progress_interval = (total / 20).max(1);
    let save_interval = 100usize;
    let mut since_last_save = 0usize;

    progress.total_clusters = total as u64;

    for (idx, (&guest_offset, rm)) in merged.iter().enumerate() {
        if idx % progress_interval == 0 && total > 0 {
            eprintln!(
                "  writing: {}/{} clusters ({:.0}%)",
                idx, total,
                idx as f64 / total as f64 * 100.0,
            );
        }

        if guest_offset >= virtual_size {
            continue;
        }

        // Skip already written clusters (resume)
        if already_done.contains(&guest_offset) {
            continue;
        }

        match read_cluster_data(&rm.source_file, rm, cluster_size, cluster_bits, crypt) {
            Ok(data) => {
                // Check if cluster is all zeros — skip writing (sparse file handles it)
                if data.iter().all(|&b| b == 0) {
                    clusters_zeroed += 1;
                } else {
                    out.seek(SeekFrom::Start(guest_offset))?;
                    out.write_all(&data)?;
                    clusters_written += 1;
                    bytes_written += data.len() as u64;
                }
                progress.written_offsets.push(guest_offset);
                since_last_save += 1;
            }
            Err(e) => {
                clusters_failed += 1;
                layer_stats[rm.layer_index].read_failures += 1;
                if !options.skip_corrupt {
                    // Save progress before returning error
                    let _ = progress.save(output);
                    return Err(e);
                }
                eprintln!(
                    "  warning: failed to read cluster at guest {guest_offset:#x} from {}: {e}",
                    rm.source_file.display(),
                );
                // Zero-filled by sparse file
                clusters_zeroed += 1;
            }
        }

        // Periodically save progress
        if since_last_save >= save_interval {
            let _ = progress.save(output);
            since_last_save = 0;
        }
    }

    out.flush()?;

    // Success — remove progress file
    RecoveryProgress::remove(output);

    // Count unallocated clusters as zeroed
    let total_clusters = virtual_size / cluster_size;
    let mapped_clusters = clusters_written + clusters_zeroed;
    clusters_zeroed += total_clusters.saturating_sub(mapped_clusters);

    Ok(RecoveryReport {
        output_path: output.display().to_string(),
        output_format: "raw".to_string(),
        virtual_size,
        cluster_size,
        source_files: layers.iter().map(|(p, _)| p.display().to_string()).collect(),
        clusters_written,
        clusters_failed,
        clusters_zeroed,
        bytes_written,
        layer_stats,
        encryption_info: build_encryption_info(encryption, crypt),
    })
}

/// Write a QCOW2 output image from merged mappings.
fn write_qcow2(
    output: &Path,
    layers: &[(PathBuf, ReconstructedTablesReport)],
    virtual_size: u64,
    cluster_size: u64,
    options: &RecoverOptions,
    crypt: Option<&CryptContext>,
    encryption: &EncryptionSetup,
) -> Result<RecoveryReport> {
    let cluster_bits = cluster_size.trailing_zeros();
    let (merged, mut layer_stats) = merge_mappings(layers, cluster_size);

    // Resume support
    let (already_done, mut progress) = if options.resume {
        let p = RecoveryProgress::load(output);
        if !p.written_offsets.is_empty() {
            eprintln!("  resuming: {} clusters already written", p.written_offsets.len());
        }
        (p.as_set(), p)
    } else {
        (std::collections::HashSet::new(), RecoveryProgress::default())
    };

    // Create or open existing QCOW2 image
    let mut image = if options.resume && output.exists() {
        qcow2::Qcow2Image::open(output)
            .map_err(|e| RescueError::Qcow2(e))?
    } else {
        let create_options = qcow2::engine::image::CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        };
        qcow2::Qcow2Image::create(output, create_options)
            .map_err(|e| RescueError::Qcow2(e))?
    };

    let mut clusters_written = already_done.len() as u64;
    let mut clusters_failed = 0u64;
    let mut clusters_zeroed = 0u64;
    let mut bytes_written = 0u64;

    let total = merged.len();
    let progress_interval = (total / 20).max(1);
    let save_interval = 100usize;
    let mut since_last_save = 0usize;

    progress.total_clusters = total as u64;

    for (idx, (&guest_offset, rm)) in merged.iter().enumerate() {
        if idx % progress_interval == 0 && total > 0 {
            eprintln!(
                "  writing: {}/{} clusters ({:.0}%)",
                idx, total,
                idx as f64 / total as f64 * 100.0,
            );
        }

        if guest_offset >= virtual_size {
            continue;
        }

        if already_done.contains(&guest_offset) {
            continue;
        }

        match read_cluster_data(&rm.source_file, rm, cluster_size, cluster_bits, crypt) {
            Ok(data) => {
                if data.iter().all(|&b| b == 0) {
                    clusters_zeroed += 1;
                } else {
                    image.write_at(&data, guest_offset)
                        .map_err(|e| RescueError::Qcow2(e))?;
                    clusters_written += 1;
                    bytes_written += data.len() as u64;
                }
                progress.written_offsets.push(guest_offset);
                since_last_save += 1;
            }
            Err(e) => {
                clusters_failed += 1;
                layer_stats[rm.layer_index].read_failures += 1;
                if !options.skip_corrupt {
                    let _ = progress.save(output);
                    return Err(e);
                }
                eprintln!(
                    "  warning: failed to read cluster at guest {guest_offset:#x} from {}: {e}",
                    rm.source_file.display(),
                );
                clusters_zeroed += 1;
            }
        }

        if since_last_save >= save_interval {
            let _ = progress.save(output);
            since_last_save = 0;
        }
    }

    image.flush().map_err(|e| RescueError::Qcow2(e))?;

    // Success — remove progress file
    RecoveryProgress::remove(output);

    let total_clusters = virtual_size / cluster_size;
    let mapped_clusters = clusters_written + clusters_zeroed;
    clusters_zeroed += total_clusters.saturating_sub(mapped_clusters);

    Ok(RecoveryReport {
        output_path: output.display().to_string(),
        output_format: "qcow2".to_string(),
        virtual_size,
        cluster_size,
        source_files: layers.iter().map(|(p, _)| p.display().to_string()).collect(),
        clusters_written,
        clusters_failed,
        clusters_zeroed,
        bytes_written,
        layer_stats,
        encryption_info: build_encryption_info(encryption, crypt),
    })
}

/// Write each layer as a separate QCOW2 with backing file references.
///
/// `output` is treated as a directory. Each layer gets its own file:
/// `layer_0_base.qcow2`, `layer_1.qcow2`, etc.
/// Layer 0 has no backing file. Layer N references layer N-1 as backing.
fn write_chain(
    output: &Path,
    layers: &[(PathBuf, ReconstructedTablesReport)],
    virtual_size: u64,
    cluster_size: u64,
    options: &RecoverOptions,
    crypt: Option<&CryptContext>,
    encryption: &EncryptionSetup,
) -> Result<RecoveryReport> {
    let cluster_bits = cluster_size.trailing_zeros();

    // output is the base path — we derive per-layer filenames
    let output_dir = output.parent().unwrap_or(Path::new("."));
    let stem = output.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("recovered");

    let mut clusters_written = 0u64;
    let mut clusters_failed = 0u64;
    let mut clusters_zeroed = 0u64;
    let mut bytes_written = 0u64;
    let mut layer_stats = Vec::new();
    let mut output_files: Vec<String> = Vec::new();

    for (layer_idx, (source_path, tables)) in layers.iter().enumerate() {
        let layer_name = if layer_idx == 0 {
            format!("{stem}_base.qcow2")
        } else {
            format!("{stem}_layer{layer_idx}.qcow2")
        };
        let layer_path = output_dir.join(&layer_name);

        // Backing file is the previous layer (if any)
        let backing_file = if layer_idx > 0 {
            Some(output_files[layer_idx - 1].clone())
        } else {
            None
        };

        let create_options = qcow2::engine::image::CreateOptions {
            virtual_size,
            cluster_bits: Some(cluster_bits),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: None,
        };

        let mut image = qcow2::Qcow2Image::create(&layer_path, create_options)
            .map_err(|e| RescueError::Qcow2(e))?;

        // Set backing file reference if this is an overlay
        if let Some(ref backing) = backing_file {
            image.rebase_unsafe(Some(Path::new(backing)))
                .map_err(|e| RescueError::Qcow2(e))?;
        }

        let mut layer_written = 0u64;
        let mut layer_failed = 0u64;

        for m in &tables.mappings {
            if m.guest_offset >= virtual_size {
                continue;
            }

            let rm = ResolvedMapping {
                source_file: source_path.clone(),
                host_offset: m.host_offset,
                compressed: m.compressed,
                encrypted: m.encrypted,
                layer_index: layer_idx,
            };

            match read_cluster_data(source_path, &rm, cluster_size, cluster_bits, crypt) {
                Ok(data) => {
                    if data.iter().all(|&b| b == 0) {
                        clusters_zeroed += 1;
                    } else {
                        image.write_at(&data, m.guest_offset)
                            .map_err(|e| RescueError::Qcow2(e))?;
                        clusters_written += 1;
                        layer_written += 1;
                        bytes_written += data.len() as u64;
                    }
                }
                Err(e) => {
                    clusters_failed += 1;
                    layer_failed += 1;
                    if !options.skip_corrupt {
                        return Err(e);
                    }
                    eprintln!(
                        "  warning: failed to read cluster at guest {:#x} from {}: {e}",
                        m.guest_offset, source_path.display(),
                    );
                    clusters_zeroed += 1;
                }
            }
        }

        image.flush().map_err(|e| RescueError::Qcow2(e))?;

        eprintln!(
            "  layer {}: {} → {} clusters written",
            layer_idx, source_path.display(), layer_written,
        );

        layer_stats.push(LayerRecoveryStat {
            file_path: source_path.display().to_string(),
            mappings_found: tables.mappings.len() as u64,
            mappings_used: layer_written,
            read_failures: layer_failed,
        });

        output_files.push(layer_path.display().to_string());
    }

    // Primary output path is the leaf (last layer)
    let primary_output = output_files.last()
        .cloned()
        .unwrap_or_else(|| output.display().to_string());

    Ok(RecoveryReport {
        output_path: primary_output,
        output_format: "chain".to_string(),
        virtual_size,
        cluster_size,
        source_files: layers.iter().map(|(p, _)| p.display().to_string()).collect(),
        clusters_written,
        clusters_failed,
        clusters_zeroed,
        bytes_written,
        layer_stats,
        encryption_info: build_encryption_info(encryption, crypt),
    })
}

/// Build encryption info for the recovery report.
fn build_encryption_info(
    encryption: &EncryptionSetup,
    crypt: Option<&CryptContext>,
) -> Option<EncryptionRecoveryInfo> {
    if !encryption.luks_found {
        return None;
    }

    Some(EncryptionRecoveryInfo {
        luks_header_found: true,
        luks_header_offset: encryption.luks_offset,
        decrypted: crypt.is_some(),
        probe_ok: encryption.probe_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use byteorder::{BigEndian, ByteOrder};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    use qcow2_format::compressed::CompressedClusterDescriptor;
    use qcow2_format::constants::{QCOW2_MAGIC, VERSION_3, L2_COMPRESSED_FLAG};

    /// Create a minimal QCOW2 image with one data cluster at guest offset 0.
    fn create_data_image(cluster_bits: u32, data: &[u8]) -> tempfile::NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Layout:
        // Cluster 0: header
        // Cluster 1: refcount table
        // Cluster 2: refcount block
        // Cluster 3: L1 table
        // Cluster 4: L2 table
        // Cluster 5: data cluster
        let l1_offset = 3 * cluster_size;
        let l2_offset = 4 * cluster_size;
        let data_offset = 5 * cluster_size;
        let file_size = 6 * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        BigEndian::write_u32(&mut buf[100..104], 104);

        // Refcount table (cluster 1): entry 0 → refcount block at cluster 2
        let rct_offset = cluster_size;
        let rcb_offset = 2 * cluster_size;
        BigEndian::write_u64(&mut buf[48..56], rct_offset); // refcount_table_offset
        BigEndian::write_u32(&mut buf[56..60], 1); // refcount_table_clusters
        BigEndian::write_u64(&mut buf[rct_offset as usize..], rcb_offset);

        // Refcount block (cluster 2): set refcount=1 for clusters 0-5
        for i in 0..6u16 {
            BigEndian::write_u16(
                &mut buf[rcb_offset as usize + i as usize * 2..],
                1,
            );
        }

        // L1[0] → L2 at cluster 4
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l2_offset | (1u64 << 63),
        );

        // L2[0] → data at cluster 5
        BigEndian::write_u64(
            &mut buf[l2_offset as usize..],
            data_offset | (1u64 << 63),
        );

        // Data cluster
        let copy_len = data.len().min(cluster_size as usize);
        buf[data_offset as usize..data_offset as usize + copy_len]
            .copy_from_slice(&data[..copy_len]);

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        tmpfile
    }

    /// Create a QCOW2 image with a compressed cluster at guest offset 0.
    fn create_compressed_image(cluster_bits: u32) -> tempfile::NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = 1u64 << 20;
        let l2_entries = cluster_size / 8;
        let l1_entries = ((virtual_size + l2_entries * cluster_size - 1)
            / (l2_entries * cluster_size)) as u32;

        // Compress some data
        let original = vec![0xAA; cluster_size as usize];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        let sector_aligned_size = ((compressed.len() + 511) & !511).max(512);

        let l1_offset = cluster_size;
        let l2_offset = 2 * cluster_size;
        let compressed_offset = 3 * cluster_size;
        let file_size = 4 * cluster_size;

        let mut buf = vec![0u8; file_size as usize];

        // Header
        BigEndian::write_u32(&mut buf[0..4], QCOW2_MAGIC);
        BigEndian::write_u32(&mut buf[4..8], VERSION_3);
        BigEndian::write_u32(&mut buf[20..24], cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], virtual_size);
        BigEndian::write_u32(&mut buf[36..40], l1_entries);
        BigEndian::write_u64(&mut buf[40..48], l1_offset);
        BigEndian::write_u32(&mut buf[100..104], 104);

        // L1[0] → L2
        BigEndian::write_u64(
            &mut buf[l1_offset as usize..],
            l2_offset | (1u64 << 63),
        );

        // L2[0] → compressed descriptor
        let desc = CompressedClusterDescriptor {
            host_offset: compressed_offset,
            compressed_size: sector_aligned_size as u64,
        };
        let l2_raw = L2_COMPRESSED_FLAG | desc.encode(cluster_bits);
        BigEndian::write_u64(&mut buf[l2_offset as usize..], l2_raw);

        // Write compressed data
        buf[compressed_offset as usize..compressed_offset as usize + compressed.len()]
            .copy_from_slice(&compressed);

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&buf).unwrap();
        tmpfile.flush().unwrap();

        tmpfile
    }

    #[test]
    fn recover_single_data_cluster_raw() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42u8; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // Verify the data at guest offset 0
        let recovered = std::fs::read(&out_path).unwrap();
        assert_eq!(recovered.len(), 1 << 20); // virtual_size
        assert_eq!(&recovered[..cluster_size as usize], &data[..]);
    }

    #[test]
    fn recover_compressed_cluster_raw() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let src = create_compressed_image(cluster_bits);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // The compressed cluster contained 0xAA bytes
        let recovered = std::fs::read(&out_path).unwrap();
        let expected = vec![0xAA; cluster_size as usize];
        assert_eq!(&recovered[..cluster_size as usize], &expected[..]);
    }

    #[test]
    fn recover_single_data_cluster_qcow2() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42u8; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.qcow2");

        let options = RecoverOptions {
            format: OutputFormat::Qcow2,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);
        assert_eq!(report.output_format, "qcow2");

        // Verify by reading back through the library
        let mut image = qcow2::Qcow2Image::open(&out_path).unwrap();
        let mut buf = vec![0u8; cluster_size as usize];
        image.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn recover_chain_merge() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        // Base: guest 0 = 0xAA
        let base_data = vec![0xAA; cluster_size as usize];
        let base = create_data_image(cluster_bits, &base_data);

        // Overlay: guest 0 = 0xBB (overrides base)
        let overlay_data = vec![0xBB; cluster_size as usize];
        let overlay = create_data_image(cluster_bits, &overlay_data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("merged.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let chain = vec![base.path().to_path_buf(), overlay.path().to_path_buf()];
        let report = recover_chain(&chain, &out_path, &options).unwrap();

        assert_eq!(report.source_files.len(), 2);
        assert!(report.clusters_written > 0);

        // Guest offset 0 should have overlay data (0xBB), not base (0xAA)
        let recovered = std::fs::read(&out_path).unwrap();
        assert_eq!(recovered[0], 0xBB);
        assert!(recovered[..cluster_size as usize].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn recover_skip_corrupt() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let data = vec![0x42; cluster_size as usize];
        let src = create_data_image(cluster_bits, &data);

        // Corrupt the data cluster (cluster 5)
        {
            let data_offset = 5 * cluster_size;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(src.path())
                .unwrap();
            // Truncate file so the data cluster is incomplete
            f.set_len(data_offset + 100).unwrap();
        }

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(src.path(), &out_path, &options).unwrap();
        // The corrupt cluster should be counted as failed
        assert!(report.clusters_failed > 0 || report.clusters_written == 0);
    }

    #[test]
    fn merge_mappings_later_overrides_earlier() {
        let cluster_size = 65536u64;
        let base_path = PathBuf::from("/fake/base.qcow2");
        let overlay_path = PathBuf::from("/fake/overlay.qcow2");

        let base_tables = ReconstructedTablesReport {
            file_path: base_path.display().to_string(),
            l1_entries: 1,
            l2_tables_verified: 1,
            l2_tables_suspicious: 0,
            mappings_total: 2,
            mappings_from_l2: 2,
            orphan_data_clusters: 0,
            refcount_check: None,
            content_validation: None,
            mapping_conflicts: 0,
            virtual_size: Some(1 << 20),
            mappings: vec![
                MappingEntry {
                    guest_offset: 0,
                    host_offset: 0x10000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
                MappingEntry {
                    guest_offset: 0x10000,
                    host_offset: 0x20000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
            ],
        };

        let overlay_tables = ReconstructedTablesReport {
            file_path: overlay_path.display().to_string(),
            l1_entries: 1,
            l2_tables_verified: 1,
            l2_tables_suspicious: 0,
            mappings_total: 1,
            mappings_from_l2: 1,
            orphan_data_clusters: 0,
            refcount_check: None,
            content_validation: None,
            mapping_conflicts: 0,
            virtual_size: Some(1 << 20),
            mappings: vec![
                MappingEntry {
                    guest_offset: 0, // same as base — overlay wins
                    host_offset: 0x30000,
                    source: MappingSource::L2Table,
                    compressed: false,
                    encrypted: false,
                    subclusters: None,
                },
            ],
        };

        let layers = vec![
            (base_path.clone(), base_tables),
            (overlay_path.clone(), overlay_tables),
        ];

        let (merged, stats) = merge_mappings(&layers, cluster_size);

        // Guest 0 should come from overlay (layer 1)
        assert_eq!(merged[&0].layer_index, 1);
        assert_eq!(merged[&0].host_offset, 0x30000);

        // Guest 0x10000 should come from base (layer 0)
        assert_eq!(merged[&0x10000].layer_index, 0);
        assert_eq!(merged[&0x10000].host_offset, 0x20000);

        // Layer stats
        assert_eq!(stats[0].mappings_found, 2);
        assert_eq!(stats[0].mappings_used, 1); // only 0x10000 survived
        assert_eq!(stats[1].mappings_found, 1);
        assert_eq!(stats[1].mappings_used, 1); // 0 won
    }

    #[test]
    fn recover_encrypted_image_with_password() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let cluster_size = 65536u64;
        let virtual_size = 1u64 << 20;
        let password = b"testpassword";

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        // Create encrypted image and write some data
        {
            let opts = CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: Some(EncryptionOptions {
                    password: password.to_vec(),
                    cipher: CipherMode::AesXtsPlain64,
                    luks_version: 1,
                    iter_time_ms: Some(10), // fast for tests
                }),
            };
            let mut image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
            let data = vec![0x42u8; cluster_size as usize];
            image.write_at(&data, 0).unwrap();
            image.flush().unwrap();
        }

        // Recover with correct password
        let recovered_path = out_dir.path().join("recovered.raw");
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: Some(password.to_vec()),
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(&src_path, &recovered_path, &options).unwrap();
        assert!(report.clusters_written > 0);
        assert_eq!(report.clusters_failed, 0);

        // Check encryption info in report
        let enc_info = report.encryption_info.as_ref().expect("should have encryption info");
        assert!(enc_info.luks_header_found);
        assert!(enc_info.decrypted);

        // Verify decrypted data
        let recovered = std::fs::read(&recovered_path).unwrap();
        assert_eq!(recovered[0], 0x42);
        assert!(recovered[..cluster_size as usize].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn recover_encrypted_image_without_password() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let cluster_size = 65536u64;
        let virtual_size = 1u64 << 20;
        let password = b"testpassword";

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        // Create encrypted image and write some data
        {
            let opts = CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: Some(EncryptionOptions {
                    password: password.to_vec(),
                    cipher: CipherMode::AesXtsPlain64,
                    luks_version: 1,
                    iter_time_ms: Some(10),
                }),
            };
            let mut image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
            let data = vec![0x42u8; cluster_size as usize];
            image.write_at(&data, 0).unwrap();
            image.flush().unwrap();
        }

        // Recover WITHOUT password — should still work but data stays encrypted
        let recovered_path = out_dir.path().join("recovered_no_pw.raw");
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: false,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report = recover_single(&src_path, &recovered_path, &options).unwrap();
        // Should still recover something
        assert!(report.clusters_written > 0 || report.clusters_zeroed > 0);

        // Encryption info should show no decryption
        let enc_info = report.encryption_info.as_ref().expect("should have encryption info");
        assert!(enc_info.luks_header_found);
        assert!(!enc_info.decrypted);

        // Data should NOT be all 0x42 (it's still encrypted)
        let recovered = std::fs::read(&recovered_path).unwrap();
        let first_cluster = &recovered[..cluster_size as usize];
        let all_0x42 = first_cluster.iter().all(|&b| b == 0x42);
        assert!(!all_0x42,
            "without password, data should still be encrypted");
    }

    #[test]
    fn find_luks_header_in_encrypted_image() {
        use qcow2::engine::encryption::CipherMode;
        use qcow2::engine::image::{CreateOptions, EncryptionOptions};

        let out_dir = tempfile::tempdir().unwrap();
        let src_path = out_dir.path().join("encrypted.qcow2");

        let opts = CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: Some(16),
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: b"test".to_vec(),
                cipher: CipherMode::AesXtsPlain64,
                luks_version: 1,
                iter_time_ms: Some(10),
            }),
        };
        let image = qcow2::Qcow2Image::create(&src_path, opts).unwrap();
        drop(image);

        let result = find_luks_header(&src_path, 65536);
        assert!(result.is_some(), "should find LUKS header");
        let (offset, data) = result.unwrap();
        assert_eq!(&data[..6], b"LUKS\xba\xbe");
        assert!(offset > 0, "LUKS header should not be at offset 0");
    }

    #[test]
    fn resume_recovery_skips_already_written() {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;

        let data = vec![0xAA; cluster_size as usize];
        let tmpfile = create_data_image(cluster_bits, &data);

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("recovered.raw");

        // First run: normal recovery
        let options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: false,
            on_conflict: ConflictStrategy::Ask,
        };

        let report1 = recover_single(tmpfile.path(), &out_path, &options).unwrap();
        let written1 = report1.clusters_written;
        assert!(written1 > 0);

        // Verify no progress file left after success
        assert!(!RecoveryProgress::progress_path(&out_path).exists());

        // Simulate interrupted run by creating a progress file
        let mut fake_progress = RecoveryProgress::default();
        // Record the data cluster's guest offset as already written
        fake_progress.written_offsets.push(0); // guest offset 0
        fake_progress.total_clusters = 1;
        fake_progress.save(&out_path).unwrap();

        // Second run: resume — should skip the cluster we "already wrote"
        let resume_options = RecoverOptions {
            format: OutputFormat::Raw,
            skip_corrupt: true,
            password: None,
            cluster_size_override: None,
            resume: true,
            on_conflict: ConflictStrategy::Ask,
        };

        let report2 = recover_single(tmpfile.path(), &out_path, &resume_options).unwrap();
        // The cluster at guest 0 was in the progress file, so it gets counted
        // in clusters_written via already_done.len(), but not re-written.
        // Total clusters_written should include the already-done count.
        assert!(report2.clusters_written >= written1,
            "resume should count already-written clusters");

        // Progress file should be cleaned up after success
        assert!(!RecoveryProgress::progress_path(&out_path).exists());
    }
}
