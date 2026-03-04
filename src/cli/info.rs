//! `info` subcommand: display QCOW2 header information.

use std::path::Path;

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;

/// Run the info subcommand, printing header details to stdout.
pub fn run(path: &Path) -> Result<()> {
    let image = Qcow2Image::open(path)?;
    let header = image.header();

    println!("QCOW2 Image: {}", path.display());
    println!("  Version:          {}", header.version);
    println!("  Virtual size:     {} bytes ({:.2} GiB)",
        header.virtual_size,
        header.virtual_size as f64 / (1024.0 * 1024.0 * 1024.0),
    );
    println!("  Cluster bits:     {}", header.cluster_bits);
    println!("  Cluster size:     {} bytes ({} KiB)",
        image.cluster_size(),
        image.cluster_size() / 1024,
    );
    println!("  L1 table entries: {}", header.l1_table_entries);
    println!("  L1 table offset:  0x{:x}", header.l1_table_offset.0);
    println!("  Refcount order:   {} ({}-bit refcounts)",
        header.refcount_order,
        header.refcount_bits(),
    );
    println!("  Refcount table:   0x{:x} ({} clusters)",
        header.refcount_table_offset.0,
        header.refcount_table_clusters,
    );
    if header.has_extended_l2() {
        println!("  Extended L2:      yes (subcluster size: {} bytes)",
            header.subcluster_size().unwrap_or(0));
    }
    println!("  Snapshots:        {}", header.snapshot_count);
    println!("  Encryption:       {}",
        match header.crypt_method {
            0 => "none",
            1 => "AES-CBC",
            2 => "LUKS",
            _ => "unknown",
        },
    );

    if header.has_backing_file() {
        if let Some(chain) = image.backing_chain() {
            println!("  Backing chain:    {} file(s)", chain.depth());
            for entry in chain.entries() {
                println!("    - {}", entry.path.display());
            }
        } else {
            println!("  Backing file:     (referenced but not resolved)");
        }
    }

    // Feature flags (v3)
    if header.version >= 3 {
        if !header.incompatible_features.is_empty() {
            println!("  Incompatible:     {:?}", header.incompatible_features);
        }
        if !header.compatible_features.is_empty() {
            println!("  Compatible:       {:?}", header.compatible_features);
        }
        if !header.autoclear_features.is_empty() {
            println!("  Autoclear:        {:?}", header.autoclear_features);
        }
    }

    // Header extensions
    let extensions = image.extensions();
    if !extensions.is_empty() {
        println!("  Extensions:       {}", extensions.len());
        for ext in extensions {
            println!("    - {ext:?}");
        }
    }

    Ok(())
}
