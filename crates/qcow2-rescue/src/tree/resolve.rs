//! QCOW2 header parsing and backing file path resolution.

use std::path::Path;

/// Information extracted from a single QCOW2 file's header.
pub(super) struct FileInfo {
    pub backing_file: Option<String>,
    pub virtual_size: Option<u64>,
    pub cluster_size: Option<u64>,
    pub header_intact: bool,
    pub allocated_clusters: u64,
}

impl FileInfo {
    fn unreadable() -> Self {
        Self {
            backing_file: None,
            virtual_size: None,
            cluster_size: None,
            header_intact: false,
            allocated_clusters: 0,
        }
    }
}

/// Read metadata from a QCOW2 file's header.
pub(super) fn read_file_info(path: &Path) -> FileInfo {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return FileInfo::unreadable(),
    };

    let mut header_buf = vec![0u8; 4096];
    let bytes_read = match file.read(&mut header_buf) {
        Ok(n) => n,
        Err(_) => return FileInfo::unreadable(),
    };
    header_buf.truncate(bytes_read);

    match qcow2_format::Header::read_from(&header_buf) {
        Ok(header) => {
            let cluster_size = 1u64 << header.cluster_bits;

            // Read backing file name if present
            let backing_file = if header.backing_file_offset > 0 && header.backing_file_size > 0 {
                let off = header.backing_file_offset as usize;
                let len = header.backing_file_size as usize;
                if off + len <= header_buf.len() {
                    Some(
                        String::from_utf8_lossy(&header_buf[off..off + len]).to_string(),
                    )
                } else {
                    read_backing_name(
                        &mut file,
                        header.backing_file_offset,
                        header.backing_file_size,
                    )
                }
            } else {
                None
            };

            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let allocated_clusters = if cluster_size > 0 {
                file_size / cluster_size
            } else {
                0
            };

            FileInfo {
                backing_file,
                virtual_size: Some(header.virtual_size),
                cluster_size: Some(cluster_size),
                header_intact: true,
                allocated_clusters,
            }
        }
        Err(_) => FileInfo::unreadable(),
    }
}

/// Read the backing file name from the image.
fn read_backing_name(file: &mut std::fs::File, offset: u64, size: u32) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; size as usize];
    file.read_exact(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Resolve a backing file path relative to the referencing file.
pub(super) fn resolve_backing_path(referencing_file: &str, backing_ref: &str) -> String {
    let backing_path = Path::new(backing_ref);
    if backing_path.is_absolute() {
        return backing_ref.to_string();
    }

    if let Some(parent) = Path::new(referencing_file).parent() {
        let resolved = parent.join(backing_ref);
        resolved
            .canonicalize()
            .unwrap_or(resolved)
            .display()
            .to_string()
    } else {
        backing_ref.to_string()
    }
}
