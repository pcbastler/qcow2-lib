//! Image creation: `create`, `create_on_backend`, `create_overlay`,
//! `create_overlay_on_backend`.

use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::read_mode::ReadMode;
use crate::engine::refcount_manager::{AllocationMode, RefcountManager};
use crate::error::{external_data_error, Error, FormatError, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::L1Table;
use crate::format::types::{ClusterGeometry, ClusterOffset};
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

use super::{CreateOptions, EncryptionOptions, Qcow2Image};

/// Validate create options and return resolved values.
///
/// Returns (cluster_bits, cluster_size, extended_l2, compression_type, data_file, encryption).
#[allow(clippy::type_complexity)]
pub(crate) fn validate_create_options(
    options: &CreateOptions,
) -> Result<(u32, u64, bool, u8, Option<String>, Option<EncryptionOptions>)> {
    if options.virtual_size == 0 {
        return Err(Error::InvalidVirtualSize { size: 0 });
    }
    if let Some(bits) = options.cluster_bits {
        if !(crate::format::constants::MIN_CLUSTER_BITS..=crate::format::constants::MAX_CLUSTER_BITS).contains(&bits) {
            return Err(FormatError::InvalidClusterBits {
                cluster_bits: bits,
                min: crate::format::constants::MIN_CLUSTER_BITS,
                max: crate::format::constants::MAX_CLUSTER_BITS,
            }
            .into());
        }
    }
    if let Some(ct) = options.compression_type {
        if ct != crate::format::constants::COMPRESSION_DEFLATE
            && ct != crate::format::constants::COMPRESSION_ZSTD
        {
            return Err(FormatError::UnsupportedCompressionType {
                compression_type: ct,
            }
            .into());
        }
    }

    let cluster_bits = options.cluster_bits.unwrap_or(16);
    let cluster_size = 1u64 << cluster_bits;
    let extended_l2 = options.extended_l2;
    let compression_type = options
        .compression_type
        .unwrap_or(crate::format::constants::COMPRESSION_DEFLATE);

    if extended_l2 && cluster_bits < crate::format::constants::MIN_CLUSTER_BITS_EXTENDED_L2 {
        return Err(FormatError::ExtendedL2ClusterBitsTooSmall {
            cluster_bits,
            min: crate::format::constants::MIN_CLUSTER_BITS_EXTENDED_L2,
        }
        .into());
    }
    if options.data_file.is_some()
        && compression_type != crate::format::constants::COMPRESSION_DEFLATE
    {
        return Err(Error::CompressedWithExternalData);
    }
    if options.encryption.is_some()
        && compression_type != crate::format::constants::COMPRESSION_DEFLATE
    {
        return Err(Error::EncryptionWithCompression);
    }

    Ok((
        cluster_bits,
        cluster_size,
        extended_l2,
        compression_type,
        options.data_file.clone(),
        options.encryption.clone(),
    ))
}

/// Calculate the number of L1 table entries needed for a given virtual size.
pub(crate) fn calculate_l1_entries(virtual_size: u64, cluster_size: u64, l2_entry_size: u64) -> u32 {
    let l2_entries = cluster_size / l2_entry_size;
    let bytes_per_l1_entry = l2_entries * cluster_size;
    ((virtual_size + bytes_per_l1_entry - 1) / bytes_per_l1_entry) as u32
}

/// Debug-assert that the initial image layout has no overlapping metadata regions.
#[inline]
fn debug_assert_layout_no_overlap(
    l1_offset: u64,
    l1_clusters: u64,
    cluster_size: u64,
    rt_offset: u64,
    rb_offset: u64,
) {
    let l1_end = l1_offset + l1_clusters * cluster_size;
    debug_assert!(
        l1_end <= rt_offset,
        "L1 table ({:#x}..{:#x}) overlaps refcount table at {:#x}",
        l1_offset, l1_end, rt_offset
    );
    debug_assert!(
        rt_offset + cluster_size <= rb_offset,
        "refcount table ({:#x}) overlaps refcount block at {:#x}",
        rt_offset, rb_offset
    );
}

/// Write the initial on-disk layout: zeroed clusters, refcount table, and refcount block.
///
/// This is shared between `create_on_backend` and `create_overlay_on_backend`.
fn write_initial_layout(
    backend: &dyn IoBackend,
    cluster_size: u64,
    initial_clusters: u64,
    rt_offset: u64,
    rb_offset: u64,
) -> Result<()> {
    // Write zeroed clusters
    let zeroed_cluster = vec![0u8; cluster_size as usize];
    for i in 0..initial_clusters {
        backend.write_all_at(&zeroed_cluster, i * cluster_size)?;
    }

    // Write refcount table: entry 0 → refcount block
    let mut rt_buf = [0u8; 8];
    BigEndian::write_u64(&mut rt_buf, rb_offset);
    backend.write_all_at(&rt_buf, rt_offset)?;

    // Write refcount block: initial clusters have refcount 1
    let mut rb_buf = vec![0u8; cluster_size as usize];
    for i in 0..initial_clusters as usize {
        BigEndian::write_u16(&mut rb_buf[i * 2..], 1);
    }
    backend.write_all_at(&rb_buf, rb_offset)?;

    Ok(())
}

/// Generate a LUKS1 header and encryption context from encryption options.
pub(crate) fn generate_luks_header(
    encryption: &Option<EncryptionOptions>,
) -> Result<(Option<Vec<u8>>, Option<crate::engine::encryption::CryptContext>)> {
    let Some(enc) = encryption else {
        return Ok((None, None));
    };
    let key_bytes = match enc.cipher {
        crate::engine::encryption::CipherMode::AesXtsPlain64 => 64u32,
        crate::engine::encryption::CipherMode::AesCbcEssiv => 32u32,
    };
    let (header_bytes, mk) = crate::engine::encryption::create::create_luks1_header(
        &enc.password,
        enc.cipher,
        key_bytes,
        enc.iter_time_ms.map(|ms| ms.max(1000)),
    )?;
    let ctx = crate::engine::encryption::CryptContext::new(mk, enc.cipher);
    Ok((Some(header_bytes), Some(ctx)))
}

/// Build incompatible/autoclear feature flags and header_length from options.
pub(crate) fn build_feature_flags(
    extended_l2: bool,
    compression_type: u8,
    has_data_file: bool,
) -> (IncompatibleFeatures, AutoclearFeatures, u32) {
    let mut incompat = IncompatibleFeatures::empty();
    if extended_l2 {
        incompat |= IncompatibleFeatures::EXTENDED_L2;
    }
    if compression_type != crate::format::constants::COMPRESSION_DEFLATE {
        incompat |= IncompatibleFeatures::COMPRESSION_TYPE;
    }
    if has_data_file {
        incompat |= IncompatibleFeatures::EXTERNAL_DATA_FILE;
    }

    let mut autoclear = AutoclearFeatures::empty();
    if has_data_file {
        autoclear |= AutoclearFeatures::RAW_EXTERNAL;
    }

    let header_length = if compression_type != crate::format::constants::COMPRESSION_DEFLATE {
        (crate::format::constants::HEADER_V3_MIN_LENGTH + 1) as u32
    } else {
        crate::format::constants::HEADER_V3_MIN_LENGTH as u32
    };

    (incompat, autoclear, header_length)
}

/// Build the Header struct for a new image.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_create_header(
    cluster_bits: u32, virtual_size: u64, encrypted: bool,
    l1_entries: u32, l1_offset: u64, rt_offset: u64,
    incompat: IncompatibleFeatures, autoclear: AutoclearFeatures,
    refcount_order: u32, header_length: u32, compression_type: u8,
) -> Header {
    Header {
        version: 3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits,
        virtual_size,
        crypt_method: if encrypted { crate::format::constants::CRYPT_LUKS } else { 0 },
        l1_table_entries: l1_entries,
        l1_table_offset: ClusterOffset(l1_offset),
        refcount_table_offset: ClusterOffset(rt_offset),
        refcount_table_clusters: 1,
        snapshot_count: 0,
        snapshots_offset: ClusterOffset(0),
        incompatible_features: incompat,
        compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
        autoclear_features: autoclear,
        refcount_order,
        header_length,
        compression_type,
    }
}

/// Build header extensions for a newly created image.
pub(crate) fn build_create_extensions(
    luks_header_data: &Option<Vec<u8>>,
    luks_offset: u64,
    data_file: &Option<String>,
) -> Vec<HeaderExtension> {
    let mut extensions = Vec::new();
    if let Some(ref data) = luks_header_data {
        extensions.push(HeaderExtension::FullDiskEncryption {
            offset: luks_offset,
            length: data.len() as u64,
        });
    }
    if let Some(ref name) = data_file {
        extensions.push(HeaderExtension::ExternalDataFile(name.clone()));
    }
    extensions
}

/// Write header, extensions, and LUKS data to the backend.
#[allow(clippy::too_many_arguments)]
fn write_image_to_backend(
    backend: &dyn IoBackend,
    header: &Header,
    extensions: &[HeaderExtension],
    header_length: u32,
    cluster_size: u64,
    initial_clusters: u64,
    rt_offset: u64,
    rb_offset: u64,
    luks_offset: u64,
    luks_clusters: u64,
    luks_header_data: &Option<Vec<u8>>,
) -> Result<()> {
    write_initial_layout(backend, cluster_size, initial_clusters, rt_offset, rb_offset)?;

    let mut header_buf = vec![0u8; cluster_size as usize];
    header.write_to(&mut header_buf)?;

    if !extensions.is_empty() {
        let ext_data = HeaderExtension::write_all(extensions);
        let ext_offset = header_length as usize;
        header_buf[ext_offset..ext_offset + ext_data.len()].copy_from_slice(&ext_data);
    }
    backend.write_all_at(&header_buf, 0)?;

    if let Some(ref luks_data) = luks_header_data {
        let padded_len = (luks_clusters as usize) * (cluster_size as usize);
        let mut padded = vec![0u8; padded_len];
        padded[..luks_data.len()].copy_from_slice(luks_data);
        backend.write_all_at(&padded, luks_offset)?;
    }

    backend.flush()
}

impl Qcow2Image {
    /// Create a new QCOW2 v3 image at the given path.
    ///
    /// Returns a writable `Qcow2Image` ready for writes. The image is
    /// created with a minimal on-disk layout:
    ///
    /// - Cluster 0: header
    /// - Clusters 1..N: L1 table (N depends on virtual size)
    /// - Cluster N+1: refcount table (1 cluster)
    /// - Cluster N+2: refcount block 0
    pub fn create<P: AsRef<Path>>(path: P, options: CreateOptions) -> Result<Self> {
        let path = path.as_ref();
        let data_file_name = options.data_file.clone();
        let virtual_size = options.virtual_size;

        let backend = SyncFileBackend::create(path).map_err(|e| {
            if let Error::Io { message, .. } = &e {
                Error::CreateFailed {
                    message: message.clone(),
                    path: path.display().to_string(),
                }
            } else {
                e
            }
        })?;

        let mut image = Self::create_on_backend(Box::new(backend), options)?;

        // Create the external data file if requested
        if let Some(ref name) = data_file_name {
            let image_dir = path.parent().unwrap_or(Path::new("."));
            let data_path = image_dir.join(name);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&data_path)
                .map_err(|e| external_data_error(e, data_path.display().to_string()))?;
            // Pre-allocate to virtual_size so guest offsets are valid
            file.set_len(virtual_size)
                .map_err(|e| external_data_error(e, data_path.display().to_string()))?;
            image.data_backend = Some(Box::new(SyncFileBackend::from_file(file)));
        }

        Ok(image)
    }

    /// Create a new QCOW2 v3 image on an I/O backend (for testing).
    pub fn create_on_backend(
        backend: Box<dyn IoBackend>,
        options: CreateOptions,
    ) -> Result<Self> {
        let (cluster_bits, cluster_size, extended_l2, compression_type, data_file, encryption) =
            validate_create_options(&options)?;

        let refcount_order = 4u32; // 16-bit refcounts
        let l2_entry_size = if extended_l2 { 16u64 } else { 8u64 };
        let l1_entries = calculate_l1_entries(options.virtual_size, cluster_size, l2_entry_size);

        let (luks_header_data, crypt_context) = generate_luks_header(&encryption)?;
        let luks_clusters = luks_header_data
            .as_ref()
            .map(|d| (d.len() as u64 + cluster_size - 1) / cluster_size)
            .unwrap_or(0);

        let l1_clusters = ((l1_entries as u64 * 8) + cluster_size - 1) / cluster_size;
        let l1_offset = cluster_size;
        let rt_offset = (1 + l1_clusters) * cluster_size;
        let rb_offset = (2 + l1_clusters) * cluster_size;
        let luks_offset = (3 + l1_clusters) * cluster_size;
        let initial_clusters = 3 + l1_clusters + luks_clusters;

        debug_assert_layout_no_overlap(l1_offset, l1_clusters, cluster_size, rt_offset, rb_offset);

        let (incompat, autoclear, header_length) =
            build_feature_flags(extended_l2, compression_type, data_file.is_some());

        let header = build_create_header(
            cluster_bits, options.virtual_size, encryption.is_some(),
            l1_entries, l1_offset, rt_offset, incompat, autoclear,
            refcount_order, header_length, compression_type,
        );

        let extensions = build_create_extensions(&luks_header_data, luks_offset, &data_file);

        write_image_to_backend(
            backend.as_ref(), &header, &extensions, header_length,
            cluster_size, initial_clusters, rt_offset, rb_offset,
            luks_offset, luks_clusters, &luks_header_data,
        )?;

        let l1_table = L1Table::new_empty(l1_entries);
        let file_size = backend.file_size()?;
        let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits, extended_l2 }, file_size);
        let refcount_manager = RefcountManager::load_with_mode(
            backend.as_ref(), &header, AllocationMode::Append,
        )?;

        Ok(Self::new_inner(
            header, extensions, backend,
            None, mapper, None, None,
            ReadMode::Strict, Vec::new(),
            Some(refcount_manager), true, false, false, crypt_context,
        ))
    }

    /// Create a new QCOW2 v3 overlay image at the given path.
    ///
    /// The overlay references the given backing file. Reads of unallocated
    /// clusters fall through to the backing image; writes go to the overlay.
    pub fn create_overlay<P: AsRef<Path>, Q: AsRef<Path>>(
        path: P,
        backing_path: Q,
        virtual_size: u64,
    ) -> Result<Self> {
        let path = path.as_ref();
        let backing_path = backing_path.as_ref();

        let backend = SyncFileBackend::create(path).map_err(|e| {
            if let Error::Io { message, .. } = &e {
                Error::CreateFailed {
                    message: message.clone(),
                    path: path.display().to_string(),
                }
            } else {
                e
            }
        })?;

        Self::create_overlay_on_backend(
            Box::new(backend),
            backing_path,
            virtual_size,
        )
    }

    /// Create a new QCOW2 v3 overlay image on an I/O backend.
    ///
    /// The overlay stores the backing file name in the header and opens
    /// the backing file for read-through. Useful for testing.
    pub fn create_overlay_on_backend(
        backend: Box<dyn IoBackend>,
        backing_path: &Path,
        virtual_size: u64,
    ) -> Result<Self> {
        let cluster_bits = 16u32;
        let cluster_size = 1u64 << cluster_bits;
        let refcount_order = 4u32;

        // Calculate L1 table size
        let l1_entries = calculate_l1_entries(virtual_size, cluster_size, 8);

        // Layout: header(0), L1(1..N), reftable(N+1), refblock(N+2)
        let l1_clusters = ((l1_entries as u64 * 8) + cluster_size - 1) / cluster_size;
        let l1_offset = cluster_size;
        let rt_offset = (1 + l1_clusters) * cluster_size;
        let rb_offset = (2 + l1_clusters) * cluster_size;
        let initial_clusters = 3 + l1_clusters;

        debug_assert_layout_no_overlap(l1_offset, l1_clusters, cluster_size, rt_offset, rb_offset);

        // Header extension area starts at header_length (byte 104).
        // Write an end-of-extensions marker (type=0, length=0 → 8 zero bytes)
        // at offset 104, then place the backing file name at offset 112.
        let backing_name = backing_path.to_string_lossy();
        let backing_name_bytes = backing_name.as_bytes();
        let ext_end_offset = crate::format::constants::HEADER_V3_MIN_LENGTH;
        let backing_file_offset = (ext_end_offset + 8) as u64; // after 8-byte terminator

        // Verify the name fits in cluster 0 (after the header)
        if backing_file_offset + backing_name_bytes.len() as u64 > cluster_size {
            return Err(Error::WriteFailed {
                guest_offset: 0,
                message: format!(
                    "backing file name ({} bytes) too long for header cluster",
                    backing_name_bytes.len()
                ),
            });
        }

        // Build header with backing file reference
        let header = Header {
            version: 3,
            backing_file_offset,
            backing_file_size: backing_name_bytes.len() as u32,
            cluster_bits,
            virtual_size,
            crypt_method: 0,
            l1_table_entries: l1_entries,
            l1_table_offset: ClusterOffset(l1_offset),
            refcount_table_offset: ClusterOffset(rt_offset),
            refcount_table_clusters: 1,
            snapshot_count: 0,
            snapshots_offset: ClusterOffset(0),
            incompatible_features: IncompatibleFeatures::empty(),
            compatible_features: crate::format::feature_flags::CompatibleFeatures::empty(),
            autoclear_features: crate::format::feature_flags::AutoclearFeatures::empty(),
            refcount_order,
            header_length: crate::format::constants::HEADER_V3_MIN_LENGTH as u32,
            compression_type: 0,
        };

        // Write initial layout: zeroed clusters + refcount table/block
        write_initial_layout(backend.as_ref(), cluster_size, initial_clusters, rt_offset, rb_offset)?;

        // Write header (over the zeroed cluster 0)
        let mut header_buf = vec![0u8; cluster_size as usize];
        header.write_to(&mut header_buf)?;
        // Write backing file name into the header cluster
        let bf_start = backing_file_offset as usize;
        header_buf[bf_start..bf_start + backing_name_bytes.len()]
            .copy_from_slice(backing_name_bytes);
        backend.write_all_at(&header_buf, 0)?;

        backend.flush()?;

        // Build in-memory structures
        let l1_table = L1Table::new_empty(l1_entries);
        let file_size = backend.file_size()?;
        let mapper = ClusterMapper::new(l1_table, ClusterGeometry { cluster_bits, extended_l2: false }, file_size);
        let refcount_manager = RefcountManager::load_with_mode(
            backend.as_ref(), &header, AllocationMode::Append,
        )?;

        // Open the backing image for read-through
        let backing_img = Qcow2Image::open(backing_path)?;

        Ok(Self::new_inner(
            header,
            Vec::new(),
            backend,
            None,  // data_backend
            mapper,
            None,  // backing_chain
            Some(Box::new(backing_img)),
            ReadMode::Strict,
            Vec::new(),
            Some(refcount_manager),
            true,  // writable
            false, // has_auto_bitmaps
            false, // has_hashes
            None,  // crypt_context
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_helpers::*;
    use super::*;
    use crate::engine::cache::{CacheConfig, MetadataCache};
    use crate::io::MemoryBackend;

    #[test]
    fn create_on_backend_produces_valid_header() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 30, // 1 GB
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        assert_eq!(image.header().version, 3);
        assert_eq!(image.header().cluster_bits, 16);
        assert_eq!(image.virtual_size(), 1 << 30);
        assert!(image.is_writable());
        assert!(!image.is_dirty());
    }

    #[test]
    fn create_on_backend_with_custom_cluster_bits() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: Some(12), // 4 KB clusters
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        assert_eq!(image.cluster_bits(), 12);
        assert_eq!(image.cluster_size(), 4096);
    }

    #[test]
    fn create_on_backend_small_virtual_size() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 512,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        assert_eq!(image.virtual_size(), 512);
        assert!(image.header().l1_table_entries >= 1);
    }

    #[test]
    fn create_on_backend_refcounts_correct() {
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 30,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        // First 4 clusters should have refcount 1
        let refcount_manager = image.meta.refcount_manager.as_ref().unwrap();
        let cache = &mut MetadataCache::new(CacheConfig::default());
        let cluster_size = image.cluster_size();
        for i in 0..4 {
            let rc = refcount_manager
                .get_refcount(i * cluster_size, image.backend(), cache)
                .unwrap();
            assert_eq!(rc, 1, "cluster {} should have refcount 1", i);
        }
    }

    #[test]
    fn create_on_backend_write_then_read() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        let write_data = b"Hello, new QCOW2 image!";
        image.write_at(write_data, 0).unwrap();

        let mut read_buf = vec![0u8; write_data.len()];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(&read_buf, write_data);
    }

    #[test]
    fn create_on_backend_write_flush_clears_dirty() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        image.write_at(&[0xAA; 64], 0).unwrap();
        assert!(image.is_dirty());

        image.flush().unwrap();
        assert!(!image.is_dirty());
    }

    #[test]
    fn create_on_backend_reopenable() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        let write_data = vec![0xBB; 256];
        image.write_at(&write_data, 4096).unwrap();
        image.flush().unwrap();

        // Extract the raw data and re-open
        let raw_data = {
            let backend_ref = image.backend();
            let size = backend_ref.file_size().unwrap() as usize;
            let mut data = vec![0u8; size];
            backend_ref.read_exact_at(&mut data, 0).unwrap();
            data
        };

        let reopened_backend = MemoryBackend::new(raw_data);
        let mut reopened = Qcow2Image::from_backend_rw(Box::new(reopened_backend)).unwrap();

        let mut read_buf = vec![0u8; 256];
        reopened.read_at(&mut read_buf, 4096).unwrap();
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn create_on_backend_large_virtual_size() {
        let backend = MemoryBackend::zeroed(0);
        let virtual_size = 2u64 * 1024 * 1024 * 1024 * 1024; // 2 TB
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        assert_eq!(image.virtual_size(), virtual_size);
        // L1 table should be large enough
        let l2_entries = image.cluster_size() / 8;
        let bytes_per_l1 = l2_entries * image.cluster_size();
        let expected_l1 =
            ((virtual_size + bytes_per_l1 - 1) / bytes_per_l1) as u32;
        assert_eq!(image.header().l1_table_entries, expected_l1);
    }

    #[test]
    fn create_on_backend_unallocated_reads_zero() {
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        let mut buf = vec![0xFFu8; 512];
        image.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn create_file_based_round_trip() {
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("qcow2");
        // Remove the temp file so create() can use create_new
        drop(tmp);

        let write_data = b"file-based creation test";

        {
            let mut image = Qcow2Image::create(
                &path,
                CreateOptions {
                    virtual_size: 1 << 20,
                    cluster_bits: None,
                    extended_l2: false, compression_type: None, data_file: None, encryption: None,
                },
            )
            .unwrap();

            image.write_at(write_data, 0).unwrap();
            image.flush().unwrap();
        }

        // Reopen and verify
        let mut image = Qcow2Image::open_rw(&path).unwrap();
        let mut read_buf = vec![0u8; write_data.len()];
        image.read_at(&mut read_buf, 0).unwrap();
        assert_eq!(&read_buf, write_data);

        // Clean up
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn create_existing_file_fails() {
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        // File already exists — create should fail
        let result = Qcow2Image::create(
            tmp.path(),
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        );
        assert!(result.is_err());
    }

    // ---- Overlay / backing file tests ----

    /// Helper: create a base image with known data, return its path.
    fn create_base_image(dir: &std::path::Path) -> std::path::PathBuf {
        let base_path = dir.join("base.qcow2");
        let mut base = Qcow2Image::create(
            &base_path,
            CreateOptions {
                virtual_size: 1 << 20, // 1 MB
                cluster_bits: None,
                extended_l2: false, compression_type: None, data_file: None, encryption: None,
            },
        )
        .unwrap();

        // Write known data at several offsets
        base.write_at(&[0xAA; 512], 0).unwrap();
        base.write_at(&[0xBB; 512], CLUSTER_SIZE as u64).unwrap();
        base.flush().unwrap();
        base_path
    }

    #[test]
    fn overlay_reads_backing_data() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Read unallocated region — should see backing data
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "should read backing data");
    }

    #[test]
    fn overlay_reads_backing_data_second_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, CLUSTER_SIZE as u64).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn overlay_write_does_not_modify_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        {
            let mut overlay = Qcow2Image::create_overlay(
                &overlay_path,
                &base_path,
                1 << 20,
            )
            .unwrap();

            // Write to the overlay at the same offset as backing data
            overlay.write_at(&[0xCC; 512], 0).unwrap();
            overlay.flush().unwrap();
        }

        // Re-read backing directly — should still have original data
        let mut base = Qcow2Image::open(&base_path).unwrap();
        let mut buf = vec![0u8; 512];
        base.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA), "backing must be unchanged");
    }

    #[test]
    fn overlay_write_overrides_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write different data to the overlay
        overlay.write_at(&[0xDD; 512], 0).unwrap();

        // Read should return overlay data, not backing data
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn overlay_partial_write_preserves_backing_data() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write 100 bytes at offset 200 within the first cluster
        // (which has 0xAA in the first 512 bytes from backing)
        overlay.write_at(&[0xEE; 100], 200).unwrap();

        // Read the full first 512 bytes
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();

        // Bytes 0-199: should be 0xAA (from backing)
        assert!(
            buf[..200].iter().all(|&b| b == 0xAA),
            "non-written region should preserve backing data"
        );
        // Bytes 200-299: should be 0xEE (from overlay write)
        assert!(buf[200..300].iter().all(|&b| b == 0xEE));
        // Bytes 300-511: should be 0xAA (from backing)
        assert!(
            buf[300..512].iter().all(|&b| b == 0xAA),
            "trailing region should preserve backing data"
        );
    }

    #[test]
    fn overlay_unallocated_beyond_backing_data_returns_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Read from a region that has no data in either backing or overlay
        let offset = 2 * CLUSTER_SIZE as u64; // third cluster, no data in base
        let mut buf = vec![0xFFu8; 256];
        overlay.read_at(&mut buf, offset).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn overlay_reopenable_with_backing() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        {
            let mut overlay = Qcow2Image::create_overlay(
                &overlay_path,
                &base_path,
                1 << 20,
            )
            .unwrap();

            overlay.write_at(&[0xFF; 256], 0).unwrap();
            overlay.flush().unwrap();
        }

        // Reopen and verify both overlay and backing data
        let mut overlay = Qcow2Image::open_rw(&overlay_path).unwrap();

        // Overlay data
        let mut buf = vec![0u8; 256];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0xFF));

        // Backing data from second cluster (not overwritten)
        let mut buf2 = vec![0u8; 512];
        overlay.read_at(&mut buf2, CLUSTER_SIZE as u64).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn overlay_header_has_backing_file_info() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        assert!(overlay.header().has_backing_file());
        assert!(overlay.header().backing_file_size > 0);
    }

    #[test]
    fn overlay_write_then_read_multiple_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = create_base_image(dir.path());
        let overlay_path = dir.path().join("overlay.qcow2");

        let mut overlay = Qcow2Image::create_overlay(
            &overlay_path,
            &base_path,
            1 << 20,
        )
        .unwrap();

        // Write to cluster 0 in the overlay
        overlay.write_at(&[0x11; 512], 0).unwrap();
        // Cluster 1 stays from backing (0xBB)

        // Read spanning both clusters
        let mut buf = vec![0u8; 512];
        overlay.read_at(&mut buf, 0).unwrap();
        assert!(buf.iter().all(|&b| b == 0x11), "cluster 0: overlay data");

        let mut buf2 = vec![0u8; 512];
        overlay.read_at(&mut buf2, CLUSTER_SIZE as u64).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xBB), "cluster 1: backing data");
    }

    // ---- Large image layout regression tests ----

    #[test]
    fn create_on_backend_13t_layout_no_overlap() {
        // 13 TiB with 64 KiB clusters: L1 needs ~3.25 clusters (4 after rounding)
        let virtual_size = 13u64 * 1024 * 1024 * 1024 * 1024;
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();

        let cluster_size = image.cluster_size();
        let l1_offset = image.header().l1_table_offset.0;
        let rt_offset = image.header().refcount_table_offset.0;
        let l1_bytes = image.header().l1_table_entries as u64 * 8;
        let l1_end = l1_offset + ((l1_bytes + cluster_size - 1) / cluster_size) * cluster_size;

        // L1 table must not overlap refcount table
        assert!(
            l1_end <= rt_offset,
            "L1 end ({:#x}) must not exceed refcount table offset ({:#x})",
            l1_end, rt_offset
        );
    }

    #[test]
    fn create_on_backend_13t_refcounts_correct() {
        let virtual_size = 13u64 * 1024 * 1024 * 1024 * 1024;
        let backend = MemoryBackend::zeroed(0);
        let image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();

        let refcount_manager = image.meta.refcount_manager.as_ref().unwrap();
        let cache = &mut MetadataCache::new(CacheConfig::default());
        let cluster_size = image.cluster_size();
        let l1_bytes = image.header().l1_table_entries as u64 * 8;
        let l1_clusters = (l1_bytes + cluster_size - 1) / cluster_size;
        let initial_clusters = 3 + l1_clusters; // header + L1 + RT + RB

        for i in 0..initial_clusters {
            let rc = refcount_manager
                .get_refcount(i * cluster_size, image.backend(), cache)
                .unwrap();
            assert_eq!(rc, 1, "cluster {} should have refcount 1", i);
        }
    }

    #[test]
    fn create_on_backend_boundary_l1_size() {
        let cluster_size = 65536u64;
        let l2_entries = cluster_size / 8;
        let bytes_per_l1 = l2_entries * cluster_size;

        // Exactly fills 1 L1 cluster (8192 entries × 8 bytes = 65536)
        let max_one_cluster = (cluster_size / 8) * bytes_per_l1;
        // One more L1 entry requires 2 L1 clusters
        let needs_two_clusters = max_one_cluster + bytes_per_l1;

        for &vsize in &[max_one_cluster, needs_two_clusters] {
            let backend = MemoryBackend::zeroed(0);
            let image = Qcow2Image::create_on_backend(
                Box::new(backend),
                CreateOptions {
                    virtual_size: vsize,
                    cluster_bits: Some(16),
                    extended_l2: false,
                    compression_type: None,
                    data_file: None,
                    encryption: None,
                },
            )
            .unwrap();

            let l1_offset = image.header().l1_table_offset.0;
            let rt_offset = image.header().refcount_table_offset.0;
            let l1_bytes = image.header().l1_table_entries as u64 * 8;
            let l1_end = l1_offset + ((l1_bytes + cluster_size - 1) / cluster_size) * cluster_size;

            assert!(
                l1_end <= rt_offset,
                "L1 must not overlap RT for vsize={:#x}: l1_end={:#x} rt={:#x}",
                vsize, l1_end, rt_offset
            );
        }
    }

    #[test]
    fn create_on_backend_8t_integrity_clean() {
        let virtual_size = 8u64 * 1024 * 1024 * 1024 * 1024;
        let backend = MemoryBackend::zeroed(0);
        let mut image = Qcow2Image::create_on_backend(
            Box::new(backend),
            CreateOptions {
                virtual_size,
                cluster_bits: Some(16),
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: None,
            },
        )
        .unwrap();

        let report = image.check_integrity().unwrap();
        assert!(
            report.is_clean(),
            "8 TiB image should be clean: {} mismatches, {} leaks, {} overlaps",
            report.mismatches.len(),
            report.leaks.len(),
            report.overlaps.len()
        );
    }
}
