//! Opening and constructing `Qcow2Image` from files and backends.

use std::path::Path;

use crate::engine::backing::{self as backing_mod, BackingChain};
use crate::engine::cluster_mapping::ClusterMapper;
use crate::engine::hash_manager;
use crate::engine::read_mode::{ReadMode, ReadWarning};
use crate::engine::refcount_manager::RefcountManager;
use crate::error::{Error, FormatError, Result};
use crate::format::feature_flags::{AutoclearFeatures, IncompatibleFeatures};
use crate::format::header::Header;
use crate::format::header_extension::HeaderExtension;
use crate::format::l1::L1Table;
use crate::format::types::ClusterOffset;
use crate::io::sync_backend::SyncFileBackend;
use crate::io::IoBackend;

use super::Qcow2Image;

impl Qcow2Image {
    /// Open a QCOW2 image file at the given path.
    ///
    /// Parses the header, loads the L1 table, and optionally resolves
    /// the backing file chain. Uses [`ReadMode::Strict`] by default.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_mode(path, ReadMode::Strict)
    }

    /// Open a QCOW2 image file with the specified read mode.
    ///
    /// In [`ReadMode::Lenient`], recoverable errors during reads will
    /// produce zeros and warnings instead of aborting.
    pub fn open_with_mode<P: AsRef<Path>>(path: P, read_mode: ReadMode) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_backend_with_options(Box::new(backend), Some(image_dir), read_mode, None, None)
    }

    /// Create a `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Useful for testing with [`MemoryBackend`](crate::io::MemoryBackend)
    /// or for custom I/O implementations. Uses [`ReadMode::Strict`].
    pub fn from_backend(backend: Box<dyn IoBackend>) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, None, None)
    }

    /// Create a `Qcow2Image` from a backend with an explicit read mode.
    pub fn from_backend_with_mode(
        backend: Box<dyn IoBackend>,
        read_mode: ReadMode,
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, read_mode, None, None)
    }

    /// Create a `Qcow2Image` from separate metadata and data backends.
    ///
    /// Use this when the image has an external data file and you want to
    /// provide the data backend yourself instead of having the library open it.
    pub fn from_backend_with_data(
        backend: Box<dyn IoBackend>,
        data_backend: Option<Box<dyn IoBackend>>,
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, data_backend, None)
    }

    /// Open a QCOW2 image file with a password for encrypted images.
    pub fn open_with_password<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_backend_with_options(
            Box::new(backend), Some(image_dir), ReadMode::Strict, None, Some(password),
        )
    }

    /// Open a QCOW2 image read-write with a password for encrypted images.
    pub fn open_rw_with_password<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open_rw(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut image = Self::from_backend_with_options(
            Box::new(backend), Some(image_dir), ReadMode::Strict, None, Some(password),
        )?;

        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;
        Ok(image)
    }

    /// Create a `Qcow2Image` from a backend with a password for encrypted images.
    pub fn from_backend_with_password(
        backend: Box<dyn IoBackend>,
        password: &[u8],
    ) -> Result<Self> {
        Self::from_backend_with_options(backend, None, ReadMode::Strict, None, Some(password))
    }

    /// Open a QCOW2 image file for read-write access.
    ///
    /// Loads the refcount table and enables `write_at` / `flush`.
    /// Sets the DIRTY incompatible feature flag on the first write.
    pub fn open_rw<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let backend = SyncFileBackend::open_rw(path)?;
        let image_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut image = Self::from_backend_with_options(
            Box::new(backend),
            Some(image_dir),
            ReadMode::Strict,
            None,
            None,
        )?;

        // If external data file, reopen in rw mode
        if image.has_external_data_file() {
            let data_file_name = image
                .meta.extensions
                .iter()
                .find_map(|e| match e {
                    HeaderExtension::ExternalDataFile(name) => Some(name.clone()),
                    _ => None,
                })
                .ok_or(Error::MissingExternalDataFilePath)?;
            let data_path = image_dir.join(&data_file_name);
            let db = SyncFileBackend::open_rw(&data_path).map_err(|e| {
                if let Error::Io { message, .. } = &e {
                    Error::ExternalDataFileOpen {
                        message: message.clone(),
                        path: data_path.display().to_string(),
                    }
                } else {
                    e
                }
            })?;
            image.data_backend = Some(Box::new(db));
        }

        // Load refcount manager for write support
        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;

        Ok(image)
    }

    /// Create a writable `Qcow2Image` from an already-opened I/O backend.
    ///
    /// Loads the refcount table for cluster allocation. Useful for testing.
    pub fn from_backend_rw(backend: Box<dyn IoBackend>) -> Result<Self> {
        let mut image = Self::from_backend_with_options(backend, None, ReadMode::Strict, None, None)?;

        let refcount_manager = RefcountManager::load(
            image.backend.as_ref(),
            &image.meta.header,
        )?;
        image.meta.refcount_manager = Some(refcount_manager);
        image.meta.writable = true;

        Ok(image)
    }

    /// Internal constructor that handles both file and backend paths.
    pub(super) fn from_backend_with_options(
        backend: Box<dyn IoBackend>,
        image_dir: Option<&Path>,
        read_mode: ReadMode,
        data_backend: Option<Box<dyn IoBackend>>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, extensions, file_size) =
            Self::read_header_and_extensions(backend.as_ref())?;

        let mapper = Self::build_mapper(backend.as_ref(), &header, file_size)?;

        let mut warnings = Vec::new();
        let (backing_chain, backing_image) =
            Self::resolve_backing(&header, backend.as_ref(), image_dir, read_mode, &mut warnings)?;

        let data_backend = Self::resolve_data_backend(
            &header, &extensions, data_backend, image_dir,
        )?;

        let has_auto_bitmaps = Self::detect_auto_bitmaps(backend.as_ref(), &extensions);
        let has_hashes = hash_manager::detect_hashes(&extensions);

        let crypt_context = Self::recover_crypt_context(
            &header, &extensions, backend.as_ref(), password,
        )?;

        Ok(Self::new_inner(
            header, extensions, backend, data_backend,
            mapper, backing_chain, backing_image,
            read_mode, warnings,
            None, false, has_auto_bitmaps, has_hashes, crypt_context,
        ))
    }

    /// Read and validate the header, extensions, and file size.
    fn read_header_and_extensions(
        backend: &dyn IoBackend,
    ) -> Result<(Header, Vec<HeaderExtension>, u64)> {
        let mut header_buf = vec![0u8; 512];
        let file_size = backend.file_size()?;
        let read_size = header_buf.len().min(file_size as usize);
        backend.read_exact_at(&mut header_buf[..read_size], 0)?;
        let header = Header::read_from(&header_buf[..read_size])?;
        header.validate_against_file(file_size)?;

        let ext_start = header.header_length as u64;
        let ext_end = header.cluster_size().min(file_size);
        let extensions = if ext_start < ext_end {
            let mut ext_buf = vec![0u8; (ext_end - ext_start) as usize];
            backend.read_exact_at(&mut ext_buf, ext_start)?;
            HeaderExtension::read_all(&ext_buf).unwrap_or_default()
        } else {
            Vec::new()
        };

        for ext in &extensions {
            if let HeaderExtension::Blake3Hashes(blake3) = ext {
                if blake3.hash_table_offset != 0
                    && !ClusterOffset(blake3.hash_table_offset)
                        .is_cluster_aligned(header.cluster_bits)
                {
                    return Err(Error::HashTableMisaligned {
                        offset: blake3.hash_table_offset,
                    });
                }
            }
        }

        Ok((header, extensions, file_size))
    }

    /// Read L1 table and build the cluster mapper.
    fn build_mapper(
        backend: &dyn IoBackend,
        header: &Header,
        file_size: u64,
    ) -> Result<ClusterMapper> {
        let l1_size = (header.l1_table_entries as usize)
            .checked_mul(crate::format::constants::L1_ENTRY_SIZE)
            .ok_or(FormatError::ArithmeticOverflow {
                context: "l1_table_entries * L1_ENTRY_SIZE",
            })?;
        let mut l1_buf = vec![0u8; l1_size];
        backend.read_exact_at(&mut l1_buf, header.l1_table_offset.0)?;
        let l1_table = L1Table::read_from(&l1_buf, header.l1_table_entries)?;
        Ok(ClusterMapper::new(l1_table, header.geometry(), file_size))
    }

    /// Resolve the backing chain and open the backing image.
    fn resolve_backing(
        header: &Header,
        backend: &dyn IoBackend,
        image_dir: Option<&Path>,
        read_mode: ReadMode,
        warnings: &mut Vec<ReadWarning>,
    ) -> Result<(Option<BackingChain>, Option<Box<Qcow2Image>>)> {
        if !header.has_backing_file() {
            return Ok((None, None));
        }
        let dir = match image_dir {
            Some(d) => d,
            None => return Ok((None, None)),
        };
        let name = backing_mod::read_backing_file_name(
            backend, header.backing_file_offset, header.backing_file_size,
        )?;
        match BackingChain::resolve(&name, dir) {
            Ok(chain) => {
                let backing_path = &chain.entries()[0].path;
                match Qcow2Image::open_with_mode(backing_path, read_mode) {
                    Ok(img) => Ok((Some(chain), Some(Box::new(img)))),
                    Err(e) if read_mode == ReadMode::Lenient => {
                        warnings.push(ReadWarning {
                            guest_offset: 0,
                            message: format!("failed to open backing file: {e}"),
                        });
                        Ok((Some(chain), None))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) if read_mode == ReadMode::Lenient => {
                warnings.push(ReadWarning {
                    guest_offset: 0,
                    message: format!("backing file resolution failed: {e}"),
                });
                Ok((None, None))
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve the external data file backend.
    fn resolve_data_backend(
        header: &Header,
        extensions: &[HeaderExtension],
        data_backend: Option<Box<dyn IoBackend>>,
        image_dir: Option<&Path>,
    ) -> Result<Option<Box<dyn IoBackend>>> {
        if !header.incompatible_features.contains(IncompatibleFeatures::EXTERNAL_DATA_FILE) {
            return Ok(None);
        }
        if !header.autoclear_features.contains(AutoclearFeatures::RAW_EXTERNAL) {
            return Err(Error::RawExternalRequired);
        }
        if let Some(db) = data_backend {
            return Ok(Some(db));
        }
        let dir = image_dir.ok_or(Error::MissingExternalDataFilePath)?;
        let data_file_name = extensions
            .iter()
            .find_map(|e| match e {
                HeaderExtension::ExternalDataFile(name) => Some(name.clone()),
                _ => None,
            })
            .ok_or(Error::MissingExternalDataFilePath)?;
        let data_path = dir.join(&data_file_name);
        let db = SyncFileBackend::open(&data_path).map_err(|e| {
            if let Error::Io { message, .. } = &e {
                Error::ExternalDataFileOpen {
                    message: message.clone(),
                    path: data_path.display().to_string(),
                }
            } else {
                e
            }
        })?;
        Ok(Some(Box::new(db) as Box<dyn IoBackend>))
    }

    /// Recover the encryption context from the LUKS header if encrypted.
    fn recover_crypt_context(
        header: &Header,
        extensions: &[HeaderExtension],
        backend: &dyn IoBackend,
        password: Option<&[u8]>,
    ) -> Result<Option<crate::engine::encryption::CryptContext>> {
        if header.crypt_method != crate::format::constants::CRYPT_LUKS {
            return Ok(None);
        }
        let pw = password.ok_or(Error::NoPasswordProvided)?;
        let (luks_offset, luks_length) = extensions
            .iter()
            .find_map(|e| match e {
                HeaderExtension::FullDiskEncryption { offset, length } => {
                    Some((*offset, *length))
                }
                _ => None,
            })
            .ok_or(Error::InvalidLuksHeader {
                message: "missing FullDiskEncryption header extension".to_string(),
            })?;
        let mut luks_data = vec![0u8; luks_length as usize];
        backend.read_exact_at(&mut luks_data, luks_offset)?;
        let ctx = crate::engine::encryption::recover_master_key(&luks_data, pw)?;
        Ok(Some(ctx))
    }
}
