//! Integration tests for LUKS encryption support.

use qcow2::engine::encryption::CipherMode;
use qcow2::engine::image::{CreateOptions, EncryptionOptions, Qcow2Image};
use qcow2::io::MemoryBackend;
use tempfile::TempDir;

/// Helper to create an encrypted image on a memory backend.
fn create_encrypted_image(
    password: &[u8],
    cipher: CipherMode,
    virtual_size: u64,
) -> Qcow2Image {
    let backend = MemoryBackend::zeroed(0);
    Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size,
            cluster_bits: None,
            extended_l2: false,
            compression_type: None,
            data_file: None,
            encryption: Some(EncryptionOptions {
                password: password.to_vec(),
                cipher,
                luks_version: 1,
                iter_time_ms: Some(1000),
            }),
        },
    )
    .unwrap()
}

fn encryption_options(password: &[u8]) -> Option<EncryptionOptions> {
    Some(EncryptionOptions {
        password: password.to_vec(),
        cipher: CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: Some(1000),
    })
}

#[test]
fn encrypted_image_creation_xts() {
    let image = create_encrypted_image(b"testpassword", CipherMode::AesXtsPlain64, 1 << 20);
    assert!(image.is_encrypted());
    assert_eq!(image.header().crypt_method, 2);
}

#[test]
fn encrypted_image_creation_cbc() {
    let image = create_encrypted_image(b"testpassword", CipherMode::AesCbcEssiv, 1 << 20);
    assert!(image.is_encrypted());
}

#[test]
fn encrypted_write_read_round_trip_xts() {
    let mut image = create_encrypted_image(b"secret", CipherMode::AesXtsPlain64, 1 << 20);

    let write_data = b"Hello, encrypted QCOW2!";
    image.write_at(write_data, 0).unwrap();

    let mut read_buf = vec![0u8; write_data.len()];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(&read_buf, write_data);
}

#[test]
fn encrypted_write_read_round_trip_cbc() {
    let mut image = create_encrypted_image(b"secret", CipherMode::AesCbcEssiv, 1 << 20);

    let write_data = b"Hello, AES-CBC-ESSIV!";
    image.write_at(write_data, 0).unwrap();

    let mut read_buf = vec![0u8; write_data.len()];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(&read_buf, write_data);
}

#[test]
fn encrypted_full_cluster_write_read() {
    let mut image = create_encrypted_image(b"pw", CipherMode::AesXtsPlain64, 1 << 20);
    let cluster_size = image.cluster_size() as usize;

    let write_data: Vec<u8> = (0..cluster_size).map(|i| (i % 251) as u8).collect();
    image.write_at(&write_data, 0).unwrap();

    let mut read_buf = vec![0u8; cluster_size];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, write_data);
}

#[test]
fn encrypted_multi_cluster_write_read() {
    let mut image = create_encrypted_image(b"pw", CipherMode::AesXtsPlain64, 1 << 20);
    let cluster_size = image.cluster_size() as usize;

    let write_data: Vec<u8> = (0..3 * cluster_size).map(|i| (i % 197) as u8).collect();
    image.write_at(&write_data, 0).unwrap();

    let mut read_buf = vec![0u8; 3 * cluster_size];
    image.read_at(&mut read_buf, 0).unwrap();
    assert_eq!(read_buf, write_data);
}

#[test]
fn encrypted_partial_cluster_write_read() {
    let mut image = create_encrypted_image(b"pw", CipherMode::AesXtsPlain64, 1 << 20);

    let write_data = vec![0xAA; 512];
    image.write_at(&write_data, 1024).unwrap();

    let mut read_buf = vec![0u8; 2048];
    image.read_at(&mut read_buf, 0).unwrap();
    assert!(read_buf[..1024].iter().all(|&b| b == 0));
    assert!(read_buf[1024..1536].iter().all(|&b| b == 0xAA));
    assert!(read_buf[1536..].iter().all(|&b| b == 0));
}

#[test]
fn encrypted_reopen_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("encrypted.qcow2");

    // Create and write
    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"mypassword"),
            },
        )
        .unwrap();

        image.write_at(b"persistent encrypted data", 4096).unwrap();
        image.flush().unwrap();
    }

    // Reopen with password and verify
    let mut image2 = Qcow2Image::open_with_password(&path, b"mypassword").unwrap();
    assert!(image2.is_encrypted());

    let mut read_buf = vec![0u8; 25];
    image2.read_at(&mut read_buf, 4096).unwrap();
    assert_eq!(&read_buf, b"persistent encrypted data");
}

#[test]
fn encrypted_wrong_password_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("encrypted.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"correctpassword"),
            },
        )
        .unwrap();
        image.write_at(&[0xBB; 512], 0).unwrap();
        image.flush().unwrap();
    }

    let result = Qcow2Image::open_with_password(&path, b"wrongpassword");
    assert!(result.is_err());
}

#[test]
fn encrypted_no_password_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("encrypted.qcow2");

    {
        let image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"pw"),
            },
        )
        .unwrap();
        drop(image);
    }

    // Open without password — should fail with NoPasswordProvided
    let result = Qcow2Image::open(&path);
    assert!(result.is_err());
}

#[test]
fn encrypted_unallocated_reads_zero() {
    let mut image = create_encrypted_image(b"pw", CipherMode::AesXtsPlain64, 1 << 20);

    let mut buf = vec![0xFF; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn encryption_with_compression_rejected() {
    let backend = MemoryBackend::zeroed(0);
    let result = Qcow2Image::create_on_backend(
        Box::new(backend),
        CreateOptions {
            virtual_size: 1 << 20,
            cluster_bits: None,
            extended_l2: false,
            compression_type: Some(qcow2::format::constants::COMPRESSION_ZSTD),
            data_file: None,
            encryption: encryption_options(b"pw"),
        },
    );
    assert!(result.is_err());
}

#[test]
fn encrypted_overwrite_preserves_other_data() {
    let mut image = create_encrypted_image(b"pw", CipherMode::AesXtsPlain64, 1 << 20);
    let cluster_size = image.cluster_size() as usize;

    // Write full cluster of 0xAA
    image.write_at(&vec![0xAA; cluster_size], 0).unwrap();

    // Overwrite first 512 bytes with 0xBB (in-place write to same cluster)
    image.write_at(&vec![0xBB; 512], 0).unwrap();

    let mut buf = vec![0u8; cluster_size];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xBB));
    assert!(buf[512..].iter().all(|&b| b == 0xAA));
}

#[test]
fn encrypted_rw_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("encrypted_rw.qcow2");

    // Create encrypted image
    {
        let image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"testpw"),
            },
        )
        .unwrap();
        drop(image);
    }

    // Reopen read-write, write data, close
    {
        let mut image = Qcow2Image::open_rw_with_password(&path, b"testpw").unwrap();
        assert!(image.is_encrypted());
        image.write_at(&[0xCC; 1024], 0).unwrap();
        image.flush().unwrap();
    }

    // Reopen read-only and verify
    let mut image = Qcow2Image::open_with_password(&path, b"testpw").unwrap();
    let mut buf = vec![0u8; 1024];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xCC));
}
