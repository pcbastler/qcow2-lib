//! QEMU interoperability tests for LUKS encryption.
//!
//! Tests that encrypted images created by our library can be read by QEMU
//! and vice versa.

mod common;

use common::{has_qemu_io, EncryptedTestImage};
use qcow2::engine::encryption::CipherMode;
use qcow2::engine::encryption::af_splitter;
use qcow2::engine::encryption::create;
use qcow2::engine::encryption::key_derivation;
use qcow2::engine::encryption::luks_header::LuksHeader;
use qcow2::engine::image::{CreateOptions, EncryptionOptions, Qcow2Image};
use std::process::Command;
use tempfile::TempDir;

fn encryption_options(password: &[u8]) -> Option<EncryptionOptions> {
    Some(EncryptionOptions {
        password: password.to_vec(),
        cipher: CipherMode::AesXtsPlain64,
        luks_version: 1,
        iter_time_ms: Some(1000),
    })
}

// --- Our library reads QEMU-created encrypted images ---

#[test]
fn library_reads_qemu_encrypted_image() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = EncryptedTestImage::create("1M", "testpw");
    img.write_pattern(0xAA, 0, 512);
    img.write_pattern(0xBB, 65536, 1024);

    // Read with our library
    let mut image = Qcow2Image::open_with_password(&img.path, b"testpw").unwrap();
    assert!(image.is_encrypted());

    let mut buf = vec![0u8; 512];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAA), "first 512 bytes should be 0xAA");

    let mut buf2 = vec![0u8; 1024];
    image.read_at(&mut buf2, 65536).unwrap();
    assert!(buf2.iter().all(|&b| b == 0xBB), "data at 64K should be 0xBB");

    // Unallocated area should be zero
    let mut buf3 = vec![0u8; 512];
    image.read_at(&mut buf3, 131072).unwrap();
    assert!(buf3.iter().all(|&b| b == 0), "unallocated should be zero");
}

// --- QEMU reads our library-created encrypted images ---

#[test]
fn qemu_reads_our_encrypted_image() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("our_encrypted.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"mypw"),
            },
        )
        .unwrap();

        image.write_at(&[0xCC; 512], 0).unwrap();
        image.write_at(&[0xDD; 1024], 65536).unwrap();
        image.flush().unwrap();
    }

    // Read with QEMU
    let secret_arg = "secret,id=sec0,data=mypw";
    let image_opts = format!(
        "driver=qcow2,encrypt.key-secret=sec0,file.driver=file,file.filename={}",
        path.display()
    );

    let output = Command::new("qemu-io")
        .args(["--object", secret_arg])
        .args(["--image-opts", &image_opts])
        .args(["-c", "read -v 0 512"])
        .output()
        .expect("failed to run qemu-io");

    assert!(
        output.status.success(),
        "qemu-io read failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let data = common::parse_qemu_io_hex_dump(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(data.len(), 512);
    assert!(data.iter().all(|&b| b == 0xCC), "QEMU should read 0xCC");
}

#[test]
fn qemu_check_our_encrypted_image() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("check_encrypted.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"checkpw"),
            },
        )
        .unwrap();

        image.write_at(&[0xEE; 4096], 0).unwrap();
        image.flush().unwrap();
    }

    // Run qemu-img check
    let secret_arg = "secret,id=sec0,data=checkpw";
    let image_opts = format!(
        "driver=qcow2,encrypt.key-secret=sec0,file.driver=file,file.filename={}",
        path.display()
    );

    let output = Command::new("qemu-img")
        .args(["check"])
        .args(["--object", secret_arg])
        .args(["--image-opts", &image_opts])
        .output()
        .expect("failed to run qemu-img check");

    assert!(
        output.status.success(),
        "qemu-img check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Full round-trip: create(ours) → write(QEMU) → read(ours) ---

#[test]
fn round_trip_our_create_qemu_write_our_read() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("round_trip.qcow2");

    // Create with our library
    {
        let image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"rtpw"),
            },
        )
        .unwrap();
        drop(image);
    }

    // Write with QEMU
    let secret_arg = "secret,id=sec0,data=rtpw";
    let image_opts = format!(
        "driver=qcow2,encrypt.key-secret=sec0,file.driver=file,file.filename={}",
        path.display()
    );

    let output = Command::new("qemu-io")
        .args(["--object", secret_arg])
        .args(["--image-opts", &image_opts])
        .args(["-c", "write -P 0x55 0 65536"])
        .output()
        .expect("failed to run qemu-io");

    assert!(
        output.status.success(),
        "qemu-io write failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read with our library
    let mut image = Qcow2Image::open_with_password(&path, b"rtpw").unwrap();
    let mut buf = vec![0u8; 65536];
    image.read_at(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|&b| b == 0x55), "should read what QEMU wrote");
}

// --- Full round-trip: create(QEMU) → write(ours) → read(QEMU) ---

#[test]
fn round_trip_qemu_create_our_write_qemu_read() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = EncryptedTestImage::create("1M", "rt2pw");

    // Write with our library
    {
        let mut image = Qcow2Image::open_rw_with_password(&img.path, b"rt2pw").unwrap();
        image.write_at(&[0x77; 512], 0).unwrap();
        image.write_at(&[0x88; 1024], 65536).unwrap();
        image.flush().unwrap();
    }

    // Read with QEMU
    let data = img.read_via_qemu(0, 512);
    assert_eq!(data.len(), 512);
    assert!(data.iter().all(|&b| b == 0x77), "QEMU should read 0x77");

    let data2 = img.read_via_qemu(65536, 1024);
    assert_eq!(data2.len(), 1024);
    assert!(data2.iter().all(|&b| b == 0x88), "QEMU should read 0x88");
}

// --- Step-by-step debug of QEMU key recovery ---

/// This test creates a QEMU-encrypted image and traces each step of the
/// key recovery pipeline to isolate where the WrongPassword failure occurs.
#[test]
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn debug_qemu_key_recovery_step_by_step() {
    if !has_qemu_io() {
        eprintln!("skipping: qemu-io not available");
        return;
    }

    let img = EncryptedTestImage::create("1M", "debugpw");

    // Read the raw QCOW2 file
    let raw_file = std::fs::read(&img.path).unwrap();
    eprintln!("QCOW2 file size: {} bytes", raw_file.len());

    // Parse QCOW2 header to find the LUKS header offset
    // Header extensions start at offset 104 (for v3) or after the basic header
    let header_length = u32::from_be_bytes(raw_file[100..104].try_into().unwrap()) as usize;
    eprintln!("QCOW2 header length: {header_length}");

    // Find the FullDiskEncryption extension (magic 0x0537be77)
    let mut ext_offset = header_length;
    let mut luks_offset = 0u64;
    let mut luks_length = 0u64;
    while ext_offset + 8 <= raw_file.len() {
        let ext_magic = u32::from_be_bytes(raw_file[ext_offset..ext_offset + 4].try_into().unwrap());
        let ext_len = u32::from_be_bytes(raw_file[ext_offset + 4..ext_offset + 8].try_into().unwrap()) as usize;
        eprintln!("Extension at {ext_offset}: magic=0x{ext_magic:08x} len={ext_len}");

        if ext_magic == 0 {
            break; // End of extensions
        }

        if ext_magic == 0x0537be77 {
            // FullDiskEncryption extension: offset(u64) + length(u64)
            luks_offset = u64::from_be_bytes(raw_file[ext_offset + 8..ext_offset + 16].try_into().unwrap());
            luks_length = u64::from_be_bytes(raw_file[ext_offset + 16..ext_offset + 24].try_into().unwrap());
            eprintln!("Found FullDiskEncryption: luks_offset={luks_offset} luks_length={luks_length}");
        }

        // Extensions are 8-byte aligned
        ext_offset += 8 + ((ext_len + 7) & !7);
    }

    // If no FDE extension found, LUKS header is at beginning of first cluster after header
    // QEMU typically stores LUKS header starting at an offset in the file
    // For QCOW2, the LUKS data is embedded in the image as regular clusters
    // Let's also check the crypt_method field
    let crypt_method = u32::from_be_bytes(raw_file[32..36].try_into().unwrap());
    eprintln!("crypt_method: {crypt_method}");
    assert_eq!(crypt_method, 2, "should be LUKS encryption (crypt_method=2)");

    // If LUKS header is embedded in QCOW2 image clusters, we need to read it via
    // our I/O layer. But for a direct test, let's check if the LUKS magic appears
    // at any known offset.
    let cluster_bits = u32::from_be_bytes(raw_file[20..24].try_into().unwrap());
    let cluster_size = 1u64 << cluster_bits;
    eprintln!("cluster_bits: {cluster_bits}, cluster_size: {cluster_size}");

    // In QEMU-created QCOW2, the LUKS header is stored as payload within the image.
    // It's referenced by the FDE extension which gives us the offset and length
    // within the QCOW2 *virtual* space... actually no, it's physical offset.
    // Let's try reading the LUKS data directly from the file at the given offset.
    if luks_offset > 0 && luks_length > 0 {
        let luks_start = luks_offset as usize;
        let luks_end = (luks_offset + luks_length) as usize;

        if luks_end <= raw_file.len() {
            let luks_data = &raw_file[luks_start..luks_end];
            eprintln!("LUKS data first 16 bytes: {:02x?}", &luks_data[..16.min(luks_data.len())]);

            // Step 1: Parse LUKS header
            let header = LuksHeader::parse(luks_data);
            match header {
                Ok(LuksHeader::V1(ref h)) => {
                    eprintln!("=== LUKS1 Header ===");
                    eprintln!("cipher_name: {}", h.cipher_name);
                    eprintln!("cipher_mode: {}", h.cipher_mode_str);
                    eprintln!("hash_spec: {}", h.hash_spec);
                    eprintln!("payload_offset: {} sectors ({} bytes)", h.payload_offset, h.payload_offset as u64 * 512);
                    eprintln!("key_bytes: {}", h.key_bytes);
                    eprintln!("mk_digest: {:02x?}", &h.mk_digest);
                    eprintln!("mk_digest_salt: {:02x?}", &h.mk_digest_salt);
                    eprintln!("mk_digest_iter: {}", h.mk_digest_iter);
                    eprintln!("uuid: {}", h.uuid);

                    for (i, slot) in h.key_slots.iter().enumerate() {
                        if slot.active {
                            eprintln!("--- Slot {i} (ACTIVE) ---");
                            eprintln!("  iterations: {}", slot.iterations);
                            eprintln!("  salt: {:02x?}", &slot.salt);
                            eprintln!("  key_material_offset: {} sectors ({} bytes)", slot.key_material_offset, slot.key_material_offset as u64 * 512);
                            eprintln!("  stripes: {}", slot.stripes);

                            let km_offset = slot.key_material_offset as usize * 512;
                            let km_size = slot.stripes as usize * h.key_bytes as usize;
                            eprintln!("  key material range: {}..{} (size {})", km_offset, km_offset + km_size, km_size);
                            eprintln!("  luks_data.len(): {}", luks_data.len());

                            if km_offset + km_size > luks_data.len() {
                                eprintln!("  ERROR: key material out of bounds!");
                                continue;
                            }

                            // Step 2: Derive split key
                            let slot_kdf = h.key_slot_kdf(i).unwrap();
                            eprintln!("  Deriving split key with {:?}...", slot_kdf);
                            let split_key = key_derivation::derive_key(&slot_kdf, b"debugpw", h.key_bytes as usize).unwrap();
                            eprintln!("  split_key[..8]: {:02x?}", &split_key[..8]);
                            eprintln!("  split_key len: {}", split_key.len());

                            // Step 3: Decrypt key material
                            let mut key_material = luks_data[km_offset..km_offset + km_size].to_vec();
                            eprintln!("  key_material[..16] (encrypted): {:02x?}", &key_material[..16]);
                            create::decrypt_key_material(&split_key, CipherMode::AesXtsPlain64, &mut key_material).unwrap();
                            eprintln!("  key_material[..16] (decrypted): {:02x?}", &key_material[..16]);

                            // Step 4: AF merge
                            let af_hash = h.af_hash().unwrap();
                            let candidate = af_splitter::af_merge(&key_material, h.key_bytes as usize, slot.stripes, af_hash).unwrap();
                            eprintln!("  candidate master key[..8]: {:02x?}", &candidate[..8]);
                            eprintln!("  candidate master key len: {}", candidate.len());

                            // Step 5: Verify digest
                            let verify_kdf = h.mk_digest_kdf().unwrap();
                            eprintln!("  Verifying with mk_digest_kdf: {:?}", verify_kdf);
                            let digest = key_derivation::derive_key(&verify_kdf, &candidate, 20).unwrap();
                            eprintln!("  computed digest:  {:02x?}", &digest);
                            eprintln!("  expected digest:  {:02x?}", &h.mk_digest);
                            eprintln!("  digest match: {}", digest == h.mk_digest.to_vec());

                            if digest == h.mk_digest.to_vec() {
                                eprintln!("  SUCCESS: Master key recovered!");
                            } else {
                                eprintln!("  FAILURE: Digest mismatch — WrongPassword bug!");
                            }
                        }
                    }
                }
                Ok(LuksHeader::V2(ref h)) => {
                    eprintln!("=== LUKS2 Header ===");
                    eprintln!("hdr_size: {}", h.hdr_size);
                    eprintln!("uuid: {}", h.uuid);
                    eprintln!("key_bytes: {}", h.key_bytes);
                    eprintln!("keyslots: {:?}", h.metadata.keyslots.keys().collect::<Vec<_>>());
                }
                Err(e) => {
                    eprintln!("LUKS parse error: {e}");
                }
            }

            // Also try full recovery
            let result = qcow2::engine::encryption::recover_master_key(luks_data, b"debugpw");
            match result {
                Ok(ctx) => eprintln!("\nrecover_master_key: SUCCESS (key_len={})", ctx.key_len()),
                Err(e) => eprintln!("\nrecover_master_key: FAILED: {e}"),
            }
        } else {
            eprintln!("LUKS data extends beyond file: luks_end={luks_end} file_len={}", raw_file.len());
        }
    } else {
        eprintln!("No FullDiskEncryption extension found — need to find LUKS header another way");

        // Try scanning for LUKS magic at cluster-aligned offsets
        let mut found = false;
        for offset in (0..raw_file.len()).step_by(cluster_size as usize) {
            if offset + 6 <= raw_file.len() && &raw_file[offset..offset + 6] == b"LUKS\xba\xbe" {
                eprintln!("Found LUKS magic at offset {offset}");
                found = true;

                let luks_data = &raw_file[offset..];
                let header = LuksHeader::parse(luks_data);
                match &header {
                    Ok(LuksHeader::V1(h)) => {
                        eprintln!("LUKS1: cipher={} mode={} key_bytes={} payload_offset={}",
                            h.cipher_name, h.cipher_mode_str, h.key_bytes, h.payload_offset);

                        // Check how much LUKS data we have
                        let total_luks_size = h.payload_offset as usize * 512;
                        eprintln!("Total LUKS header size: {total_luks_size} bytes");
                        eprintln!("Available from offset: {} bytes", raw_file.len() - offset);

                        if offset + total_luks_size <= raw_file.len() {
                            let full_luks = &raw_file[offset..offset + total_luks_size];
                            let result = qcow2::engine::encryption::recover_master_key(full_luks, b"debugpw");
                            match result {
                                Ok(ctx) => eprintln!("recover_master_key: SUCCESS (key_len={})", ctx.key_len()),
                                Err(e) => eprintln!("recover_master_key: FAILED: {e}"),
                            }
                        }
                    }
                    Ok(LuksHeader::V2(h)) => {
                        eprintln!("LUKS2: hdr_size={} key_bytes={}", h.hdr_size, h.key_bytes);
                    }
                    Err(e) => eprintln!("Parse error: {e}"),
                }
                break;
            }
        }
        if !found {
            eprintln!("No LUKS magic found at any cluster-aligned offset");
        }
    }
}

// --- Integrity check on encrypted images ---

#[test]
fn integrity_check_encrypted_image() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("integrity_enc.qcow2");

    {
        let mut image = Qcow2Image::create(
            &path,
            CreateOptions {
                virtual_size: 1 << 20,
                cluster_bits: None,
                extended_l2: false,
                compression_type: None,
                data_file: None,
                encryption: encryption_options(b"intpw"),
            },
        )
        .unwrap();

        image.write_at(&[0xAA; 4096], 0).unwrap();
        image.write_at(&[0xBB; 512], 65536).unwrap();
        image.flush().unwrap();
    }

    // Check integrity (doesn't need password — just checks refcounts)
    let image = Qcow2Image::open_with_password(&path, b"intpw").unwrap();
    let report = qcow2::engine::integrity::check_integrity(
        image.backend(),
        image.header(),
    )
    .unwrap();

    assert!(
        report.mismatches.is_empty(),
        "no refcount mismatches expected: {:?}",
        report.mismatches
    );
    assert!(
        report.leaks.is_empty(),
        "no leaked clusters expected: {:?}",
        report.leaks
    );
}
