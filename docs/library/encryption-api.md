# Encryption API

<!-- TODO
- Explain how encryption is specified at image creation time via EncryptionOptions:
    password: String
    cipher_mode: CipherMode (AesXts | AesCbcEssiv)
    key_bits: u32 (128 or 256)
    kdf: KdfOptions (Pbkdf2 | Argon2id with time/memory parameters)
    luks_version: LuksVersion (Luks1 | Luks2)
    af_stripe_count: u32 (anti-forensic stripe count, default 4000)

- Explain how to open an encrypted image:
    OpenOptions::new().password("secret") → Qcow2Image::open_with_options(path, opts)
    The engine derives the master key from the password and the LUKS key slots

- Explain what is and is NOT encrypted:
    Encrypted: guest data clusters
    Not encrypted: QCOW2 metadata (header, L1, L2, refcount, snapshots, bitmaps)

- Explain the key derivation path at open time:
    1. Read LUKS header from the FullDiskEncryption extension offset
    2. Try each active key slot with the provided password
    3. Verify master key against mk_digest
    4. Derive sector encryption key from master key

- Explain IV/tweak calculation (physical, not guest):
    AES-XTS: tweak = host_cluster_offset / 512 + intra_cluster_sector
    AES-CBC-ESSIV: IV = AES_ECB(SHA256(key), sector_num)

- Cross-reference format/encryption.md for the on-disk LUKS header layout

- Reference: crates/qcow2/src/engine/encryption/ (luks_header, key_derivation, af_splitter, create)
- Reference: crates/qcow2-core/src/engine/encryption/ (cipher, af_splitter stub, key_derivation)
-->
