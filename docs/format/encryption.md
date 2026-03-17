# Encryption

QCOW2 supports three encryption methods selected by the `crypt_method` header
field. The LUKS method (method 2) is the current standard; AES-CBC (method 1)
is legacy and not recommended.

<!-- TODO
- Document the three crypt_method values: 0 = none, 1 = AES-CBC legacy, 2 = LUKS

LUKS encryption:
- Explain that the LUKS header is stored at the offset given by the
  FullDiskEncryption header extension (not at the start of the file)
- LUKS1 header structure: magic, version, cipher_name, cipher_mode, hash_spec,
  payload_offset, key_bytes, mk_digest, key slots (8 slots × key_slot_size)
- LUKS2 header structure: JSON metadata, keyslot objects, digest objects
- Key derivation:
    LUKS1: PBKDF2-SHA1 or PBKDF2-SHA256
    LUKS2: PBKDF2 or Argon2id (per-slot configuration)
- Anti-forensic splitting: master key split into stripe_count sectors using
  AFD_SHA256 (SHA256-based hash chain), stored encrypted in key slots
- Key slot alignment: offsets must be 8-sector (4 KB) aligned (QEMU convention)
- Cipher modes:
    AES-XTS-plain64 (QEMU default):
      tweak = host_cluster_offset / 512 + sector_index_within_cluster
    AES-CBC-ESSIV:
      IV = AES_ECB(SHA256(key), sector_num)
- Key sizes: AES-128 → 32-byte master key, AES-256 → 64-byte master key
- Encryption scope: cluster data only; metadata (L1/L2/refcount) is NOT encrypted
- IV/tweak is based on the host cluster offset, not the guest offset

AES-CBC legacy (method 1):
- Uses AES-CBC with ESSIV(SHA256) and a single key from the password
- No key slots, no anti-forensic splitting
- Not recommended; prefer LUKS

- Reference: crates/qcow2-format/src/constants.rs (crypt_method values)
- Reference: crates/qcow2-core/src/engine/encryption/ (cipher, key_derivation, af_splitter)
- Reference: crates/qcow2/src/engine/encryption/ (LUKS1/2 header parsing, key recovery)
-->
